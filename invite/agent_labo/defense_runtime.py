"""Garde invité : preuves réelles, autorisations signées, actions bornées.

Ne qualifie pas un programme de malware. Les objets et actions sont choisis
par le manifeste root ; le Cloud n'accorde aucun droit. Les fichiers énormes,
les liens et les mesures instables produisent une alerte, pas un hash inventé.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import time
import uuid

BASE = Path('/opt/sawm-labo')
STATE = Path('/run/sawm-labo/defense-state.json')
MAX_HASH = 8 * 1024 * 1024
MAX_PROOF_AGE_MS = 1500
LIMITS = ['Objets explicitement inscrits ; pas une couverture intégrale du serveur.',
          'Le hash est plafonné à 8 Mio par fichier ; les objets plus grands restent à examiner.',
          'La capture VFS ne couvre pas mmap ni un noyau compromis.',
          'Confinement selon politique locale ; analyse SAWM séparée et asynchrone.']


def trusted_manifest(path=BASE/'manifeste.json'):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        st = os.fstat(stream.fileno())
        if st.st_uid != 0 or st.st_mode & 0o022 or not stat.S_ISREG(st.st_mode):
            raise ValueError('manifest_not_trusted')
        raw = stream.read(1024*1024+1)
        if len(raw) > 1024*1024:
            raise ValueError('manifest_too_large')
    m = json.loads(raw)
    m['_sha256'] = hashlib.sha256(raw).hexdigest()
    return m


def targets(m):
    policy = m.get('defense_fichiers') or {}
    if policy.get('enabled') is not True:
        return []
    rows = policy.get('targets')
    if not isinstance(rows, list) or not 1 <= len(rows) <= 16:
        raise ValueError('invalid_targets')
    result = []
    for t in rows:
        p = Path(t['path'])
        if (not p.is_absolute() or '..' in p.parts or not p.is_relative_to(BASE/'fixtures')
                or not re.fullmatch(r'labo-[a-z0-9_.-]+\.service', t.get('unit', ''))
                or t.get('kind') not in ('file', 'sqlite')
                or not re.fullmatch('[a-f0-9]{64}', t.get('reference_sha256', ''))):
            raise ValueError('invalid_target_scope')
        # Check every component, not just the last filename.
        if any(x.is_symlink() for x in (p, *p.parents)):
            raise ValueError('symbolic_target')
        result.append(dict(t))
    if len({(t['unit'],t['path']) for t in result}) != len(result):
        raise ValueError('duplicate_target')
    return result


def integrity(path, reference):
    start = time.monotonic()
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        before = os.fstat(f.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_HASH or before.st_nlink != 1:
            return {'sample_stable': False, 'reason': 'file_not_bounded_regular'}
        h = hashlib.sha256()
        remaining = MAX_HASH+1
        while remaining:
            chunk = f.read(min(65536, remaining))
            if not chunk:
                break
            remaining -= len(chunk); h.update(chunk)
        after = os.fstat(f.fileno())
    current = os.stat(path, follow_symlinks=False)
    signature = lambda s: (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    stable = remaining > 0 and signature(before)==signature(after)==signature(current)
    return {'reference_sha256': reference, 'current_sha256': h.hexdigest(),
            'reference_verified': True, 'sample_stable': stable,
            'device': before.st_dev, 'inode': before.st_ino,
            'hash_ms': round((time.monotonic()-start)*1000,3)}


def availability(path):
    result = {}
    before = os.stat(path, follow_symlinks=False)
    # Read and a rolled-back transaction probe. No business row is modified.
    for kind, mode in (('read','ro'), ('write','rw')):
        conn = None
        try:
            conn = sqlite3.connect(Path(path).as_uri()+'?mode='+mode, uri=True, timeout=0)
            conn.execute('SELECT count(*) FROM sqlite_master' if kind=='read' else 'BEGIN IMMEDIATE').fetchone()
            result[kind+'_available'] = True; result[kind+'_error'] = None
        except sqlite3.Error as e:
            result[kind+'_available'] = False
            # Python 3.10 exposes no numeric SQLite error attribute. Match the
            # exact SQLite diagnostic, never a substring from external logs.
            result[kind+'_error'] = getattr(e,'sqlite_errorname',None) or (
                'SQLITE_BUSY' if type(e) is sqlite3.OperationalError and str(e)=='database is locked' else 'SQLITE_ERROR')
        finally:
            if conn:
                conn.rollback(); conn.close()
    after = os.stat(path, follow_symlinks=False)
    stable = (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino) and stat.S_ISREG(after.st_mode)
    result.update(sample_stable=stable, device=after.st_dev, inode=after.st_ino)
    if not stable:
        result.update(read_available=None, write_available=None, read_error='OBJECT_CHANGED', write_error='OBJECT_CHANGED')
    return result


def exclusive_lock(obs):
    obj = obs.get('object') or {}
    pid = obs.get('pid')
    if obs.get('identity_stable') is not True:
        return False
    try:
        if obs.get('fd_on_object') is not True:
            return False
        for line in obs.get('kernel_locks', []):
            p = line.split()
            if len(p)!=8 or p[1:4]!=['POSIX','ADVISORY','WRITE'] or int(p[4])!=pid:
                continue
            dev = p[5].split(':')
            if (int(dev[0],16),int(dev[1],16),int(dev[2])) != (os.major(obj['device']),os.minor(obj['device']),obj['inode']):
                continue
            if int(p[6]) <= 1073741826 and (p[7]=='EOF' or int(p[7])>=1073742335):
                return True
    except (OSError,KeyError,ValueError,IndexError):
        return False
    return False


def matching_write(snapshot, obs, now_ms):
    """Only the same boot, process incarnation and target inode may be joined."""
    obj = obs.get('object') or {}
    if (snapshot.get('active') is not True or snapshot.get('error')
            or obs.get('identity_stable') is not True
            or type(obj.get('device')) is not int or obj['device'] < 0
            or type(obj.get('inode')) is not int or obj['inode'] <= 0):
        return None
    device = (os.major(obj['device']) << 20) | os.minor(obj['device'])
    for event in reversed(snapshot.get('events', [])):
        proc = event.get('process') or {}
        latency = event.get('capture_latency_ms')
        if (event.get('operation_succeeded') is True and event.get('boot_id')==obs.get('boot_id')
                and event.get('pid')==obs.get('pid') and proc.get('identity_stable') is True
                and proc.get('start_ticks')==obs.get('process_start_ticks')
                and event.get('euid')==obs.get('uid')
                and str(proc.get('cgroup','')).removeprefix('0::')==obs.get('cgroup')
                and event.get('inode')==obj.get('inode')
                and event.get('device')==device
                and type(event.get('received_at_ms')) is int
                and type(latency) in (int,float) and math.isfinite(latency)
                and 0 <= latency <= MAX_PROOF_AGE_MS
                and 0 <= now_ms-event['received_at_ms'] <= MAX_PROOF_AGE_MS
                and now_ms-event['received_at_ms']+latency <= MAX_PROOF_AGE_MS):
            return event
    return None


def sensor_signature(paths):
    """A same-name replacement must get new probes, not silently lose coverage."""
    rows = []
    for path in paths:
        p = Path(path)
        if any(x.is_symlink() for x in (p,*p.parents)):
            raise ValueError('symbolic_sensor_target')
        st = os.stat(path,follow_symlinks=False)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError('sensor_target_not_regular')
        rows.append((path,st.st_dev,st.st_ino))
    return tuple(rows)


def sensor_health(snapshot):
    issues = []
    if snapshot.get('active') is not True:
        issues.append('capteur_ecritures_inactif')
    if snapshot.get('error'):
        issues.append('erreur_capteur_ecritures')
    for key, label in (('loss_notifications','perte_evenements_noyau'),
                       ('evicted_events','evenements_locaux_evinces'),
                       ('invalid_events','evenements_capteur_invalides')):
        if snapshot.get(key,0):
            issues.append(label)
    return issues


def inspect_target(m, target, sensor, observe, evaluate, diagnose):
    start = time.monotonic()
    path, unit = target['path'], target['unit']
    probe = availability(path) if target['kind']=='sqlite' else {}
    hashed = integrity(path,target['reference_sha256'])
    obs = observe(unit,path)
    now = int(time.time()*1000)
    obj = obs.get('object') or {}
    observed_at = obs.get('observed_at_ms')
    fresh = type(observed_at) is int and 0 <= now-observed_at <= MAX_PROOF_AGE_MS
    same_object = (hashed.get('device'),hashed.get('inode')) == (obj.get('device'),obj.get('inode'))
    if not same_object:
        hashed.update(sample_stable=False,reference_verified=False,reason='object_changed_between_probes')
    if probe and (probe.get('sample_stable') is not True or
            (probe.get('device'),probe.get('inode')) != (obj.get('device'),obj.get('inode'))):
        probe.update(read_available=None,write_available=None,read_error='OBJECT_CHANGED',write_error='OBJECT_CHANGED')
    oid = f"{obj.get('device')}:{obj.get('inode')}"
    ident = {'unit':unit,'boot_id':obs.get('boot_id'),'pid':obs.get('pid'),
             'starttime_ticks':obs.get('process_start_ticks'),'cgroup':obs.get('cgroup')}
    common = {'object_id':oid,'observed_ms':now,'identity':ident,
              'identity_stable':obs.get('identity_stable') is True and fresh}
    rows = [dict(common,id='hash',kind='integrity',source='controller_probe',**hashed)]
    if probe:
        rows.append(dict(common,id='availability',kind='availability',source='controller_probe',**probe))
    locked = fresh and exclusive_lock(obs)
    if locked:
        rows.append(dict(common,id='lock',kind='lock',source='procfs',exclusive_range_verified=True,holder_verified=True))
    write = matching_write(sensor,obs,now) if fresh and same_object else None
    if write:
        rows.append(dict(common,id='write',kind='file',source='ebpf',operation='write',succeeded=True))
    changed_hash = (hashed.get('sample_stable') is True and hashed.get('reference_verified') is True
                    and hashed.get('current_sha256') != target['reference_sha256'])
    unavailable = (probe.get('read_available') is False and probe.get('write_available') is False
                   and probe.get('read_error') == 'SQLITE_BUSY' and probe.get('write_error') == 'SQLITE_BUSY')
    # Authorize the violation actually established, not merely a lock seen
    # after otherwise successful availability probes. A write permit never
    # covers an additional availability violation (and vice versa).
    qualified = []
    if locked and unavailable:
        qualified.append('sqlite-exclusive-lock')
    if changed_hash and write:
        qualified.append('file-write')
    operations = qualified or ['sqlite-exclusive-lock' if locked else 'file-write']
    receipts = [{'operation': operation, **evaluate(m,obs,unit=unit,operation=operation,
                  object_path=path,now_ms=now)} for operation in operations]
    # A proven unapproved violation suffices for the local mandate; preserve
    # the other receipts so a different authorized operation stays visible.
    absent_reasons = {'aucun_mandat_pour_operation','mandat_expire_ou_futur','mandat_revoque'}
    selected = next((x for x in receipts if x.get('authorized') is False and x.get('reason') in absent_reasons),
                    next((x for x in receipts if x.get('authorized') is not True),receipts[0]))
    operation = selected['operation']
    receipt = {k:v for k,v in selected.items() if k != 'operation'}
    policy = {'unit':unit,'object_id':oid,'manifest_sha256':m['_sha256'],'verified':True,
              'protected':unit in m.get('unites_protegees',[]) or unit=='labo-temoin.service',
              'authorization_required':True,'allowed_actions':
                  ['arreter-service'] if target.get('automatic_containment') is True and unit in m.get('unites_autorisees',[])
                  and 'arreter-service' in (m.get('veille') or {}).get('actions_automatiques',[]) else []}
    clock = time.monotonic()
    diagnostic = diagnose(rows,autorisation=receipt,mandat=policy,maintenant_ms=now)
    uncovered = set()
    if changed_hash and not write:
        uncovered.add('alteration_non_couverte_auteur_non_attribue')
    if unavailable and not locked:
        uncovered.add('indisponibilite_non_couverte_detenteur_non_attribue')
    if probe and any(probe.get(k) is False for k in ('read_available','write_available')) and not unavailable:
        uncovered.add('indisponibilite_non_qualifiee_par_verrou_exclusif')
    if uncovered:
        diagnostic['inconnues'] = sorted(set(diagnostic.get('inconnues',[])) | uncovered)
        if diagnostic.get('recommandation') == 'surveiller':
            diagnostic.update(recommandation='signaler',priorite='haute',raison='effet_non_couvert_par_mandat_operation')
    if not same_object or hashed.get('sample_stable') is not True:
        diagnostic['inconnues'] = sorted(set(diagnostic.get('inconnues',[])) | {'integrite_incomplete_ou_objet_change'})
        if diagnostic.get('recommandation')=='surveiller':
            diagnostic.update(recommandation='signaler',priorite='haute',raison='integrite_incomplete_ou_objet_change')
    health = sensor_health(sensor)
    if health:
        diagnostic['inconnues'] = sorted(set(diagnostic.get('inconnues',[])) | set(health))
        if diagnostic.get('recommandation')=='surveiller':
            diagnostic.update(recommandation='signaler',priorite='haute',raison='couverture_capteur_degradee')
    if not fresh:
        diagnostic['inconnues'] = sorted(set(diagnostic.get('inconnues',[])) | {'attribution_processus_perimee'})
        diagnostic.update(recommandation='signaler',priorite='haute',raison='attribution_processus_perimee')
    return {'unit':unit,'path':path,'operation':operation,'authorization':receipt,
            'authorizations':receipts,'qualified_operations':qualified,
            'attribution_os':{k:obs.get(k) for k in ('unit','boot_id','pid','process_start_ticks','cgroup','uid',
                'invocation_id','identity_stable','observed_at_ms','fd_on_object')},
            'diagnostic':diagnostic,'integrity':hashed,'availability':probe,
            'identity':obs,'observations':rows,'action':None,
            'metrics':{'diagnostic_ms':round((time.monotonic()-clock)*1000,3),
                       'observation_ms':round((time.monotonic()-start)*1000,3),
                       'capture_latency_ms':write.get('capture_latency_ms') if write else None},
            'observed_ms':now}


def contain(m, item, execute):
    obs = item['identity']
    if item['diagnostic']['recommandation']!='contenir_sous_mandat':
        return None
    now = int(time.time()*1000)
    if (obs.get('identity_stable') is not True
            or any(type(t) is not int or not 0 <= now-t <= MAX_PROOF_AGE_MS
                   for t in (item.get('observed_ms'),obs.get('observed_at_ms')))
            or not any(row.get('kind') in ('lock','file') and row.get('identity_stable') is True
                       for row in item.get('observations',[]))):
        return {'applique':False,'motif':'attribution_absente_ou_perimee'}
    request = {'decision_id':'local-file-'+uuid.uuid4().hex,'action':'arreter-service',
        'cible':item['unit'],'generation':m['generation'],'manifest_sha256':m['_sha256'],
        'expected_identity':{'cible':item['unit'],'boot_id':obs['boot_id'],
            'MainPID':str(obs['pid']),'InvocationID':obs['invocation_id'],'ControlGroup':obs['cgroup']}}
    return execute(request)


def atomic_state(value):
    raw = json.dumps(value,ensure_ascii=False,allow_nan=False).encode()
    if len(raw)>65536:
        raise ValueError('state_too_large')
    STATE.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    tmp = STATE.with_suffix('.tmp')
    fd = os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(raw)
    os.replace(tmp,STATE)


def main():
    import sys
    sys.path[:0] = [str(BASE),str(BASE/'agent'),str(BASE/'executeur')]
    from write_attribution import WriteAttributionSensor
    from maintenance import observer_os, evaluate
    from diagnostic_defense import diagnostiquer
    from executeur import appliquer
    sensor, signature, history, attempted = None,None,[],set()
    try:
        while True:
            started = time.monotonic()
            state = {'schema':'sawm-file-defense/v1','observed_ms':int(time.time()*1000),
                     'active':True,'targets':[],'alertes':history[-8:],'limits':LIMITS}
            try:
                m = trusted_manifest(); scope = targets(m)
                paths = sorted({x['path'] for x in scope})
                next_signature = sensor_signature(paths)
                if signature != next_signature or (sensor and not sensor.snapshot().get('active')):
                    if sensor: sensor.close()
                    sensor = None
                    if paths:
                        sensor = WriteAttributionSensor(paths).start()
                        # No claim of coverage if replacement raced compilation.
                        if sensor_signature(paths) != next_signature:
                            sensor.close();sensor=None
                            raise ValueError('sensor_target_changed_during_attach')
                    signature = next_signature
                snap = sensor.snapshot() if sensor else {'active':False,'events':[]}
                state['sensor'] = {k:v for k,v in snap.items() if k not in ('events','targets')}
                for target in scope:
                    try:
                        item = inspect_target(m,target,snap,observer_os,evaluate,diagnostiquer)
                        fingerprint = hashlib.sha256(json.dumps([m['_sha256'],item['identity'],item['diagnostic']['raison']],sort_keys=True).encode()).hexdigest()
                        # Deduplicate by incarnation, not by changing capture time.
                        obs=item['identity']
                        key=(m['_sha256'],target['unit'],obs.get('boot_id'),obs.get('pid'),obs.get('process_start_ticks'))
                        if item['diagnostic']['recommandation']=='contenir_sous_mandat' and key not in attempted:
                            attempted.add(key)
                            item['action'] = contain(m,item,appliquer)
                            item['metrics']['action_ms'] = item['action'].get('duree_ms') if item['action'] else None
                            if item['action'] and item['action'].get('applique'):
                                item['after'] = availability(target['path']) if target['kind']=='sqlite' else integrity(target['path'],target['reference_sha256'])
                        if item['diagnostic']['recommandation']!='surveiller' or item['action']:
                            event = {k:v for k,v in item.items() if k not in ('identity','observations')}
                            event['id'] = hashlib.sha256(json.dumps([key,item['operation'],item['diagnostic']['raison']]).encode()).hexdigest()[:24]
                            if not history or event['id']!=history[-1]['id'] or item['action']:
                                history.append(event); history=history[-8:]
                        state['targets'].append({k:v for k,v in item.items() if k not in ('identity','observations')})
                    except Exception as e:
                        state['targets'].append({'unit':target['unit'],'path':target['path'],'error':type(e).__name__,
                                                 'diagnostic':{'recommandation':'signaler','priorite':'haute','raison':'inspection_incomplete'}})
                state['alertes'] = history[-8:]
                if len(attempted)>512: attempted=set(list(attempted)[-256:])
            except Exception as e:
                state.update(active=False,error=type(e).__name__)
            state['cycle_ms'] = round((time.monotonic()-started)*1000,3)
            atomic_state(state)
            time.sleep(max(0.05,0.25-(time.monotonic()-started)))
    finally:
        if sensor: sensor.close()


if __name__=='__main__':
    main()
