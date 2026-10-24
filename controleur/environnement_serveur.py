"""Inspections de serveur en lecture seule, limitées au MainPID d'une unité labo.

La cible vient du validateur appelant, jamais d'une sortie de processus. Aucun
argument, environnement, hash de mot de passe ou contenu de fichier métier
n'est collecté. Les comptes et les sockets restent des observations système,
sans déduction d'une personne ou d'une intention.
"""
from __future__ import annotations

import inspect
import re

_ACTIONS = frozenset(('inspecter-processus', 'inspecter-compte', 'inspecter-connexions'))
_UNIT = re.compile(r'labo-[a-z0-9][a-z0-9_.-]{0,55}\.service')


def _parse_stat(text, expected_pid, page_size):
    """Champs numériques /proc/stat sans exporter comm, potentiellement hostile."""
    before, separator, tail = text.rpartition(')')
    if not separator or '(' not in before:
        raise ValueError('process_stat_invalid')
    pid = int(before.split('(', 1)[0].strip())
    fields = tail.split()
    if pid != expected_pid or len(fields) < 22 or fields[0] in ('Z', 'X'):
        raise ValueError('process_stat_invalid')
    values = dict(pid=pid, cpu_ticks=int(fields[11]) + int(fields[12]),
                  starttime_ticks=int(fields[19]), rss_bytes=int(fields[21]) * page_size,
                  threads=int(fields[17]))
    if any(value < 0 for value in values.values()) or values['starttime_ticks'] == 0:
        raise ValueError('process_stat_invalid')
    return values


def _parse_connections(text, pid):
    """Attribution ss explicite au PID; ni texte libre ni compteurs de trafic."""
    import re
    if not isinstance(text, str) or len(text) > 262144:
        raise ValueError('socket_output_limit')
    rows = []
    observed = 0
    lines = text.splitlines()
    scan_truncated = len(lines) > 2048
    for line in lines[:2048]:
        parts = line.split(None, 5)
        if len(parts) != 6:
            continue
        state, _recv_queue, _send_queue, local, peer, owners = parts
        # Valider toute la structure users: empêche qu'un nom de programme
        # contenant « pid=42 » soit pris pour une attribution de socket.
        if not owners.startswith('users:(') or not owners.endswith(')'):
            continue
        entries = owners[len('users:('):-1]
        owner_pattern = re.compile(r'\("(?:[^"\\]|\\.)*",pid=(\d+),fd=\d+\)')
        owners_pids = []
        offset = 0
        while offset < len(entries):
            match = owner_pattern.match(entries, offset)
            if match is None:
                owners_pids = []
                break
            owners_pids.append(int(match.group(1)))
            offset = match.end()
            if offset < len(entries):
                if entries[offset] != ',':
                    owners_pids = []
                    break
                offset += 1
        if pid not in owners_pids:
            continue
        if (not re.fullmatch(r'[A-Z0-9_-]{1,20}', state)
                or any(len(endpoint) > 128 or not re.fullmatch(r'[A-Za-z0-9_.:%*\[\]-]+', endpoint)
                       for endpoint in (local, peer))):
            raise ValueError('socket_endpoint_invalid')
        observed += 1
        if len(rows) < 16:
            rows.append({'protocol': 'tcp', 'state': state, 'local': local, 'peer': peer,
                         'owner_pid': pid, 'attribution': 'ss_process_pid'})
    return {'source': 'ss -Hntp', 'connections': rows, 'observed_count': observed,
            'truncated': scan_truncated or observed > len(rows),
            'scan_truncated': scan_truncated, 'network_volume_bytes': None,
            'scope': 'TCP du MainPID seulement; ni UDP ni descendants ni volume réseau.'}


_REMOTE = r'''
import json,os,pathlib,pwd,re,subprocess,time
deadline=time.monotonic()+8
result={'schema':'sawm-server-inspection/v1','action':action,'unit':unit,
        'observed_epoch_ms':int(time.time()*1000),'observation_valid':False,
        'identity_stable':False,'status':'inconclusive','measurements_complete':False,
        'before':None,'after':None,
        'evidence':None,'errors':{},'human_actor':'unknown',
        'human_actor_inferred':False,
        'limits':['Un UID, le compte root, systemd ou loginuid ne prouvent pas un acteur humain.',
                  'Observation du MainPID et du cgroup sur une fenêtre courte; aucune intention déduite.',
                  'Les noms de comptes et les métadonnées observées restent des données non fiables.']}

def bounded_read(path, limit=16384):
    with open(path,'r') as stream:data=stream.read(limit+1)
    if len(data)>limit:raise ValueError('observation_size_limit')
    return data

def remaining():
    value=deadline-time.monotonic()
    if value <= 0:raise TimeoutError('inspection_budget_expired')
    return value

def identity():
    fields='Id,LoadState,ActiveState,MainPID,ControlGroup,InvocationID'
    p=subprocess.run(['systemctl','show','--property='+fields,'--',unit],
                     capture_output=True,text=True,timeout=min(1.5,remaining()))
    if p.returncode:raise ValueError('systemd_identity_unavailable')
    u=dict(line.split('=',1) for line in p.stdout.splitlines() if '=' in line)
    if (u.get('Id') != unit or u.get('LoadState') != 'loaded'
        or u.get('ActiveState') != 'active'
        or not re.fullmatch('[0-9a-f]{32}',u.get('InvocationID',''))):
        raise ValueError('systemd_identity_unavailable')
    pid=int(u.get('MainPID','0'));cg=u.get('ControlGroup','')
    if (pid <= 1 or not cg.startswith('/sawm.slice/') or cg.split('/')[-1] != unit
        or any(part in ('.','..') for part in cg.split('/'))
        or not re.fullmatch(r'/[A-Za-z0-9_./:@-]+',cg)):
        raise ValueError('systemd_identity_unavailable')
    root=pathlib.Path('/proc')/str(pid)
    if '0::'+cg not in bounded_read(root/'cgroup').splitlines():
        raise ValueError('process_cgroup_mismatch')
    process=_parse_stat(bounded_read(root/'stat'),pid,os.sysconf('SC_PAGE_SIZE'))
    boot=bounded_read('/proc/sys/kernel/random/boot_id',128).strip()
    if not re.fullmatch('[0-9a-f-]{36}',boot):raise ValueError('boot_identity_unavailable')
    return {'systemd':u,'pid':pid,'starttime_ticks':process['starttime_ticks'],
            'boot_id':boot,'cgroup':cg,'invocation_id':u['InvocationID']}

def account(uid):
    try:
        entry=pwd.getpwuid(uid)
        return {'uid':uid,'gid':entry.pw_gid,'name':entry.pw_name[:128],
                'name_resolved':True,'source':'pwd.getpwuid'}
    except KeyError:
        return {'uid':uid,'gid':None,'name':None,'name_resolved':False,'source':'pwd.getpwuid'}

def credentials(pid):
    root=pathlib.Path('/proc')/str(pid)
    fields=dict(line.split(':',1) for line in bounded_read(root/'status').splitlines() if ':' in line)
    values=[int(value) for value in fields['Uid'].split()]
    if len(values)!=4 or any(not 0 <= value <= 4294967295 for value in values):
        raise ValueError('uid_unavailable')
    loginuid=None
    try:
        value=int(bounded_read(root/'loginuid',32).strip())
        if 0 <= value < 4294967295:loginuid=value
    except (OSError,ValueError):pass
    return {'real_uid':values[0],'effective_uid':values[1],
            'real_account':account(values[0]),'effective_account':account(values[1]),
            'loginuid':loginuid,'loginuid_known':loginuid is not None,
            'audit_login_account':account(loginuid) if loginuid is not None else None,
            'human_actor':'unknown','human_actor_inferred':False}

def process_sample(pid):
    root=pathlib.Path('/proc')/str(pid)
    value=_parse_stat(bounded_read(root/'stat'),pid,os.sysconf('SC_PAGE_SIZE'))
    value['sample_monotonic_s']=time.monotonic()
    return value

def io_counters(pid):
    allowed={'rchar','wchar','syscr','syscw','read_bytes','write_bytes','cancelled_write_bytes'}
    values={}
    for line in bounded_read(pathlib.Path('/proc')/str(pid)/'io').splitlines():
        key,value=line.split(':',1)
        if key in allowed:values[key]=int(value.strip())
    if set(values)!=allowed or any(value<0 for value in values.values()):
        raise ValueError('process_io_unavailable')
    return values

def fd_count(pid):
    count=0
    with os.scandir(pathlib.Path('/proc')/str(pid)/'fd') as entries:
        for entry in entries:
            if not entry.name.isdecimal():continue
            count+=1
            if count>4096:return {'count':None,'lower_bound':4096,'truncated':True}
    return {'count':count,'lower_bound':count,'truncated':False}

def cgroup_sample(cg):
    root=pathlib.Path('/sys/fs/cgroup'+cg)
    stats=dict(line.split() for line in bounded_read(root/'cpu.stat').splitlines())
    quota,period=bounded_read(root/'cpu.max',128).split()
    current=int(bounded_read(root/'memory.current',128).strip())
    limit=bounded_read(root/'memory.max',128).strip()
    value={'cpu_usage_usec':int(stats['usage_usec']),
           'cpu_quota_us':None if quota=='max' else int(quota),'cpu_period_us':int(period),
           'cpu_unlimited':quota=='max','memory_current_bytes':current,
           'memory_max_bytes':None if limit=='max' else int(limit),'memory_unlimited':limit=='max'}
    if any(type(v) is int and v<0 for v in value.values()) or value['cpu_period_us']<=0:
        raise ValueError('cgroup_counters_invalid')
    return value

def optional(name,operation):
    try:return operation()
    except Exception:
        result['errors'][name]='unavailable'
        return None

stage='identity_before_unavailable'
try:
    before=identity();result['before']=before;pid=before['pid']
    stage='process_measurement_unavailable'
    first=process_sample(pid)
    creds_before=optional('credentials_before',lambda:credentials(pid))
    cg_first=optional('cgroup_before',lambda:cgroup_sample(before['cgroup']))
    io_first=optional('io_before',lambda:io_counters(pid))
    time.sleep(.5)
    second=process_sample(pid)
    cg_after=optional('cgroup_after',lambda:cgroup_sample(before['cgroup']))
    io_after=optional('io_after',lambda:io_counters(pid))
    creds_after=optional('credentials_after',lambda:credentials(pid))
    fds=optional('fd_count',lambda:fd_count(pid))
    executable=optional('executable',lambda:os.path.basename(os.readlink('/proc/'+str(pid)+'/exe'))[:128])
    sockets=None
    if action=='inspecter-connexions':
        def read_sockets():
            p=subprocess.run(['ss','-Hntp'],capture_output=True,text=True,timeout=min(1.5,remaining()))
            if p.returncode:raise ValueError('ss_unavailable')
            return _parse_connections(p.stdout,pid)
        sockets=optional('connections',read_sockets)
    stage='identity_after_unavailable'
    after=identity();result['after']=after
    if (before!=after or first['starttime_ticks']!=before['starttime_ticks']
        or second['starttime_ticks']!=before['starttime_ticks']):
        result['reason']='identity_changed'
    else:
        stage='process_measurement_invalid'
        dt=second['sample_monotonic_s']-first['sample_monotonic_s']
        ticks=second['cpu_ticks']-first['cpu_ticks']
        if dt<.5 or ticks<0:raise ValueError('process_measurement_invalid')
        cpu_seconds=ticks/os.sysconf('SC_CLK_TCK')
        io_delta=None
        if io_first is not None and io_after is not None:
            io_delta={key:io_after[key]-io_first[key] for key in io_first}
            if any(value<0 for value in io_delta.values()):
                io_delta=None;result['errors']['io_delta']='counter_regressed'
        cg_delta=None
        if cg_first is not None and cg_after is not None:
            cg_delta=cg_after['cpu_usage_usec']-cg_first['cpu_usage_usec']
            if cg_delta<0:cg_delta=None;result['errors']['cgroup_delta']='counter_regressed'
        evidence={'pid':pid,'exe_basename':executable,'credentials':creds_after,
                  'credentials_stable':creds_before is not None and creds_before==creds_after,
                  'process':{'cpu_delta_seconds':round(cpu_seconds,6),
                             'sample_elapsed_seconds':round(dt,6),
                             'cpu_percent_one_core':round(100*cpu_seconds/dt,3),
                             'rss_bytes':second['rss_bytes'],'threads':second['threads'],
                             'io_counters':io_after,'io_delta':io_delta,'file_descriptors':fds},
                  'cgroup':{'path':before['cgroup'],'counters':cg_after,
                            'cpu_delta_usec':cg_delta,
                            'scope':'Unité entière, distincte des compteurs du MainPID.'}}
        if action=='inspecter-connexions':evidence['connections']=sockets
        if creds_before!=creds_after:evidence['credentials_before']=creds_before
        result.update(identity_stable=True,observation_valid=True,status='observed',
                      evidence=evidence,reason='identity_verified',
                      measurements_complete=not bool(result['errors']))
except Exception:
    result['reason']=stage
    result['errors'][stage]='unavailable'
print(json.dumps(result))
'''


def inspecter(action: str, unit: str, *, contexte: dict | None = None) -> dict:
    """Relève des faits sans action sur le compte, le processus ou les fichiers.

    Le contexte est local : seuls decision_id/justification sont conservés pour
    rapprocher le choix SAWM de sa preuve. Il ne modifie aucune commande invitée.
    """
    if not isinstance(action, str) or action not in _ACTIONS:
        raise ValueError('inspection_action_not_allowed')
    if not isinstance(unit, str) or not _UNIT.fullmatch(unit):
        raise ValueError('unite_hors_laboratoire')
    if contexte is not None and not isinstance(contexte, dict):
        raise ValueError('inspection_context_invalid')
    choice = {'action': action, 'cible': unit}
    for key, limit in (('decision_id', 128), ('justification', 512)):
        value = (contexte or {}).get(key)
        if value is not None:
            if not isinstance(value, str) or len(value) > limit:
                raise ValueError('inspection_context_invalid')
            choice[key] = value
    from controleur import vm_labo as vm
    source = ('action=' + repr(action) + '\nunit=' + repr(unit) + '\n'
              + inspect.getsource(_parse_stat) + '\n'
              + inspect.getsource(_parse_connections) + '\n' + _REMOTE)
    result = vm.json_code(source, timeout=12)
    if (not isinstance(result, dict) or result.get('schema') != 'sawm-server-inspection/v1'
            or result.get('action') != action or result.get('unit') != unit
            or type(result.get('observation_valid')) is not bool):
        raise ValueError('inspection_response_invalid')
    if result['observation_valid'] and (result.get('identity_stable') is not True
            or not result.get('before') or result.get('before') != result.get('after')):
        raise ValueError('inspection_identity_invalid')
    result['choix_sawm'] = choice
    return result
