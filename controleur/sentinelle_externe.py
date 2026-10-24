"""External read-only witness: approved hashes and signed evidence stay on Mac.

This detects selected changes/visibility losses. Guest root can still falsify
guest measurements; this is not TPM attestation or general root resistance.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time

if __package__:
    from .audit_signe import JournalSigne, canonique
    from .vm_labo import json_code, local_vm
else:
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
    from controleur.audit_signe import JournalSigne, canonique
    from controleur.vm_labo import json_code, local_vm

HOME = Path.home()/'.sawm-labo/sentinelle-externe'
LIMITS = ['Témoin externe et références hors invité ; aucun confinement automatique.',
          'Le root invité peut falsifier hash et état rapportés par SSH.',
          'Aucune attestation TPM/Secure Boot ni résistance générale à root démontrée.',
          'Une maintenance approuvée exige un renouvellement explicite de référence.',
          'Mac arrêté ou compromis : ce témoin ne fournit plus de garantie.']
UNIT = re.compile(r'(?:labo-[a-z0-9_.-]+|ssh)\.service')
SHA = re.compile(r'[a-f0-9]{64}')


def validate_reference(value):
    if type(value) is not dict or value.get('schema')!='sawm-external-reference/v1':
        raise ValueError('reference_schema_invalid')
    services=value.get('services');files=value.get('files')
    if (type(services) is not list or not 1<=len(services)<=16
            or any(type(x) is not str or not UNIT.fullmatch(x) for x in services)
            or len(set(services))!=len(services)
            or type(files) is not list or not 1<=len(files)<=16):
        raise ValueError('reference_scope_invalid')
    paths=set()
    for item in files:
        path=item.get('path') if type(item) is dict else None
        if (type(path) is not str or len(path)>1024 or '..' in Path(path).parts
                or not (path.startswith('/opt/sawm-labo/') or path.startswith('/etc/systemd/system/labo-'))
                or not SHA.fullmatch(str(item.get('sha256',''))) or path in paths):
            raise ValueError('reference_file_invalid')
        paths.add(path)
    if value.get('controller')!='mac_external' or value.get('auto_accept_guest_changes') is not False:
        raise ValueError('external_boundary_required')
    return value


def load_reference(path):
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as f:
        st=os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode & 0o077:
            raise ValueError('external_reference_not_private')
        data=f.read(65537)
        if len(data)>65536:raise ValueError('external_reference_too_large')
    return validate_reference(json.loads(data))


def acquire_watch_lock(path):
    """Only one persistent witness for this external reference directory."""
    descriptor=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        mode=os.fstat(descriptor)
        if not stat.S_ISREG(mode.st_mode) or mode.st_uid!=os.getuid() or mode.st_nlink!=1:
            raise ValueError('watch_lock_not_private_regular')
        fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
        os.fchmod(descriptor,0o600)
        os.ftruncate(descriptor,0);os.write(descriptor,str(os.getpid()).encode('ascii'))
        return descriptor
    except Exception:
        os.close(descriptor);raise


def dashboard(route, value=None):
    connection=http.client.HTTPConnection('127.0.0.1',int(os.environ.get('LABO_HTTP','8899')),timeout=2)
    try:
        raw=None if value is None else canonique(value)
        connection.request('GET' if value is None else 'POST',route,body=raw,
                           headers={} if raw is None else {'Content-Type':'application/json'})
        result=connection.getresponse();body=result.read(2*1024*1024+1)
        if result.status!=200 or len(body)>2*1024*1024:raise ValueError('dashboard_unavailable')
        return json.loads(body)
    finally:connection.close()


_REMOTE = r'''
import hashlib,json,os,pathlib,stat,subprocess,time,urllib.request
out={'services':{},'files':{},'observed_ms_guest':int(time.time()*1000),
     'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
     'trust':'guest_self_report_not_attested'}
try:
 with urllib.request.urlopen('http://127.0.0.1:8080/sante',timeout=2) as response:out['witness_http']=response.status
except Exception:out['witness_http']=None
for unit in SERVICES:
 try:
  p=subprocess.run(['systemctl','show','--property=Id,ActiveState,SubState,MainPID','--',unit],capture_output=True,text=True,timeout=2)
  row=dict(x.split('=',1) for x in p.stdout.splitlines() if '=' in x)
  out['services'][unit]={'available':p.returncode==0 and row.get('Id')==unit,
     'active':row.get('ActiveState')=='active','substate':row.get('SubState'),
     'pid':int(row['MainPID']) if row.get('MainPID','').isdigit() else None}
 except Exception:out['services'][unit]={'available':False,'active':None}
for name in FILES:
 try:
  path=pathlib.Path(name)
  if any(x.is_symlink() for x in (path,*path.parents)):raise ValueError('link')
  with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
   before=os.fstat(stream.fileno())
   if not stat.S_ISREG(before.st_mode) or before.st_size>1048576:raise ValueError('scope')
   data=stream.read(1048577);after=os.fstat(stream.fileno())
  stable=(before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns) and len(data)<=1048576
  out['files'][name]={'available':True,'sample_stable':stable,'sha256':hashlib.sha256(data).hexdigest()}
 except Exception:out['files'][name]={'available':False,'sample_stable':False,'sha256':None}
print(json.dumps(out))
'''


def guest_snapshot(reference, *, transport=json_code):
    return transport('SERVICES='+repr(reference['services'])+'\nFILES='+repr([x['path'] for x in reference['files']])+'\n'+_REMOTE,timeout=30)


def diagnose(reference, guest, telemetry, *, now_ms, previous=None):
    """All comparisons use host-held expectations; nothing updates them here."""
    reference=validate_reference(reference)
    issues=[]
    guest=guest if type(guest) is dict else {}
    if guest.get('witness_http')!=200:
        issues.append({'kind':'temoin_sante_indisponible','target':'temoin_http_local'})
    services=guest.get('services') if type(guest.get('services')) is dict else {}
    files=guest.get('files') if type(guest.get('files')) is dict else {}
    for unit in reference['services']:
        row=services.get(unit) if type(services.get(unit)) is dict else {}
        if row.get('available') is not True or row.get('active') is not True:
            issues.append({'kind':'service_non_actif','target':unit,'observed':row.get('active') if type(row.get('active')) is bool else None})
    for expected in reference['files']:
        row=files.get(expected['path']) if type(files.get(expected['path'])) is dict else {}
        if (row.get('available') is not True or row.get('sample_stable') is not True
                or type(row.get('sha256')) is not str or not SHA.fullmatch(row['sha256'])):
            issues.append({'kind':'empreinte_non_verifiable','target':expected['path']})
        elif row.get('sha256')!=expected['sha256']:
            issues.append({'kind':'empreinte_differe_reference_externe','target':expected['path'],
                           'expected_sha256':expected['sha256'],'observed_sha256':row.get('sha256')})
    telemetry=telemetry if type(telemetry) is dict else {}
    envelope=telemetry.get('telemetrie_invite') if type(telemetry.get('telemetrie_invite')) is dict else {}
    samples=telemetry.get('invite')
    sample=samples[-1] if type(samples) is list and samples and type(samples[-1]) is dict else {}
    age=envelope.get('age_ms')
    fresh=(telemetry.get('mode')=='DIRECT' and envelope.get('connectee') is True
           and type(age) in (int,float) and math.isfinite(age) and 0<=age<=5000
           and type(sample.get('sequence')) is int and sample['sequence']>=0
           and type(sample.get('boot_id')) is str and 0<len(sample['boot_id'])<=128
           and type(sample.get('mur_epoch_ms')) is int and abs(now_ms-sample['mur_epoch_ms'])<=10000)
    if not fresh:issues.append({'kind':'telemetrie_absente_ou_perimee','target':'collecte'})
    progress={'boot_id':sample.get('boot_id'),'sequence':sample.get('sequence'),
              'checked_at_ms':now_ms}
    if previous and previous.get('boot_id')==progress['boot_id'] and progress['sequence']==previous.get('sequence') \
            and now_ms-previous.get('checked_at_ms',now_ms)>5000:
        issues.append({'kind':'telemetrie_sequence_figee','target':'collecte'})
    issues.sort(key=lambda x:(x['kind'],x['target']))
    return {'schema':'sawm-external-sentinel/v1','observed_ms_external':now_ms,
            'reference_sha256':hashlib.sha256(canonique(reference)).hexdigest(),
            'issues':issues,'status':'alerte' if issues else 'controles_cibles_conformes',
            'controller':'mac_external','progress':progress,'guest_attested':False,
            'action_performed':False,'limits':LIMITS}


class ExternalSentinel:
    def __init__(self, reference_path, audit_path, *, journal=None, transport=json_code, http=dashboard):
        if local_vm():raise RuntimeError('external_witness_cannot_run_inside_guest')
        self.reference_path=Path(reference_path)
        self.reference=load_reference(self.reference_path)
        self.audit=journal or JournalSigne(audit_path)
        self.transport=transport;self.http=http;self.previous=None;self.last=None
        self.open_alerts=set()

    def check(self):
        # Never re-enroll a changed baseline silently during a running process.
        current=load_reference(self.reference_path)
        if canonique(current)!=canonique(self.reference):raise ValueError('external_reference_changed')
        started=time.monotonic()
        try:guest=guest_snapshot(self.reference,transport=self.transport)
        except Exception:guest={}
        try:telemetry=self.http('/api/etat?n=1')
        except Exception:telemetry={}
        result=diagnose(self.reference,guest,telemetry,now_ms=int(time.time()*1000),previous=self.previous)
        # Retain the first timestamp for a stuck sequence; polling alone must
        # not reset its age and conceal a frozen sender.
        if not self.previous or any(result['progress'].get(k)!=self.previous.get(k) for k in ('boot_id','sequence')):
            self.previous=result['progress']
        signature=hashlib.sha256(canonique([result['reference_sha256'],result['issues']])).hexdigest()
        due=self.last is None or signature!=self.last[0] or time.monotonic()-self.last[1]>=60
        if due:
            receipt=self.audit.append({'kind':'sentinelle_externe','result':result})
            result['audit_receipt']=receipt
            self.last=(signature,time.monotonic())
        else:result['audit_receipt']=None
        current_alerts=set()
        result['dashboard_updates']=[]
        for issue in result['issues']:
            identifier='sentinelle-'+hashlib.sha256(canonique([result['reference_sha256'],issue['kind'],issue['target']])).hexdigest()[:24]
            current_alerts.add(identifier)
            if identifier in self.open_alerts:continue
            payload={'id':identifier,'titre':'Sentinelle externe : '+issue['kind'].replace('_',' '),
                     'statut':'a_verifier','gravite':'haute','origine':'Témoin Mac externe, sans attestation de root',
                     'faits':[json.dumps(issue,ensure_ascii=False),'Référence et preuve conservées hors VM ; aucun verdict malware.']}
            try:self.http('/api/incident',payload);result['dashboard_updates'].append({'id':identifier,'posted':True})
            except Exception:result['dashboard_updates'].append({'id':identifier,'posted':False});current_alerts.discard(identifier)
        for identifier in self.open_alerts-current_alerts:
            try:
                self.http('/api/incident',{'id':identifier,'titre':'Sentinelle externe : contrôle rétabli',
                    'statut':'resolu','gravite':'information','origine':'Témoin Mac externe',
                    'faits':['Contrôle ciblé revenu à la référence ; ne prouve pas une décontamination générale.']})
                result['dashboard_updates'].append({'id':identifier,'posted':True,'resolved':True})
            except Exception:current_alerts.add(identifier)
        self.open_alerts=current_alerts
        result['check_duration_ms']=round((time.monotonic()-started)*1000,3)
        return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference',type=Path,default=HOME/'reference.json')
    parser.add_argument('--audit',type=Path,default=HOME/'audit.jsonl')
    parser.add_argument('--watch',action='store_true')
    parser.add_argument('--interval',type=float,default=5)
    args=parser.parse_args()
    if sys.platform!='darwin':parser.error('ce témoin doit tourner sur le Mac externe')
    if not 2<=args.interval<=60:parser.error('intervalle entre 2 et 60 secondes')
    # Keep descriptor alive until process exit; launchd restart reuses the
    # existing approved reference, never enrollment from the guest.
    watch_lock=acquire_watch_lock(args.reference.parent/'watch.lock') if args.watch else None
    sentinel=ExternalSentinel(args.reference,args.audit)
    while True:
        result=sentinel.check()
        print(json.dumps({'status':result['status'],'issues':len(result['issues']),
                          'audit_receipt':result['audit_receipt']},ensure_ascii=False),flush=True)
        if not args.watch:break
        time.sleep(args.interval)


if __name__=='__main__':main()
