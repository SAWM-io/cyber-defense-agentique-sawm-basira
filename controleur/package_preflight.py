"""Sas de lecture avant installation. Aucun apt/dpkg --install dans ce module.

L'entrée est copiée depuis une fixture explicite vers un instantané root. Le
worker lit cet instantané sans privilège ni réseau dans une unité transitoire.
Un résultat positif bloque ; l'absence d'alerte exige encore l'accord propriétaire.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from controleur import vm_labo as vm

REMOTE = r'''
import hashlib,json,os,pathlib,stat,subprocess,tempfile,time
source=pathlib.Path(package)
if source.resolve()!=source or any(p.is_symlink() for p in (source,*source.parents)):
 raise ValueError('symbolic_input')
root=pathlib.Path('/run/sawm-package-review');root.mkdir(mode=0o755,exist_ok=True)
job=root/run;job.mkdir(mode=0o755)
staged=job/'package.deb'
with os.fdopen(os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as i:
 s=os.fstat(i.fileno())
 if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or not 0<s.st_size<=64*1024**2:
  raise ValueError('input_not_bounded_regular_file')
 with open(staged,'xb') as o:
  h=hashlib.sha256();size=0
  while True:
   data=i.read(1024*1024)
   if not data:break
   size+=len(data)
   if size>64*1024**2:raise ValueError('input_expanded_during_copy')
   h.update(data);o.write(data)
 after=os.fstat(i.fileno());current=source.stat()
 identity=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
 if identity(s)!=identity(after) or identity(s)!=identity(current):raise ValueError('input_changed_during_copy')
staged.chmod(0o444)
unit='labo-package-review-'+run+'.service'
properties={'DynamicUser':'yes','PrivateNetwork':'yes','PrivateTmp':'yes','PrivateDevices':'yes',
 'ProtectSystem':'strict','ProtectHome':'yes','NoNewPrivileges':'yes','CapabilityBoundingSet':'',
 'ProtectKernelTunables':'yes','ProtectKernelModules':'yes','ProtectKernelLogs':'yes','ProtectControlGroups':'yes',
 'RestrictSUIDSGID':'yes','RestrictRealtime':'yes','RestrictAddressFamilies':'AF_UNIX',
 'MemoryMax':'1700M','CPUQuota':'75%','TasksMax':'32','RuntimeMaxSec':'145','LimitFSIZE':'128M',
 'UMask':'0077','InaccessiblePaths':'/opt/sawm-labo/fixtures -/opt/sawm-labo/evidence /root /home',
 'TemporaryFileSystem':'/tmp:rw,nosuid,nodev,noexec,size=256M'}
args=['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit]
for key,value in properties.items():args+=['-p',key+'='+value]
args+=['/usr/bin/python3','/opt/sawm-labo/agent/package_inspector.py',str(staged)]
with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
 started=time.monotonic();p=subprocess.run(args,stdout=out,stderr=err,timeout=160)
 out.seek(0);raw=out.read(1024*1024+1);err.seek(0);error=err.read(4096).decode(errors='replace')
 if p.returncode or len(raw)>1024*1024:
  report={'schema':'sawm-package-preflight/v1','admission':'inconclusive_installation_not_permitted',
    'error':'isolated_worker_failed','returncode':p.returncode,'diagnostic':error[:300]}
 else:
  try:report=json.loads(raw)
  except Exception:report={'admission':'inconclusive_installation_not_permitted','error':'worker_invalid_json'}
 actual=hashlib.sha256(staged.read_bytes()).hexdigest()
 if actual!=h.hexdigest() or report.get('sha256') not in (None,actual):
  report.update(admission='inconclusive_installation_not_permitted',error='staged_input_changed')
 report.update(run=run,package_sha256=actual,package_bytes=size,
    isolation={'unit':unit,'properties':properties,'total_wall_ms':round((time.monotonic()-started)*1000,3)},
    installed=False,installation_executed=False,staged_package=str(staged),
    staged_input_retained=True,policy='scan_and_review_only_no_installation_authority')
 print(json.dumps(report,ensure_ascii=False))
'''


def inspect(package, *, json_code_fn=None):
    if (not isinstance(package, str) or not re.fullmatch(
            r'/opt/sawm-labo/fixtures/package-defense/[a-zA-Z0-9_./-]+\.deb', package)
            or '..' in Path(package).parts):
        raise ValueError('package_outside_enrolled_fixture_scope')
    run = uuid.uuid4().hex[:12]
    return (json_code_fn or vm.json_code)('package=' + repr(package) + '\nrun=' + repr(run) + '\n' + REMOTE, timeout=175)


def publish(report):
    from controleur.validation import post, now
    run = report['run']; destination = ROOT / 'releves/rapports' / ('package-preflight-' + run + '.json')
    destination.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    from controleur.audit_signe import JournalSigne
    JournalSigne(destination.with_suffix('.jsonl')).append(report)
    post('/api/incident', {'id': 'package-' + run, 'titre': 'Contrôle avant installation',
        'statut': 'a_revoir', 'run_id': run,
        'faits': [report['admission'], 'SHA256 : ' + report['package_sha256'],
                  'Aucun script du paquet exécuté ; aucune installation réalisée.'],
        'preuves': ['releves/rapports/' + destination.name]})
    return destination


def main():
    p = argparse.ArgumentParser(); p.add_argument('package'); args = p.parse_args()
    result = inspect(args.package); path = publish(result)
    print(json.dumps({'report': str(path), 'admission': result['admission'], 'installed': False}))


if __name__ == '__main__':
    main()
