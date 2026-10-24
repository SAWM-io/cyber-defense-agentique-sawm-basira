"""Campagne autorisée et bornée, 1,125 Gio réels de fixtures dans la VM dédiée.

Aucun objet métier, mandat existant, service de défense ou pare-feu n'est modifié.
Le service staging reste déclenchable manuellement ; aucun timer n'est activé.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

if __package__:
    from . import vm_labo
else:
    import vm_labo

ROOT=Path(__file__).resolve().parents[1]
MODULE=ROOT/'invite/agent_labo/large_tree.py'
SERVICE=ROOT/'provisionnement/systemd/labo-integrite-arbre-staging.service'

SOURCE=r'''
import hashlib,json,os,pathlib,resource,shutil,subprocess,sys,tempfile,time
sys.path.insert(0,'/opt/sawm-labo/agent')
import large_tree as lt
BASE=pathlib.Path('/opt/sawm-labo')
if BASE.resolve()!=BASE:raise ValueError('racine_labo_symbolique')
if shutil.disk_usage(BASE).free<4*1024**3:raise ValueError('espace_libre_insuffisant')
unit='labo-integrite-arbre-staging.service'
if subprocess.run(['systemctl','is-active',unit],capture_output=True,text=True).stdout.strip()=='active':
 raise ValueError('staging_deja_actif')
created_ms=int(time.time()*1000)
tree=pathlib.Path(tempfile.mkdtemp(prefix='large-tree-',dir=BASE/'fixtures'))
refs=BASE/'references'/tree.name;refs.mkdir(mode=0o700,parents=True,exist_ok=False)
baseline=refs/'baseline.json';config=BASE/'config/large-tree-staging.json'
config.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
if config.exists():
 previous=lt.read_trusted(str(config),str(tree))
 lt.write_json(refs/'previous-config.json',previous,str(tree),exclusive=True)
output=pathlib.Path('/run/sawm-large-tree/status.json');output.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
cfg=dict(chunk_bytes=1024**2,block_bytes=4*1024**2,max_bytes=2*1024**3,max_file_bytes=128*1024**2,
         max_entries=1000,max_blocks=1024,max_seconds=120,bytes_per_second=64*1024**2,max_changes=100)
report=dict(schema='sawm-large-tree-validation/v1',started_ms=created_ms,
 scope='VM 192.0.2.3, generated fixture tree only',root=str(tree),baseline_path=str(baseline),
 cases=[],limits=['No malware or writer attribution from hash changes.',
 'Test mutation time is known only because this fixture generator records it.',
 'These are page-cache-warm scans; no cache-drop or cold-storage benchmark.',
 'No timer enabled; optional staging service with CPU 50%, memory192MiB.',
 'No whole-server coverage and no automatic containment.'])
mutation_saved=None; renamed=False;deleted=None;mode=None;owner=None
def command(args,timeout=130):
 p=subprocess.run(args,check=True,capture_output=True,text=True,timeout=timeout)
 return json.loads(p.stdout)
def scan(name,mutation_ms=None):
 began=int(time.time()*1000)
 result=command([sys.executable,'/opt/sawm-labo/agent/large_tree.py','--config',str(config)])
 result['campaign_case']=name;result['trigger_to_start_ms']=0
 if mutation_ms is not None:
  result['fixture_mutation_completed_ms']=mutation_ms
  result['fixture_wait_before_launch_ms']=began-mutation_ms
  result['fixture_mutation_to_report_ms']=result['observed_ms']-mutation_ms
 lt.write_json(refs/(name+'.json'),result,str(tree),exclusive=True)
 return result
try:
 start=time.monotonic();cpu=time.process_time()
 for i in range(18):
  directory=tree/f'shard-{i//6}';directory.mkdir(exist_ok=True)
  with (directory/f'payload-{i:02d}.bin').open('xb') as f:
   for _ in range(64):f.write(os.urandom(1024**2))
   f.flush();os.fsync(f.fileno())
 (tree/'delete-me.txt').write_bytes(b'Synthetic deletion witness\n')
 (tree/'rename-me.txt').write_bytes(b'Synthetic rename witness\n')
 (tree/'permissions.txt').write_bytes(b'Synthetic permissions witness\n')
 (tree/'owner.txt').write_bytes(b'Synthetic owner witness\n')
 files=[p for p in tree.rglob('*') if p.is_file()]
 actual_bytes=sum(p.stat().st_size for p in files);allocated=sum(p.stat().st_blocks*512 for p in files)
 report['fixture_generation']=dict(seconds=round(time.monotonic()-start,3),cpu_seconds=round(time.process_time()-cpu,3),
  files=len(files),logical_bytes=actual_bytes,allocated_bytes=allocated,
  random_payload_bytes=18*64*1024**2,method='Fresh os.urandom buffer for every MiB, normal write+fsync, no sparse allocation or repeated buffer.')
 if actual_bytes<1024**3 or allocated<actual_bytes:raise AssertionError('fixture_pas_reellement_allouee')
 approved=command([sys.executable,'/opt/sawm-labo/agent/large_tree.py','--approve-baseline','--root',str(tree),
                   '--baseline',str(baseline),'--limits-json',json.dumps(cfg)])
 report['baseline_approval']=approved
 reference=lt.read_trusted(str(baseline),str(tree),approved['baseline_sha256'])
 payloads=[e for e in reference['entries'].values() if e['kind']=='file' and e['size']==64*1024**2]
 report['fixture_generation']['unique_payload_sha256']=len({e['sha256'] for e in payloads})
 if len(payloads)!=18 or len({e['sha256'] for e in payloads})!=18:raise AssertionError('payloads_non_uniques')
 lt.write_json(config,dict(root=str(tree),baseline=str(baseline),baseline_sha256=approved['baseline_sha256'],
                            output=str(output),limits=cfg),str(tree))
 clean=scan('clean');report['cases'].append(dict(name='baseline_clean',passed=clean['status']=='unchanged',result=clean))
 path=tree/'shard-0/payload-00.bin'
 with path.open('r+b') as f:
  first=f.read(4096);f.seek(-4096,os.SEEK_END);last=f.read(4096)
  mutation_saved=(first,last)
  f.seek(0);f.write(bytes(x^0xff for x in first));f.seek(-4096,os.SEEK_END);f.write(bytes(x^0xff for x in last));f.flush();os.fsync(f.fileno())
 (tree/'added.txt').write_bytes(b'Synthetic addition witness\n')
 deleted=(tree/'delete-me.txt').read_bytes()
 # Preserve only this tiny synthetic witness outside the monitored tree so its
 # exact inode can be restored after a real unlink, without blessing a new one.
 os.link(tree/'delete-me.txt',refs/'deleted-preserved.txt');(tree/'delete-me.txt').unlink()
 (tree/'rename-me.txt').rename(tree/'renamed.txt');renamed=True
 mode=(tree/'permissions.txt').stat().st_mode&0o7777;(tree/'permissions.txt').chmod(0o600 if mode!=0o600 else 0o640)
 st=(tree/'owner.txt').stat();owner=(st.st_uid,st.st_gid);os.chown(tree/'owner.txt',65534,65534)
 changed=scan('changed',int(time.time()*1000))
 expected={'content_changed','added','deleted','rename_candidate','permissions_changed','owner_changed'}
 report['cases'].append(dict(name='all_fixture_changes',passed=changed['status']=='changed' and expected<=set(changed['counts']),result=changed))
 # Brief symlink test must refuse before reading the outside target.
 (tree/'a-link').symlink_to('/etc/passwd')
 linked=scan('symlink_refused');(tree/'a-link').unlink()
 report['cases'].append(dict(name='symlink_refused',passed=linked['status']=='inconclusive' and 'lien_symbolique_refuse' in linked.get('reason',''),result=linked))
except Exception as exc:
 report['error']=type(exc).__name__+': '+str(exc)[:300]
finally:
 try:
  if mutation_saved:
   with (tree/'shard-0/payload-00.bin').open('r+b') as f:
    f.seek(0);f.write(mutation_saved[0]);f.seek(-4096,os.SEEK_END);f.write(mutation_saved[1]);f.flush();os.fsync(f.fileno())
  (tree/'added.txt').unlink(missing_ok=True);(tree/'a-link').unlink(missing_ok=True)
  if deleted is not None:
   if not (tree/'delete-me.txt').exists():os.link(refs/'deleted-preserved.txt',tree/'delete-me.txt')
   (refs/'deleted-preserved.txt').unlink(missing_ok=True)
  if renamed:(tree/'renamed.txt').rename(tree/'rename-me.txt')
  if mode is not None:(tree/'permissions.txt').chmod(mode)
  if owner is not None:os.chown(tree/'owner.txt',*owner)
  restored=scan('restored') if baseline.exists() and config.exists() else None
  restoration_good=bool(restored and restored['status']=='unchanged')
  report['restoration']=dict(fixture_content_and_permissions_restored=restoration_good,
   original_baseline_preserved=baseline.exists(),existing_services_or_manifest_modified=False)
  report['cases'].append(dict(name='restored_fixture_content',passed=restoration_good,result=restored))
 except Exception as exc:report['restoration']={'error':type(exc).__name__+': '+str(exc)[:200]}
if not report.get('error') and report['restoration'].get('fixture_content_and_permissions_restored'):
 subprocess.run(['systemctl','daemon-reload'],check=True,capture_output=True,timeout=15)
 subprocess.run(['systemctl','start',unit],check=True,capture_output=True,timeout=140)
 status=subprocess.run(['systemctl','show',unit,'--property=Result,ExecMainStatus,MemoryPeak,CPUUsageNSec,ActiveState'],check=True,capture_output=True,text=True,timeout=10).stdout
 report['staging_service']={line.split('=',1)[0]:line.split('=',1)[1] for line in status.splitlines() if '=' in line}
 report['staging_snapshot']=json.loads(output.read_text())
 report['cases'].append(dict(name='optional_service_runs',passed=report['staging_service'].get('Result')=='success' and report['staging_service'].get('ExecMainStatus')=='0'))
 report['staging_service']['enabled']=subprocess.run(['systemctl','is-enabled',unit],capture_output=True,text=True).stdout.strip()
report['finished_ms']=int(time.time()*1000)
report['status']='passed' if len(report['cases'])==5 and all(c['passed'] for c in report['cases']) and not report.get('error') else 'failed'
lt.write_json(refs/'validation.json',report,str(tree),exclusive=True)
print(json.dumps(report))
'''


def run():
    vm_labo.push(MODULE,'/opt/sawm-labo/agent/large_tree.py')
    vm_labo.push(SERVICE,'/etc/systemd/system/labo-integrite-arbre-staging.service')
    report=vm_labo.json_code(SOURCE,timeout=420)
    report['tested_at']=datetime.now(timezone.utc).isoformat()
    report['source_sha256']=hashlib.sha256(MODULE.read_bytes()).hexdigest()
    path=ROOT/'releves/rapports'/('validation-gros-dossiers-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.json')
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'path':str(path),'status':report['status'],'cases':[{k:c[k] for k in ('name','passed')} for c in report['cases']],
                      'error':report.get('error'),'bytes':report.get('fixture_generation',{}).get('logical_bytes')}))
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',action='store_true',required=True);parser.parse_args()
    run()
