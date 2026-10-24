"""Explicit benign VM test: real file writes, no service or policy mutation."""
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

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / 'invite/agent_labo/write_attribution.py'

SOURCE = r'''
import hashlib,json,os,pathlib,shutil,sqlite3,sys,tempfile,time
sys.path.insert(0,'/opt/sawm-labo/agent')
from write_attribution import WriteAttributionSensor
root=pathlib.Path(tempfile.mkdtemp(prefix='write-attribution-',dir='/opt/sawm-labo/fixtures'))
sensor=None
report={'schema':'sawm-write-attribution-validation/v1','scope':'temporary_synthetic_files_only','cases':[]}
try:
    binary=root/'probe.bin'; binary.write_bytes(b'fixture-only\n')
    control=root/'unmonitored.bin'; control.write_bytes(b'fixture-only\n')
    database=root/'synthetic.sqlite'
    db=sqlite3.connect(database);db.execute('create table synthetic(id integer, amount integer)')
    db.execute('insert into synthetic values (1, 10)');db.commit();db.close()
    before=hashlib.sha256(database.read_bytes()).hexdigest()
    sensor=WriteAttributionSensor([binary,database]).start()
    started=time.monotonic()
    for name,call in (
        ('write',lambda fd:os.write(fd,b'A')),
        ('pwrite',lambda fd:os.pwrite(fd,b'B',1)),
        ('writev',lambda fd:os.writev(fd,[b'C',b'D']))):
        count=sensor.snapshot()['observed_events']
        fd=os.open(binary,os.O_WRONLY)
        try:written=call(fd);os.fsync(fd)
        finally:os.close(fd)
        deadline=time.monotonic()+2
        while time.monotonic()<deadline and sensor.snapshot()['observed_events']==count:time.sleep(.01)
        events=sensor.snapshot()['events'][count:]
        matching=[e for e in events if e['pid']==os.getpid() and e['inode']==binary.stat().st_ino and e['bytes']==written]
        report['cases'].append({'name':name,'passed':bool(matching),'successful_write_events':len(matching),
          'captured_latency_ms':[round(e['capture_latency_ms'],3) for e in matching],
          'process_identity_verified':all(e['process']['identity_stable'] for e in matching) if matching else False})
    count=sensor.snapshot()['observed_events']; control.write_bytes(b'outside exact watched inodes')
    time.sleep(.2)
    report['cases'].append({'name':'unmonitored_file_excluded','passed':sensor.snapshot()['observed_events']==count})
    count=sensor.snapshot()['observed_events']
    db=sqlite3.connect(database);db.execute('update synthetic set amount=11 where id=1');db.commit();db.close()
    deadline=time.monotonic()+2
    while time.monotonic()<deadline and sensor.snapshot()['observed_events']==count:time.sleep(.01)
    time.sleep(.1)
    after=hashlib.sha256(database.read_bytes()).hexdigest()
    events=[e for e in sensor.snapshot()['events'][count:] if e['pid']==os.getpid() and e['inode']==database.stat().st_ino]
    report['cases'].append({'name':'sqlite_write_and_hash_change','passed':bool(events) and before!=after,
      'successful_write_events':len(events),'hash_changed':before!=after,
      'captured_latency_ms':[round(e['capture_latency_ms'],3) for e in events],
      'process_identity_verified':all(e['process']['identity_stable'] for e in events) if events else False})
    state=sensor.snapshot()
    report['sensor']={k:state[k] for k in ('active','observed_events','evicted_events','loss_notifications','invalid_events','error','limits')}
    report['attribution_fields']=['PID','TID','UID','EUID','loginuid','PPID','process_start_ns','cgroup_id','device','inode','boot_id','successful_bytes']
    report['duration_s']=round(time.monotonic()-started,3)
    report['limits']=['No block requested or performed','Capture latency is not SAWM decision latency','Hash change is not proof of malware','Only temporary exact file inodes covered','Journal/WAL files require explicit enrollment']
except Exception as exc:
    report['error']=type(exc).__name__+': '+str(exc)[:120]
finally:
    if sensor:sensor.close()
    shutil.rmtree(root)
    report['cleanup']={'temporary_files_removed':not root.exists(),'sensor_stopped':not sensor or not sensor.process or sensor.process.poll() is not None,'existing_services_changed':False,'manifest_changed':False}
report['status']='passed' if len(report['cases'])==5 and all(x['passed'] for x in report['cases']) and not report.get('error') else 'failed'
print(json.dumps(report))
'''


def run():
    vm_labo.push(MODULE, '/opt/sawm-labo/agent/write_attribution.py')
    report = vm_labo.json_code(SOURCE, timeout=40)
    report['tested_at'] = datetime.now(timezone.utc).isoformat()
    report['sensor_source_sha256'] = hashlib.sha256(MODULE.read_bytes()).hexdigest()
    name = datetime.now(timezone.utc).strftime('validation-write-attribution-%Y%m%dT%H%M%SZ.json')
    path = ROOT / 'releves/rapports' / name
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'path': str(path), **report}, ensure_ascii=False))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', required=True)
    parser.parse_args()
    run()
