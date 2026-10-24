"""Bounded external witness test: sensor stop/restart and synthetic copy only.

Neither a hostile rootkit nor a boot/root-resistant attestation test. The Mac
keeps the reference and Ed25519 key; the guest sends non-attested measurements.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import uuid

if not __package__:sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from controleur import vm_labo
from controleur.sentinelle_externe import ExternalSentinel,HOME,guest_snapshot

ROOT=Path(__file__).resolve().parents[1]
UNIT='labo-capteur-large.service'
SERVICES=[UNIT,'labo-telemetrie.service','labo-temoin.service','ssh.service']


def probe():
    return vm_labo.json_code('''import glob,json,pathlib,subprocess,urllib.request
def read(path):
 try:return pathlib.Path(path).read_text().strip()[:128]
 except OSError:return None
secure=None
for name in glob.glob('/sys/firmware/efi/efivars/SecureBoot-*'):
 try:secure=pathlib.Path(name).read_bytes()[4]==1
 except (OSError,IndexError):pass
with urllib.request.urlopen('http://127.0.0.1:8080/sante',timeout=2) as response:witness=response.status
print(json.dumps({'services':{unit:subprocess.run(['systemctl','is-active',unit],capture_output=True,text=True,timeout=2).stdout.strip() for unit in SERVICES},
 'witness_http':witness,'kernel':subprocess.run(['uname','-r'],capture_output=True,text=True).stdout.strip(),
 'reported_hardening':{'efi_present':pathlib.Path('/sys/firmware/efi').exists(),'secure_boot_reported':secure,
 'tpm_devices':[pathlib.Path(p).name for p in glob.glob('/dev/tpm*')],
 'ima_log_present':pathlib.Path('/sys/kernel/security/ima/ascii_runtime_measurements').exists(),
 'lockdown':read('/sys/kernel/security/lockdown'),
 'module_signature_enforcement':read('/sys/module/module/parameters/sig_enforce')},
 'hardware_attestation_performed':False}))
'''.replace('SERVICES',repr(SERVICES)))


def systemctl(verb):
    return vm_labo.json_code('import json,subprocess\np=subprocess.run(["systemctl",'+repr(verb)+','+repr(UNIT)+'],capture_output=True,timeout=12)\nprint(json.dumps({"success":p.returncode==0}))')


def run():
    if sys.platform!='darwin' or vm_labo.local_vm():raise RuntimeError('external_mac_required')
    started=datetime.now(timezone.utc);stamp=started.strftime('%Y%m%dT%H%M%SZ')
    original=b'sawm external witness synthetic configuration v1\n'
    altered=b'sawm external witness synthetic configuration changed v2\n'
    fixture='/opt/sawm-labo/fixtures/sentinel-'+uuid.uuid4().hex
    remote=fixture+'/reference.conf'
    expected=hashlib.sha256(original).hexdigest()
    private=HOME/('validation-'+stamp);private.mkdir(mode=0o700,parents=True)
    reference={'schema':'sawm-external-reference/v1','controller':'mac_external',
               'auto_accept_guest_changes':False,'services':SERVICES,
               'files':[{'path':remote,'sha256':expected}],
               'approved_source':'synthetic bytes chosen on the external controller before guest write'}
    ref=private/'reference.json';ref.write_text(json.dumps(reference,sort_keys=True));ref.chmod(0o600)
    reference_before=ref.read_bytes()
    output=ROOT/'releves/rapports';output.mkdir(parents=True,exist_ok=True)
    audit_path=output/('audit-sentinelle-externe-'+stamp+'.jsonl')
    sentinel=ExternalSentinel(ref,audit_path)
    cases=[];restored=False;cleanup={};error=None
    before=probe()
    if any(x!='active' for x in before['services'].values()) or before['witness_http']!=200:
        raise RuntimeError('baseline_services_not_healthy')
    vm_labo.json_code('import json,pathlib\np=pathlib.Path('+repr(fixture)+');p.mkdir(mode=0o700)\n(p/"reference.conf").write_bytes('+repr(original)+')\nprint(json.dumps({"fixture_created":True}))')
    try:
        baseline=sentinel.check()
        if baseline['issues']:raise RuntimeError('baseline_not_healthy')
        cases.append({'case':'baseline','check':baseline})
        evidence_before=audit_path.read_bytes()
        # Very short sensor-only outage. systemctl start is unconditional even
        # when the probe or dashboard fails; no network/key configuration moves.
        mark=time.monotonic()
        try:
            if not systemctl('stop')['success']:raise RuntimeError('sensor_stop_failed')
            outage=sentinel.check()
            cases.append({'case':'sensor_stopped','check':outage,
                          'elapsed_from_stop_request_ms':round((time.monotonic()-mark)*1000,3)})
        finally:
            restored=systemctl('start')['success']
        if not restored:raise RuntimeError('sensor_restart_failed')
        cases.append({'case':'sensor_restored','check':sentinel.check()})
        vm_labo.json_code('import json,pathlib\npathlib.Path('+repr(remote)+').write_bytes('+repr(altered)+')\nprint(json.dumps({"fixture_changed":True}))')
        mark=time.monotonic();changed=sentinel.check()
        cases.append({'case':'copy_tampered','check':changed,
                      'detection_check_ms':round((time.monotonic()-mark)*1000,3)})
        preserved=audit_path.read_bytes().startswith(evidence_before)
        vm_labo.json_code('import json,pathlib\npathlib.Path('+repr(remote)+').write_bytes('+repr(original)+')\nprint(json.dumps({"fixture_restored":True}))')
        cases.append({'case':'copy_restored','check':sentinel.check()})
        proof={'external_evidence_prefix_preserved':preserved,
               'external_reference_unchanged':ref.read_bytes()==reference_before,
               'audit_verification':sentinel.audit.verify(),
               'private_key_was_sent_to_guest':False,
               'external_audit_sha256':hashlib.sha256(audit_path.read_bytes()).hexdigest()}
    except Exception as exc:
        error=type(exc).__name__+': '+str(exc)[:200]
        proof={'audit_verification':sentinel.audit.verify()}
    finally:
        # Sensor stop was this test's only service mutation.
        restored=systemctl('start')['success']
        cleanup=vm_labo.json_code('import json,pathlib\np=pathlib.Path('+repr(remote)+');p.unlink(missing_ok=True)\nd=p.parent;d.rmdir()\nprint(json.dumps({"synthetic_copy_deleted":not p.exists(),"fixture_directory_deleted":not d.exists(),"system_config_modified":False,"network_modified":False}))')
        cleanup['sensor_restart_success']=restored
    after=probe()
    kinds={c['case']:{i['kind'] for i in c['check']['issues']} for c in cases}
    assertions={
        'inactive_sensor_detected':'service_non_actif' in kinds.get('sensor_stopped',set()),
        'modified_copy_detected':'empreinte_differe_reference_externe' in kinds.get('copy_tampered',set()),
        'all_restoration_checks_clear':all(not kinds.get(k,{'missing'}) for k in ('sensor_restored','copy_restored')),
        'dashboard_alerts_delivered':all(any(x.get('posted') for x in c['check']['dashboard_updates']) for c in cases if c['case'] in ('sensor_stopped','copy_tampered')),
        'external_evidence_preserved':proof.get('external_evidence_prefix_preserved') is True,
        'external_reference_unchanged':proof.get('external_reference_unchanged') is True,
        'signature_chain_valid':proof['audit_verification'].get('valide') is True,
        'services_restored':all(x=='active' for x in after['services'].values()) and after['witness_http']==200,
        'fixture_removed':cleanup.get('synthetic_copy_deleted') is True,
    }
    report={'schema':'sawm-external-sentinel-validation/v1','tested_at':started.isoformat(),
            'status':'passed' if not error and all(assertions.values()) else 'failed',
            'assertions':assertions,'cases':cases,'before':before,'after':after,
            'proof':proof,'cleanup':cleanup,'error':error,
            'scope':'external Mac witness, stopped sensor, changed synthetic configuration copy',
            'limits':['Guest root can falsify SSH measurements. No hostile-root resistance demonstrated.',
                      'Detection is polling: shown check latency excludes configured interval and network loss.',
                      'No guest TPM attestation, recovery boot, firewall or malware exercised.',
                      'Private Ed25519 key and approved reference remain on the Mac. A compromised Mac is out of scope.']}
    target=output/('validation-sentinelle-externe-'+stamp+'.json')
    target.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'path':str(target),'status':report['status'],'assertions':assertions,'error':error},ensure_ascii=False))
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',required=True,action='store_true');parser.parse_args();run()
