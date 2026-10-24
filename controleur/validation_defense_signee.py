"""Validation autorisée sur la VM dédiée, fixtures SQLite synthétiques seulement.

L'effet local, la décision Cloud et le nettoyage opérateur sont comptés
séparément. Chaque exécution conserve un rapport neuf, y compris les échecs.
"""
from __future__ import annotations
import json
from pathlib import Path
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from controleur import vm_labo as vm
from controleur import validation_database as old
from controleur.maintenance import (SCHEMA,POLICY_SCHEMA,OBS_KEYS,public_key_record,signer)
from controleur.audit_signe import JournalSigne
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def write_manifest(m):
    return vm.json_code('value='+repr(m)+'\n'+'''import fcntl,json,os,pathlib,hashlib
with open('/opt/sawm-labo/.executeur.lock','a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 p=pathlib.Path('/opt/sawm-labo/manifeste.json');t=p.with_suffix('.tmp')
 t.write_text(json.dumps(value));t.chmod(0o600);os.replace(t,p)
 value['_sha256']=hashlib.sha256(p.read_bytes()).hexdigest()
 print(json.dumps(value))
''')


def state():
    return vm.json_code("import pathlib,json;p=pathlib.Path('/run/sawm-labo/defense-state.json');print(p.read_text() if p.exists() else '{}')")


def service(command):
    return vm.commands([['systemctl',command,'labo-defense-fichiers.service']])


def run_case(mode,permit='absent', *, cloud=False):
    run='guard-'+uuid.uuid4().hex[:10];unit='labo-'+run+'.service'
    path='/opt/sawm-labo/fixtures/database-defense/run-'+run+'/ledger.sqlite'
    report={'id':run,'protocol':'sawm-signed-defense/v2','mode':mode,'permit':permit,'cloud_requested':cloud,'status':'running',
            'origin':'local_policy','started_ms':int(time.time()*1000)}
    baseline=vm.json_code("import pathlib,json;print(pathlib.Path('/opt/sawm-labo/manifeste.json').read_text())")
    backup=Path.home()/'.sawm-labo/campaign-backups'/f'{run}-manifest.json'
    backup.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    backup.write_text(json.dumps(baseline));backup.chmod(0o600)
    service('stop')
    try:
        old.db('prepare',run); before=old.db('status',run)
        report['before']=before
        assert old.service_start(unit,run,mode,180)['returncode']==0
        time.sleep(.6)
        observation=vm.json_code('import sys,json;sys.path.insert(0,"/opt/sawm-labo");from maintenance import observer_os;print(json.dumps(observer_os('+repr(unit)+','+repr(path)+')))')
        key=Ed25519PrivateKey.generate()
        record=public_key_record(key,'institution-lab-cto',units=[unit],operations=['file-write','sqlite-exclusive-lock'],objects=[path])
        target={'unit':unit,'path':path,'kind':'sqlite','reference_sha256':before['reference_sha256'],
                'automatic_containment':not cloud}
        m={**baseline,'generation':run,'run_id':run,
            'unites_autorisees':list(set(baseline['unites_autorisees']+[unit])),
            'defense_fichiers':{'enabled':True,'targets':[target]},
            'maintenance':{'schema':POLICY_SCHEMA,'machine_id':observation['machine_id'],
                'keys':[record],'mandates':[],'revoked_mandates':[]}}
        now=int(time.time()*1000)
        if permit!='absent':
            operation='sqlite-exclusive-lock' if mode=='lock' else 'file-write'
            payload={**{k:observation[k] for k in OBS_KEYS},'schema':SCHEMA,'mandate_id':run+'-permit',
                'principal':record['principal'],'key_id':record['key_id'],'generation':run,
                'operation':operation,'issued_at_ms':now-1000,'not_before_ms':now-1000,
                'expires_at_ms':now+170000 if permit!='expired' else now-100}
            envelope=signer(payload,key)
            if permit=='forged':envelope['signature']='A'*88
            if permit=='revoked':m['maintenance']['revoked_mandates']=[payload['mandate_id']]
            m['maintenance']['mandates']=[envelope]
        m=write_manifest(m)
        report['manifest_sha256']=m['_sha256']
        start=time.monotonic();service('start')
        deadline=start+35; snapshot={}; selected=None
        while time.monotonic()<deadline:
            snapshot=state()
            selected=next((x for x in snapshot.get('targets',[]) if x.get('unit')==unit),None)
            historical=next((x for x in reversed(snapshot.get('alertes',[])) if x.get('unit')==unit and x.get('action')),None)
            if historical:selected=historical
            authorized_observed=(selected and selected.get('authorization',{}).get('authorized')
                and selected.get('diagnostic',{}).get('recommandation')=='surveiller'
                and ('file-write' if mode=='tamper' else 'sqlite-exclusive-lock') in selected.get('qualified_operations',[]))
            if selected and (selected.get('action') or authorized_observed
                or permit=='forged' and selected.get('diagnostic',{}).get('recommandation')=='signaler'
                or cloud and ('file-write' if mode=='tamper' else 'sqlite-exclusive-lock') in selected.get('qualified_operations',[])):
                break
            time.sleep(.25)
        report['monitor_start_to_verdict_ms']=round((time.monotonic()-start)*1000,3)
        report['snapshot']=snapshot;report['result']=selected
        report['initial_identity']={k:observation[k] for k in OBS_KEYS}
        if permit=='valid' and selected:
            # Exercise the actual privileged boundary, not merely inaction by
            # the monitor. An unsolicited stop must be refused under this grant.
            request={'decision_id':'veto-'+uuid.uuid4().hex,'action':'arreter-service','cible':unit,
                     'generation':run,'manifest_sha256':m['_sha256'],
                     'expected_identity':{'cible':unit,'boot_id':observation['boot_id'],
                         'MainPID':str(observation['pid']),'InvocationID':observation['invocation_id'],
                         'ControlGroup':observation['cgroup']}}
            report['veto_attempt']=vm.json_code('import subprocess,json;p=subprocess.run(["python3","/opt/sawm-labo/executeur/executeur.py"],input='+repr(json.dumps(request))+',capture_output=True,text=True,timeout=15);print(p.stdout)')
        if cloud and selected:
            from controleur import validation as v
            from connecteur.pont_memoire import PontMemoire
            from controleur.verification_action import observer_ressource,verifier_action
            pont=PontMemoire(campagne=run)
            try:
                decision,trace=v.decision_cloud(pont,[selected],run,[unit],
                    context='Base synthétique protégée. Inspection OS et mandat authentifié fournis. SQLITE_BUSY est une indisponibilité, pas une preuve de corruption. La maintenance valide couvre seulement son opération. Sans mandat valide, un verrou exclusif attribué qui empêche lecture et écriture viole la disponibilité. Choisir une action autorisée ou signaler les preuves manquantes.',
                    politique_locale={'generation':run,'manifest_sha256':m['_sha256'],
                        'unites_connues':m['veille']['unites_connues'],
                        'reseau_hors_baseline_autorise':m['veille']['reseau_hors_baseline_autorise'],
                        'actions_automatiques':['arreter-service'],
                        'database_policy':{'unit':unit,
                            'write_requires_authorization':True,
                            'write_authorized':any(x.get('operation')=='file-write' and x.get('authorized') is True for x in selected.get('authorizations',[])),
                            'exclusive_lock_authorized':bool(selected.get('authorization',{}).get('authorized') and mode=='lock'),
                            'availability_required':not bool(selected.get('authorization',{}).get('authorized') and mode=='lock'),
                            'integrity_required':not bool(selected.get('authorization',{}).get('authorized') and mode=='tamper'),
                            'reference_sha256':before['reference_sha256']}})
                report['cloud_trace']=trace;report['cloud_decision']={'action':decision.proposition.action if decision.proposition else None,'executable':decision.executable,'refus':decision.refus}
                if decision.executable and decision.proposition.action=='arreter-service':
                    identity=observer_ressource(unit);receipt=v.execute(decision,run,attendu=identity)
                    report['cloud_receipt']=receipt
                    if receipt.get('applique'):
                        report['origin']='SAWM';report['cloud_verification']=verifier_action('arreter-service',unit,receipt,identity)
            finally:pont.close()
        report['after']=old.db('status',run);report['witness']=old.healthy()
        report['unit_after']=vm.json_code('import subprocess,json;s=subprocess.run(["systemctl","show",'+repr(unit)+',"-p","ActiveState","-p","MainPID"],capture_output=True,text=True);print(json.dumps(dict(x.split("=",1) for x in s.stdout.splitlines() if "=" in x)))')
        authorized=permit=='valid'
        action=(selected or {}).get('action') or report.get('cloud_receipt') or {}
        if authorized:
            veto=report.get('veto_attempt') or {}
            expected=(report['unit_after']['ActiveState']=='active' and report['unit_after']['MainPID']==str(observation['pid'])
                and selected and selected.get('authorization',{}).get('authorized') is True and not action.get('applique')
                and veto.get('applique') is False and veto.get('refus',{}).get('motif')=='maintenance_signee_preservee')
        elif permit=='forged':
            expected=selected and selected.get('diagnostic',{}).get('recommandation')=='signaler' and not action.get('applique')
        else:
            expected=action.get('applique') is True and action.get('effet_verifie') is True and report['unit_after']['ActiveState']!='active'
            if mode=='lock':expected=expected and report['after']['read_available'] and report['after']['write_available']
            if cloud:expected=expected and report.get('cloud_verification',{}).get('statut')=='verifie'
        report['status']='passed' if expected and report['witness'].get('healthy') else 'failed'
    except Exception as e:
        report.update(status='error',error=type(e).__name__,detail=str(e)[:250])
    finally:
        cleanup_errors=[]
        for name,fn in [('stop_monitor',lambda:service('stop')),('stop_fixture',lambda:vm.commands([['systemctl','stop',unit]])),
                        ('restore_manifest',lambda:write_manifest(baseline)),('restart_monitor',lambda:service('start'))]:
            try:fn()
            except Exception as exc:cleanup_errors.append({'step':name,'error':type(exc).__name__})
        if cleanup_errors:report.update(status='error',cleanup_errors=cleanup_errors)
        report['cleanup']='operator_stop_and_manifest_restored_not_counted_as_defense'
        report['finished_ms']=int(time.time()*1000)
    return report


def main():
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--mode',choices=['lock','tamper'],required=True)
    p.add_argument('--permit',choices=['absent','valid','expired','revoked','forged'],default='absent')
    p.add_argument('--cloud',action='store_true');args=p.parse_args()
    result=run_case(args.mode,args.permit,cloud=args.cloud)
    dest=ROOT/'releves/rapports'/('validation-defense-signee-'+result['id']+'.json')
    dest.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    journal=JournalSigne(dest.with_suffix('.jsonl'));journal.append(result)
    print(json.dumps({'path':str(dest),'status':result['status'],'origin':result['origin'],
        'error':result.get('error'),'metrics':(result.get('result') or {}).get('metrics'),
        'cloud_decision':result.get('cloud_decision')}))
    return 0 if result['status']=='passed' else 1


if __name__=='__main__':raise SystemExit(main())
