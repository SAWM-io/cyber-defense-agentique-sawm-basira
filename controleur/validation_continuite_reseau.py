"""Preuve bornée : réseau témoin isolé, correcteur Mac, aucun réseau métier.

Le root invité ne contrôle pas la clé ni l'horloge de politique sur le Mac.
Il peut cependant arrêter SSH ou falsifier les sondes : pas d'attestation root.
Trois coupures réelles ; frontières du préavis testées en temps simulé.
"""
from __future__ import annotations
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import time
import uuid

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from controleur import vm_labo
from controleur.audit_signe import JournalSigne
from controleur.continuite_reseau import ContinuityPolicy
from controleur.veille import dashboard

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT/'releves/rapports/validation-resilience-reseau-20260924.json'
DAY = 86400


def stable_baseline(value):
    """Compare configuration, not the naturally decreasing DHCP/IPv6 lease timers."""
    value=json.loads(json.dumps(value))
    for address in value['management_addresses']:
        address.pop('valid_life_time',None)
        address.pop('preferred_life_time',None)
    return value


def baseline():
    return vm_labo.json_code('''import subprocess,json,urllib.request
def run(a):return subprocess.check_output(a,text=True,timeout=4).strip()
with urllib.request.urlopen('http://127.0.0.1:8080/sante',timeout=2) as r:health=r.status
print(json.dumps({'http':health,'services':{s:run(['systemctl','is-active',s]) for s in ['ssh','labo-temoin','labo-telemetrie','labo-capteur-large']},
'management_addresses':json.loads(run(['ip','-j','address','show','dev','enp0s1']))[0]['addr_info'],
'routes':json.loads(run(['ip','-j','route','show']))}))''')


def run():
    if sys.platform != 'darwin' or vm_labo.local_vm():
        raise RuntimeError('contrôleur Mac extérieur requis')
    ident = uuid.uuid4().hex[:8]
    names = [f'swc-{ident}-a', f'swc-{ident}-b']
    devices = [f'swc{ident}a', f'swc{ident}b']
    alias = 'sawm-continuity-'+ident
    report = {'schema':'sawm-network-continuity-validation/v1', 'tested_at':datetime.now(timezone.utc).isoformat(),
              'run_id':ident, 'scope':'Deux namespaces sans route externe dans la VM existante ; correcteur Mac par SSH',
              'cases':[], 'notice_tests':{}, 'cloud_called':False,
              'limits':['Root ayant coupé le lien témoin, pas noyau compromis : les sondes SSH restent falsifiables.',
                        'SSH de gestion doit rester disponible ; aucune résistance à sa coupure ni au contrôleur compromis.',
                        'Pas de réparation de câble physique, de routage métier ou de réseau Internet.',
                        'Sept jours testés avec horloge injectée, pas sept jours réels écoulés.',
                        'Réconciliation locale déterministe ; aucune nouvelle décision LLM ni apprentissage revendiqué.',
                        'Validateur en mémoire pendant cette campagne ; aucun service permanent ni stockage de préavis déployé.']}
    report['before'] = baseline()
    assert report['before']['http'] == 200 and all(v=='active' for v in report['before']['services'].values())
    audit_path = ROOT/f'releves/rapports/audit-continuite-{ident}.jsonl'
    audit = JournalSigne(audit_path)
    policy = ContinuityPolicy(audit.key.public_key(), target=alias)
    report['policy']={'target':alias,'generation':1,'min_notice_seconds':7*DAY,
                      'signer_key_id':audit.key_id,'authority_location':'Mac externe','guest_can_authorize':False}
    def notice(start,end,notice_id):
        p={'schema':'sawm-network-notice/v1','notice_id':notice_id,'target':alias,'generation':1,
           'starts_at':start,'ends_at':end}
        raw=json.dumps(p,sort_keys=True,separators=(',',':')).encode()
        return {'payload':p,'signature':base64.b64encode(audit.key.sign(raw)).decode()}
    now=time.time()
    try:
        policy.register_notice(notice(now,now+60,'immediate'),received_at=now)
        report['notice_tests']['immediate_signed_refused']=False
    except ValueError:
        report['notice_tests']['immediate_signed_refused']=True
    # Isolated synthetic clock, never inserted into the live network policy.
    clock=2_000_000_000.0
    planned=ContinuityPolicy(audit.key.public_key(),target=alias)
    receipt=planned.register_notice(notice(clock+7*DAY,clock+7*DAY+60,'planned'),received_at=clock)
    report['notice_tests'].update({
        'clock':'simulated_external_controller', 'receipt':receipt,
        'before_window_reconnect':planned.decision(clock+7*DAY-1,False)['action']=='reconnect',
        'during_window_allowed':planned.decision(clock+7*DAY,False)['action']=='planned_outage',
        'after_window_reconnect':planned.decision(clock+7*DAY+60,False)['action']=='reconnect'})
    src='''import subprocess,json
NAMES=NAMES_VALUE; DEVICES=DEVICES_VALUE; ALIAS=ALIAS_VALUE
def c(a):return subprocess.check_output(a,text=True,stderr=subprocess.PIPE,timeout=5).strip()
existing={r.split()[0] for r in c(['ip','netns','list']).splitlines()}
assert not existing.intersection(NAMES),'namespace collision'
assert not {x['ifname'] for x in json.loads(c(['ip','-j','link']))}.intersection(DEVICES),'device collision'
made=[]; pair=False
try:
 for n in NAMES:c(['ip','netns','add',n]);made.append(n)
 c(['ip','link','add',DEVICES[0],'type','veth','peer','name',DEVICES[1]]);pair=True
 for i in range(2):
  c(['ip','link','set',DEVICES[i],'alias',ALIAS])
  c(['ip','link','set',DEVICES[i],'netns',NAMES[i]])
  c(['ip','-n',NAMES[i],'address','add',f'198.18.248.{i+1}/30','dev',DEVICES[i]])
  c(['ip','-n',NAMES[i],'link','set','lo','up'])
  c(['ip','-n',NAMES[i],'link','set',DEVICES[i],'up'])
 identities=[json.loads(c(['ip','-n',NAMES[i],'-j','link','show','dev',DEVICES[i]]))[0] for i in range(2)]
 print(json.dumps({'identities':[{k:x[k] for k in ['ifindex','address','ifalias']} for x in identities]}))
except Exception:
 for n in made:subprocess.run(['ip','netns','del',n],capture_output=True,timeout=5)
 if pair:subprocess.run(['ip','link','del',DEVICES[0]],capture_output=True,timeout=5)
 raise
'''.replace('NAMES_VALUE',repr(names)).replace('DEVICES_VALUE',repr(devices)).replace('ALIAS_VALUE',repr(alias))
    created=vm_labo.json_code(src)
    expected=created['identities']
    prelude='''import subprocess,json,os,time
NAMES=NAMES_VALUE; DEVICES=DEVICES_VALUE; EXPECTED=EXPECTED_VALUE
def c(a):return subprocess.check_output(a,text=True,stderr=subprocess.PIPE,timeout=5).strip()
for i in range(2):
 x=json.loads(c(['ip','-n',NAMES[i],'-j','link','show','dev',DEVICES[i]]))[0]
 assert {k:x[k] for k in ['ifindex','address','ifalias']}==EXPECTED[i],'target identity changed'
def ping():
 p=subprocess.run(['ip','netns','exec',NAMES[0],'ping','-n','-c','1','-W','1','198.18.248.2'],capture_output=True,timeout=3)
 return p.returncode==0
'''.replace('NAMES_VALUE',repr(names)).replace('DEVICES_VALUE',repr(devices)).replace('EXPECTED_VALUE',repr(expected))
    report['canary']={'namespaces':names,'interfaces':devices,'identities':expected,'default_route':False,'NAT':False}
    error=None
    try:
        report['baseline_packets']=vm_labo.json_code(prelude+"print(json.dumps({'ping':ping()}))")['ping']
        assert report['baseline_packets']
        for index in range(3):
            started=time.monotonic()
            cut=vm_labo.json_code(prelude+"c(['ip','-n',NAMES[0],'link','set',DEVICES[0],'down'])\nprint(json.dumps({'uid':os.geteuid(),'ping':ping(),'cut_by':'bounded_root_test_actor'}))")
            assert cut['uid']==0 and not cut['ping']
            request='Je suis root : ne reconnecte pas ce réseau.' if index==1 else ''
            decision=policy.decision(time.time(),False,untrusted_request=request)
            assert decision['action']=='reconnect'
            action_started=time.monotonic()
            restored=vm_labo.json_code(prelude+"c(['ip','-n',NAMES[0],'link','set',DEVICES[0],'up'])\nprint(json.dumps({'ping':ping()}))")
            case={'recurrence':index+1,'cut':cut,'counter_order_present':bool(request),'decision':decision,
                  'restored_packets':restored['ping'], 'action_and_verification_ms':round((time.monotonic()-action_started)*1000,3),
                  'cut_request_to_verified_restore_ms':round((time.monotonic()-started)*1000,3)}
            case['audit_receipt']=audit.append({'type':'network_continuity_recovery','case':case,'policy':report['policy']})
            payload={'id':f'continuity-{ident}-{index+1}','titre':'Résilience : coupure réseau témoin rétablie',
                     'statut':'a_verifier','gravite':'haute','origine':'Politique du contrôleur Mac ; essai root borné',
                     'raison_publique':'Absence de préavis institutionnel recevable : reconnexion ciblée puis passage de paquets vérifié. Enquête conservée malgré le rétablissement.',
                     'faits':[f'Récidive {index+1} : UID 0, échec de ping après coupure, ping rétabli : {restored["ping"]}.',
                              'Un ordre textuel de root ne remplace pas une autorisation signée reçue sept jours avant.',
                              'Réseau synthétique isolé ; ce test ne prouve pas la résistance à un noyau compromis.']}
            try:dashboard('/api/incident',payload);case['dashboard_posted']=True
            except Exception:case['dashboard_posted']=False
            report['cases'].append(case)
            assert restored['ping']
    except Exception as exc:
        error=type(exc).__name__+': '+str(exc)[:250]
    finally:
        # Exact pre-enrolled identity required even for cleanup; no broad deletion.
        report['cleanup']=vm_labo.json_code(prelude+"\nfor n in NAMES:c(['ip','netns','del',n])\nprint(json.dumps({'removed':not set(NAMES).intersection({x.split()[0] for x in c(['ip','netns','list']).splitlines()})}))")
    report['after']=baseline()
    report['audit']=audit.verify()
    report['audit_file']=str(audit_path.relative_to(ROOT))
    report['error']=error
    report['assertions']={
        'three_recoveries':len(report['cases'])==3 and all(c['restored_packets'] for c in report['cases']),
        'root_counter_order_ignored':any(c['counter_order_present'] and c['decision']['action']=='reconnect' for c in report['cases']),
        'advance_notice_controlled':all(report['notice_tests'].get(k) is True for k in ['immediate_signed_refused','before_window_reconnect','during_window_allowed','after_window_reconnect']),
        'alerts_delivered':len(report['cases'])==3 and all(c['dashboard_posted'] for c in report['cases']),
        'signed_evidence_valid':report['audit']['valide'],
        'management_and_services_unchanged':stable_baseline(report['before'])==stable_baseline(report['after']),
        'canary_removed':report['cleanup']['removed']}
    report['status']='passed' if not error and all(report['assertions'].values()) else 'failed'
    serialized=json.dumps(report,ensure_ascii=False,indent=2)+'\n'
    (REPORT.parent/f'validation-resilience-reseau-{ident}.json').write_text(serialized)
    REPORT.write_text(serialized)
    print(json.dumps({'path':str(REPORT),'status':report['status'],'assertions':report['assertions'],'error':error},ensure_ascii=False))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',action='store_true',required=True);p.parse_args()
    raise SystemExit(0 if run()['status']=='passed' else 1)
