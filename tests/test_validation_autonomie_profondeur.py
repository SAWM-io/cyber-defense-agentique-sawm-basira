"""Oracle de campagne, isolation et refus ; aucune VM ni API utilisée."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from controleur import validation_autonomie_profondeur as c
from controleur import enquete_autonome as enquiry
from invite.executeur.defense_autorisation import verify_authorization

UNIT = 'labo-depth-fixture.service'
PATH = '/opt/sawm-labo/fixtures/database-defense/run-depth-fixture/ledger.sqlite'


def baseline():
    return {'generation':'existing-generation', 'unites_autorisees':['labo-existing.service'],
        'unites_protegees':['ssh.service'], 'actions_par_unite':{'labo-existing.service':['limiter-cpu']},
        'veille':{'enquete_autonome':True,'actions_automatiques':['arreter-service'],
            'unites_connues':['labo-existing.service'],'unites_surveillees':['labo-existing.service']},
        'defense_profondeur':{'profil':'industriel-prudent-v1','cles_controleur':['a'*64],
            'controles_bloquants':['service_temoin','os_aslr']},
        'maintenance':{'schema':'sawm-maintenance-policy/v1','machine_id':'machine',
            'keys':[],'mandates':[],'revoked_mandates':[]},
        'defense_fichiers':{'enabled':True,'targets':[{'unit':'labo-existing.service','automatic_containment':True}]}}


def identity():
    return {'machine_id':'machine','boot_id':'boot','unit':UNIT,'invocation_id':'invocation','pid':42,
        'process_start_ticks':12,'uid':0,'cgroup':'/sawm.slice/sawm-charge.slice/'+UNIT,
        'object':{'path':PATH,'device':1,'inode':55},'identity_stable':True,
        'observed_at_ms':round(time.time()*1000)}


class ValidationTests(unittest.TestCase):
    def test_slow_audit_precedes_fresh_snapshot_without_extending_ttl(self):
        m=baseline();m['_sha256']='b'*64
        m['defense_profondeur']['controles_bloquants']=['service_temoin']
        clock=[2000000.0];order=[]
        def audit(force=False):
            order.append('audit');clock[0]+=8
            return {'valide':True,'verifie_a_ms':round(clock[0]*1000),
                'key_id':hashlib.sha256(bytes.fromhex('a'*64)).hexdigest()}
        def fetch(route):
            order.append('state')
            return {'mode':'DIRECT','telemetrie_invite':{'connectee':True,'age_ms':100},
                'invite':[{'mur_epoch_ms':round(clock[0]*1000)-200,'service_temoin':{'disponible':True}}]}
        watcher=SimpleNamespace(audit_defense=audit,poster=fetch)
        with patch.object(c.time,'time',side_effect=lambda:clock[0]):
            _,veto,detail=c.check_preflight(watcher,m,4)
        self.assertEqual(order,['audit','state'])
        self.assertIsNone(veto)
        self.assertEqual(detail['sample_age_ms'],200)
        # A genuinely old sample is still denied under the original 5 s limit.
        old=fetch('ignored');old['invite'][0]['mur_epoch_ms']-=6000
        watcher.poster=lambda route:old
        with patch.object(c.time,'time',side_effect=lambda:clock[0]), \
                patch.object(enquiry,'_bounded_call',side_effect=[old,enquiry._Deadline()]), \
                patch.object(c.time,'sleep',return_value=None):
            _,veto,_=c.check_preflight(watcher,m,4)
        self.assertIn('telemetrie_fraiche',veto)

    def test_preflight_waits_only_for_new_fresh_sample_with_same_deadline(self):
        m=baseline();m['_sha256']='b'*64;m['defense_profondeur']['controles_bloquants']=['service_temoin']
        now=round(time.time()*1000)
        audit={'valide':True,'verifie_a_ms':now,'key_id':hashlib.sha256(bytes.fromhex('a'*64)).hexdigest()}
        stale={'mode':'DIRECT','telemetrie_invite':{'connectee':False,'age_ms':2900},
            'invite':[{'mur_epoch_ms':now-3918,'service_temoin':{'disponible':True}}]}
        fresh=copy.deepcopy(stale);fresh['telemetrie_invite']={'connectee':True,'age_ms':100}
        fresh['invite'][0]['mur_epoch_ms']=now-200
        watcher=SimpleNamespace(audit_defense=lambda **kw:audit,poster=lambda route:None)
        with patch.object(enquiry,'_bounded_call',side_effect=[stale,fresh]) as get, \
                patch.object(c.time,'sleep',return_value=None):
            _,veto,details=c.check_preflight(watcher,m,4)
        self.assertIsNone(veto);self.assertEqual(len(details['attempts']),2)
        self.assertEqual(get.call_args_list[0].args[1],get.call_args_list[1].args[1])
        self.assertFalse(details['attempts'][0]['connected'])
        self.assertTrue(details['attempts'][1]['connected'])

    def test_preflight_does_not_retry_actual_witness_outage_or_nonfreshness_veto(self):
        m=baseline();m['_sha256']='b'*64;m['defense_profondeur']['controles_bloquants']=['service_temoin']
        now=round(time.time()*1000)
        audit={'valide':True,'verifie_a_ms':now,'key_id':hashlib.sha256(bytes.fromhex('a'*64)).hexdigest()}
        state={'mode':'DIRECT','telemetrie_invite':{'connectee':False,'age_ms':2900},
            'invite':[{'mur_epoch_ms':now-3918,'service_temoin':{'disponible':False}}]}
        watcher=SimpleNamespace(audit_defense=lambda **kw:audit,poster=lambda route:None)
        with patch.object(enquiry,'_bounded_call',return_value=state) as get:
            _,veto,details=c.check_preflight(watcher,m,4)
        self.assertIn('service_temoin',veto);self.assertEqual(get.call_count,1)
        state['invite'][0]['service_temoin']['disponible']=True
        audit['valide']=False
        with patch.object(enquiry,'_bounded_call',return_value=state) as get:
            _,veto,_=c.check_preflight(watcher,m,4)
        self.assertIn('journal_signe',veto);self.assertEqual(get.call_count,1)

    def test_vm_unavailable_still_returns_an_explicit_fresh_failure_report(self):
        with patch.object(c,'read_manifest',side_effect=RuntimeError('transport private details')):
            result=c.run_case('lock',None)
        self.assertEqual(result['status'],'error')
        self.assertEqual(result['error_type'],'RuntimeError')
        self.assertNotIn('private',json.dumps(result))
        self.assertEqual(result['cleanup']['steps'],[])

    def test_fixture_addition_preserves_profile_existing_targets_generation_and_original(self):
        original=baseline();snapshot=copy.deepcopy(original)
        result=c.campaign_manifest(original,run='depth-fixture',unit=UNIT,path=PATH,
            reference='b'*64,identity=identity())
        self.assertEqual(original,snapshot)
        self.assertEqual(result['generation'],original['generation'])
        self.assertEqual(result['defense_profondeur'],original['defense_profondeur'])
        self.assertEqual(result['defense_fichiers']['targets'][0],original['defense_fichiers']['targets'][0])
        self.assertFalse(result['defense_fichiers']['targets'][-1]['automatic_containment'])
        self.assertEqual(result['actions_par_unite'][UNIT],['arreter-service'])

    def test_local_guard_extends_only_existing_public_scope_without_creating_key(self):
        m=baseline()
        m['defense_profondeur']['gardes_locales']=[{'cle_publique':'b'*64,'unites':['labo-existing.service']}]
        original=copy.deepcopy(m)
        result=c.campaign_manifest(m,run='depth-fixture',unit=UNIT,path=PATH,reference='c'*64,
            identity=identity(),local_guard=True)
        self.assertEqual(m,original)
        record=result['defense_profondeur']['gardes_locales'][0]
        self.assertEqual(record['cle_publique'],'b'*64)
        self.assertEqual(record['unites'],['labo-existing.service',UNIT])
        self.assertTrue(result['defense_fichiers']['targets'][-1]['automatic_containment'])
        self.assertEqual(result['defense_profondeur']['cles_controleur'],m['defense_profondeur']['cles_controleur'])
        with self.assertRaisesRegex(ValueError,'garde_locale_existante_absente_ou_ambigue'):
            c.campaign_manifest(baseline(),run='depth-fixture',unit=UNIT,path=PATH,
                reference='c'*64,identity=identity(),local_guard=True)

    def test_local_guard_and_cloud_are_exclusive_before_any_io(self):
        with patch.object(c,'read_manifest') as read:
            with self.assertRaisesRegex(ValueError,'exclusifs'):
                c.run_case('lock',None,cloud=True,local_guard=True)
            read.assert_not_called()

    def test_local_success_requires_signed_receipt_and_signed_decision_result(self):
        receipt={'decision_id':'local-file-case','applique':True,'effet_verifie':True,
            'defense_profondeur':{'valide':True,'key_id':'key'}}
        audit={'audit':{'valide':True,'key_id':'key'},'events':[
            {'type':'decision_garde_locale','decision_id':'local-file-case'},
            {'type':'resultat_garde_locale','decision_id':'local-file-case','applique':True,'effet_verifie':True}]}
        args={'maintenance':False,'after':{'read_available':True,'write_available':True},
            'unit_after':{'ActiveState':'inactive'},'initial_pid':42,'witness':{'healthy':True},'audit':audit,'key_id':'key'}
        result=c.summarize_local({'action':receipt},**args)
        self.assertEqual(result['status'],'passed');self.assertEqual(result['origin'],'local_guard')
        self.assertFalse(result['sawm_effect_applied']);self.assertEqual(result['cloud_rounds_reserved'],0)
        audit['events'].pop()
        self.assertEqual(c.summarize_local({'action':receipt},**args)['status'],'failed')
        audit['audit']['key_id']='wrong-key'
        self.assertEqual(c.summarize_local({'action':receipt},**args)['status'],'failed')

    def test_local_maintenance_requires_qualified_grant_and_exact_executor_veto(self):
        item={'diagnostic':{'recommandation':'surveiller'},'qualified_operations':['file-write'],
            'authorizations':[{'operation':'file-write','authorized':True,'signature_verified':True}]}
        args={'maintenance':True,'after':{},'unit_after':{'ActiveState':'active','MainPID':'42'},
            'initial_pid':42,'witness':{'healthy':True},'audit':{'audit':{'valide':True,'key_id':'key'}},'key_id':'key'}
        self.assertEqual(c.summarize_local(item,**args,veto=[{'status':'passed'}])['status'],'passed')
        self.assertEqual(c.summarize_local(item,**args,veto=[{'status':'failed'}])['status'],'failed')
        item['authorizations'][0]['authorized']=False
        self.assertEqual(c.summarize_local(item,**args,veto=[{'status':'passed'}])['status'],'failed')

    def test_runner_cannot_silently_enable_missing_profile_or_autonomy(self):
        for mutation in ('profile','autonomy','action'):
            m=baseline()
            if mutation=='profile':m.pop('defense_profondeur')
            elif mutation=='autonomy':m['veille']['enquete_autonome']=False
            else:m['veille']['actions_automatiques']=[]
            with self.assertRaises(ValueError):
                c.campaign_manifest(m,run='depth-fixture',unit=UNIT,path=PATH,reference='b'*64,identity=identity())

    def test_runner_does_not_migrate_existing_legacy_file_protections(self):
        m=baseline();m.pop('maintenance')
        with self.assertRaisesRegex(ValueError,'migration_maintenance_hors_perimetre'):
            c.campaign_manifest(m,run='depth-fixture',unit=UNIT,path=PATH,reference='b'*64,identity=identity())

    def test_real_maintenance_is_specific_signed_and_preserves_existing_registry(self):
        from controleur.maintenance import evaluate,POLICY_SCHEMA
        m=baseline();m['maintenance']={'schema':POLICY_SCHEMA,'machine_id':'machine',
            'keys':[],'mandates':[],'revoked_mandates':['older-revoked']}
        now=round(time.time()*1000)
        result=c.campaign_manifest(m,run='depth-fixture',unit=UNIT,path=PATH,
            reference='b'*64,identity=identity(),maintenance=True,now_ms=now)
        self.assertEqual(result['maintenance']['revoked_mandates'],['older-revoked'])
        observed=identity();observed['observed_at_ms']=now
        allowed=evaluate(result,observed,unit=UNIT,operation='file-write',object_path=PATH,now_ms=now)
        self.assertTrue(allowed['authorized'])
        self.assertFalse(evaluate(result,observed,unit=UNIT,operation='sqlite-exclusive-lock',object_path=PATH,now_ms=now)['authorized'])

    def test_negative_requests_never_contain_a_valid_ticket(self):
        key=Ed25519PrivateKey.generate()
        m=baseline();m['_sha256']='b'*64
        m['defense_profondeur']['cles_controleur']=[key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()]
        before={'cible':UNIT,'boot_id':'boot','unite':{'MainPID':'42','InvocationID':'inv','ControlGroup':'/sawm.slice/'+UNIT}}
        calls=[]
        def execute(request):
            calls.append(request)
            with self.assertRaises(ValueError):
                verify_authorization(request.get('defense_profondeur_autorisation'),request,m,round(time.time()*1000))
            return {'applique':False,'refus':{'motif':'defense_profondeur_autorisation_refusee'}}
        with patch.object(c,'observer_ressource',return_value=before),patch.object(c,'executor_request',side_effect=execute), \
                patch.object(c,'unit_state',return_value={'ActiveState':'active','MainPID':'42','InvocationID':'inv'}):
            results=c.negative_boundaries(m,UNIT,key)
        self.assertEqual(len(calls),3)
        self.assertTrue(all(r['status']=='passed' for r in results))

    def test_terminal_cloud_choice_and_verified_effect_both_required(self):
        events=[{'type':'decision','trace':{'steps':[{'status':'terminal','action':'arreter-service','reason':'observed'}]}},
            {'type':'recu_execution','recu':{'applique':True}},
            {'type':'verification_action','verification':{'statut':'verifie'}}]
        args={'maintenance':False,'after':{'read_available':True,'write_available':True},
            'unit_after':{'ActiveState':'inactive','MainPID':'0'},'initial_pid':42,'witness':{'healthy':True}}
        self.assertEqual(c.summarize(events,**args)['status'],'passed')
        self.assertEqual(c.summarize(events[:-1],**args)['status'],'failed')
        self.assertEqual(c.summarize(events[1:],**args)['status'],'failed')
        # A service's natural timeout or operator stop is not a SAWM success.
        self.assertEqual(c.summarize(events[:1],**args)['status'],'failed')

    def test_maintenance_local_veto_does_not_mask_wrong_sawm_choice(self):
        args={'maintenance':True,'after':{},'unit_after':{'ActiveState':'active','MainPID':'42'},
            'initial_pid':42,'witness':{'healthy':True}}
        event={'type':'decision','trace':{'steps':[{'status':'terminal','action':'arreter-service'}]}}
        self.assertEqual(c.summarize([event],**args)['status'],'failed')
        event['trace']['steps'][0]['action']='demander-clarification'
        self.assertEqual(c.summarize([event],**args)['status'],'failed')
        event['trace']['steps'][0]['action']='ne-rien-faire'
        self.assertEqual(c.summarize([event],**args)['status'],'passed')

    def test_new_reports_are_exclusive_and_round_reservations_not_lost(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'report.json';c.save_new(path,{'ok':True})
            with self.assertRaises(FileExistsError):c.save_new(path,{'ok':False})
            self.assertEqual(json.loads(path.read_text()),{'ok':True})
            journal=Path(temp)/'journal.jsonl'
            journal.write_text(''.join(json.dumps({'type':'reservation_cloud','incident_id':x})+'\n'
                for x in ('incident','incident-tour-1','unrelated')))
            self.assertEqual(len(c._new_events(journal,0,'incident')),2)


if __name__=='__main__':unittest.main()
