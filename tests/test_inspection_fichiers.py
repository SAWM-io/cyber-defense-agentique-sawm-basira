"""Raccordement aux fichiers : aucun appel VM/Cloud dans ces tests."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from controleur import inspection_fichiers as f, veille, validation, verification_action
UNIT='labo-dossier.service';PATH='/opt/sawm-labo/fixtures/dossier.sqlite'


def fixtures():
    target={'unit':UNIT,'path':PATH,'kind':'sqlite','reference_sha256':'a'*64,'automatic_containment':False}
    manifest={'generation':'g-test','_sha256':'b'*64,'unites_autorisees':[UNIT],
              'defense_fichiers':{'enabled':True,'targets':[target]},
              'veille':{'unites_connues':[],'sources_connues':[],'reseau_hors_baseline_autorise':False,
                        'actions_automatiques':['arreter-service']}}
    identity={'unit':UNIT,'machine_id':'machine-1','boot_id':'12345678-1234-1234-1234-123456789abc',
              'invocation_id':'c'*32,'pid':42,'process_start_ticks':333,'uid':1000,
              'cgroup':'/sawm.slice/'+UNIT,'object':{'path':PATH,'device':12,'inode':13}}
    absent={'authorized':False,'reason':'aucun_mandat_pour_operation'}
    inspection={'unit':UNIT,'path':PATH,'qualified_operations':['file-write'],
                'integrity':{'reference_sha256':'a'*64,'current_sha256':'d'*64,'sample_stable':True}}
    result={'schema':'sawm-server-inspection/v1','action':'inspecter-base','unit':UNIT,
            'status':'observed','source':'vm_controller_reinspection','observation_valid':True,
            'identity_stable':True,'policy_verified':True,'generation':'g-test','manifest_sha256':'b'*64,
            'observed_epoch_ms':int(time.time()*1000),'before':copy.deepcopy(identity),'after':identity,
            'object_path':PATH,'evidence':{'target':target,'inspection':inspection,
            'policy_receipts':{'sqlite-exclusive-lock':copy.deepcopy(absent),'file-write':copy.deepcopy(absent)}}}
    incident={'id':'inc-file','genre':'diagnostic_defense_fichiers','unite':UNIT,'analysable':True,
              'survenu_observe_ms':int(time.time()*1000),'faits':[{'objet':PATH,'maintenance':{'authorized':True}}]}
    return manifest,result,incident


def grant():
    return {'authorized':True,'reason':'mandat_signe_valide','signature_verified':True,
            'principal':'institution:cto','mandate_id':'maintenance-1','expires_at_ms':int(time.time()*1000)+60000}


class FileInspectionTests(unittest.TestCase):
    def test_transport_binds_current_manifest_and_exact_target_and_no_provider(self):
        manifest,result,_=fixtures();transport=Mock(return_value=result)
        self.assertEqual(f.inspecter_base(UNIT,manifest,object_path=PATH,json_code_fn=transport),result)
        source=transport.call_args.args[0]
        for fragment in ('trusted_manifest()',"expected_sha='"+'b'*64,"generation='g-test'",'inspect_target(', 'observer_os(', 'evaluate('):
            self.assertIn(fragment,source)
        self.assertNotIn('PontMemoire',source)
        self.assertEqual(transport.call_args.kwargs,{'timeout':20})

    def test_unconfigured_database_never_calls_vm_or_fabricates_observation(self):
        manifest,result,_=fixtures();manifest.pop('defense_fichiers');transport=Mock()
        result=f.inspecter_base(UNIT,manifest,json_code_fn=transport)
        self.assertFalse(result['observation_valid']);self.assertEqual(result['status'],'unavailable')
        transport.assert_not_called()

    def test_exact_stable_fresh_target_required_not_telemetry_grant(self):
        manifest,result,_=fixtures()
        self.assertTrue(f.valide(result,manifest,UNIT))
        for changes in ({'source':'telemetry'},{'manifest_sha256':'e'*64},{'generation':'other'},
                        {'observed_epoch_ms':int(time.time()*1000)-2000},{'object_path':PATH+'-wal'},
                        {'before':{**result['before'],'pid':True}}):
            self.assertFalse(f.valide({**result,**changes},manifest,UNIT),changes)
        changed=copy.deepcopy(result);changed['evidence']['target']['reference_sha256']='e'*64
        self.assertFalse(f.valide(changed,manifest,UNIT))

    def test_cloud_policy_requires_verified_receipts_and_separates_writes_and_locks(self):
        manifest,result,_=fixtures()
        policy=f.politique_database(result,manifest,UNIT)
        self.assertFalse(policy['write_authorized']);self.assertTrue(policy['write_requires_authorization'])
        self.assertFalse(policy['exclusive_lock_authorized']);self.assertTrue(policy['integrity_required'])
        result['evidence']['policy_receipts']['file-write']=grant()
        policy=f.politique_database(result,manifest,UNIT)
        self.assertTrue(policy['write_authorized']);self.assertFalse(policy['integrity_required'])
        self.assertFalse(policy['exclusive_lock_authorized']);self.assertTrue(policy['availability_required'])
        result['evidence']['policy_receipts']['file-write']={'authorized':True}
        self.assertIsNone(f.politique_database(result,manifest,UNIT))

    def test_current_forged_unknown_or_authorized_receipt_cannot_authorize_stop(self):
        manifest,result,_=fixtures();reference=copy.deepcopy(result)
        self.assertIsNone(f.refus_action(result,reference,manifest,UNIT,object_path=PATH))
        for receipt,expected in [({'authorized':False,'reason':'signature_invalide'},'autorisation_operation_fichier_non_etablie'),
                                 (grant(),'maintenance_signee_preservee')]:
            result['evidence']['policy_receipts']['file-write']=receipt
            self.assertEqual(f.refus_action(result,reference,manifest,UNIT),expected)

    def test_process_restart_and_file_replacement_prevent_old_decision(self):
        manifest,result,_=fixtures();reference=copy.deepcopy(result)
        for field,value in [('pid',43),('process_start_ticks',334),('boot_id','other'),('object',{'path':PATH,'device':12,'inode':14})]:
            changed=copy.deepcopy(result);changed['before'][field]=value;changed['after'][field]=value
            self.assertEqual(f.refus_action(changed,reference,manifest,UNIT),'identite_fichier_ou_processus_changee')

    def test_multiple_operations_require_all_permissions_for_preservation(self):
        manifest,result,_=fixtures();reference=copy.deepcopy(result)
        result['evidence']['inspection']['qualified_operations']=['file-write','sqlite-exclusive-lock']
        result['evidence']['policy_receipts']['file-write']=grant()
        self.assertIsNone(f.refus_action(result,reference,manifest,UNIT))
        result['evidence']['policy_receipts']['sqlite-exclusive-lock']=grant()
        self.assertEqual(f.refus_action(result,reference,manifest,UNIT),'maintenance_signee_preservee')


class VeilleFilePipelineTests(unittest.TestCase):
    def test_action_authorization_no_longer_requires_unrelated_socket(self):
        manifest,result,incident=fixtures()
        decision=types.SimpleNamespace(executable=True,proposition=types.SimpleNamespace(action='arreter-service',cible=UNIT))
        state={'mode':'DIRECT','telemetrie_invite':{'connectee':True,'age_ms':5},'invite':[{'connexions':[]}]}
        self.assertIsNone(veille.autoriser_action(decision,incident,manifest,manifest,state,True,150,
                          observation_fichiers=result,reference_fichiers=copy.deepcopy(result)))
        self.assertEqual(veille.autoriser_action(decision,incident,manifest,manifest,state,True,124,
                          observation_fichiers=result,reference_fichiers=result),'budget_temps_insuffisant_pour_action_et_retour')
        decision.proposition.action='geler-transfert';manifest['veille']['actions_automatiques'].append('geler-transfert')
        self.assertEqual(veille.autoriser_action(decision,incident,manifest,manifest,state,True,150,
                          observation_fichiers=result,reference_fichiers=result),'action_non_qualifiee_pour_incident_fichier')

    def test_cloud_receives_fresh_policy_and_reinspection_before_execute(self):
        manifest,result,incident=fixtures()
        state={'mode':'DIRECT','telemetrie_invite':{'connectee':True,'age_ms':5},'invite':[{'connexions':[]}]}
        d=types.SimpleNamespace(executable=True,proposition=types.SimpleNamespace(action='arreter-service',cible=UNIT,
            justification='Écriture attribuée sans mandat.',confiance=.7,inconnues=[]),decision_id='decision-file',refus=None,resume=lambda:{'action':'arreter-service'})
        identity=result['after'];before={'cible':UNIT,'boot_id':identity['boot_id'],
            'unite':{'MainPID':str(identity['pid']),'InvocationID':identity['invocation_id'],'ControlGroup':identity['cgroup']}}
        bridge=Mock(espace='test-space',entite='test-entity')
        bridge.deposer.return_value={'accepted':True}
        with tempfile.TemporaryDirectory() as directory:
            journal=veille.Journal(Path(directory).resolve())
            try:
                watch=veille.Veille(manifest,journal,cloud=True,appliquer=True,poster=lambda *args:state,
                                   lire_manifest=lambda:manifest,fin=time.monotonic()+300)
                with patch.object(watch,'inspecter_autorise',side_effect=[copy.deepcopy(result),copy.deepcopy(result)]) as inspect, \
                     patch('connecteur.pont_memoire.PontMemoire',return_value=bridge), \
                     patch.object(validation,'decision_cloud',return_value=(d,{})) as cloud, \
                     patch.object(validation,'execute',return_value={'applique':True}) as execute, \
                     patch.object(verification_action,'observer_ressource',return_value=before), \
                     patch.object(verification_action,'verifier_action',return_value={'statut':'verifie','effet':'arret_unite_verifie','temoin':'disponible'}):
                    watch.analyser_cloud(incident)
                policy=cloud.call_args.kwargs['politique_locale']['database_policy']
                self.assertFalse(policy['write_authorized'])  # fake telemetry grant was ignored
                self.assertTrue(policy['write_requires_authorization'])
                self.assertEqual(inspect.call_count,2)
                execute.assert_called_once()
                events=[json.loads(line)['type'] for line in journal.path.read_text().splitlines()]
                self.assertLess(events.index('inspection_fichiers_avant_action'),events.index('avant_execution'))
            finally:journal.close()


if __name__=='__main__':unittest.main()
