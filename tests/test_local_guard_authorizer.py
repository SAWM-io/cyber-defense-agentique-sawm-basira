"""Confinement local : vraies signatures/fichiers, sondes système simulées et bornées."""
from contextlib import ExitStack
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from controleur import defense_profondeur as depth
from invite.agent_labo import local_guard_authorizer as guard, defense_runtime as runtime
from invite.executeur import defense_autorisation as auth

NOW = 1_800_000_000_000
UNIT = 'labo-ledger-demo.service'


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()


class LocalGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.key=Ed25519PrivateKey.generate();self.key_path=self.root/'local.key'
        self.key_path.write_bytes(self.key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,
                                                        serialization.NoEncryption()))
        self.key_path.chmod(0o600)
        Path(str(self.key_path)+'.pub').write_bytes(bytes.fromhex(public(self.key)))
        self.audit_path=self.root/'proofs/audit.jsonl';self.audit_path.parent.mkdir(mode=0o700)
        self.fixture=self.root/'fixtures/ledger.txt';self.fixture.parent.mkdir()
        self.fixture.write_bytes(b'fixture altered')
        self.target={'unit':UNIT,'path':str(self.fixture),'kind':'file','automatic_containment':True,
                     'reference_sha256':hashlib.sha256(b'fixture original').hexdigest()}
        self.manifest={'generation':'g1','unites_autorisees':[UNIT],'unites_protegees':['ssh.service'],
            'veille':{'actions_automatiques':['arreter-service']},
            'defense_fichiers':{'enabled':True,'targets':[self.target]},
            'defense_profondeur':{'profil':auth.PROFILE,'controles_bloquants':[], 'cles_controleur':[],
                'gardes_locales':[{'cle_publique':public(self.key),'unites':[UNIT]}]}}
        self.manifest_path=self.root/'manifest.json';self.save()
        st=self.fixture.stat()
        self.obs={'unit':UNIT,'boot_id':'11111111-1111-1111-1111-111111111111','pid':123,'process_start_ticks':77,'uid':1001,
                  'cgroup':'/sawm.slice/'+UNIT,'invocation_id':'run-1','identity_stable':True,
                  'observed_at_ms':NOW,'object':{'device':st.st_dev,'inode':st.st_ino},'fd_on_object':True}
        self.sensor={'active':True,'events':[{'operation_succeeded':True,'boot_id':'11111111-1111-1111-1111-111111111111','pid':123,'euid':1001,
            'process':{'identity_stable':True,'start_ticks':77,'cgroup':self.obs['cgroup']},
            'inode':st.st_ino,'device':(os.major(st.st_dev)<<20)|os.minor(st.st_dev),
            'received_at_ms':NOW,'capture_latency_ms':0}]}
        self.observe=Mock(return_value=self.obs)
        self.maintenance=Mock(return_value={'authorized':False,'reason':'aucun_mandat_pour_operation'})
        original_trusted=guard.trusted_path
        self.stack.enter_context(patch.object(guard,'trusted_path',side_effect=lambda p,**kw:
            original_trusted(p,owner=os.getuid(),root=self.root,**kw)))
        self.stack.enter_context(patch.object(runtime,'trusted_manifest',side_effect=self.read_manifest))
        self.stack.enter_context(patch.object(runtime,'BASE',self.root))
        self.stack.enter_context(patch.object(guard,'observer_os',self.observe))
        self.stack.enter_context(patch.object(guard,'maintenance',self.maintenance))
        self.stack.enter_context(patch.object(guard.posture_securite,'snapshot',return_value={'schema':'sawm-posture-os/v1','observed_ms':NOW,'controls':[]}))
        self.stack.enter_context(patch.object(guard.time,'time',return_value=NOW/1000))
        self.authorizer=guard.LocalGuardAuthorizer(key_path=self.key_path,audit_path=self.audit_path,manifest_path=self.manifest_path)
        self.request={'decision_id':'local-file-123','action':'arreter-service','cible':UNIT,'generation':'g1',
             'manifest_sha256':self.read_manifest()['_sha256'],
             'expected_identity':{'cible':UNIT,'boot_id':'11111111-1111-1111-1111-111111111111','MainPID':'123','InvocationID':'run-1','ControlGroup':self.obs['cgroup']}}
        self.initial={'path':str(self.fixture)}

    def save(self):
        self.manifest_path.write_text(json.dumps(self.manifest));self.manifest_path.chmod(0o600)

    def read_manifest(self,*args):
        raw=self.manifest_path.read_bytes();m=json.loads(raw);m['_sha256']=hashlib.sha256(raw).hexdigest();return m

    def authorize(self):
        return self.authorizer.authorize(self.request,self.initial,self.sensor)

    def test_real_file_change_and_attributed_write_sign_journal_then_bound_ticket(self):
        envelope=self.authorize()
        self.assertTrue(auth.verify_authorization(envelope,self.request,self.read_manifest(),NOW))
        verified=self.authorizer.journal.verify();self.assertEqual(verified['seq'],1)
        event=json.loads(self.audit_path.read_text())['evenement']
        self.assertEqual(event['origine'],'garde_locale')
        self.assertEqual(event['raison'],'infraction_locale_attribuee')
        self.assertEqual(event['decision_id'],self.request['decision_id'])
        self.assertEqual(event['identite'],self.request['expected_identity'])
        self.authorizer.record_result(self.request,{'applique':True})
        self.assertEqual(self.authorizer.journal.verify()['seq'],2)
        self.assertTrue(any(p['kind']=='integrity' for p in event['preuves']))

    def test_initial_diagnostic_cannot_override_fresh_os_reinspection(self):
        self.initial['diagnostic']={'recommandation':'contenir_sous_mandat'}
        self.fixture.write_bytes(b'fixture original')
        with self.assertRaisesRegex(ValueError,'preuve_ou_identite'): self.authorize()
        self.assertEqual(self.authorizer.journal.verify()['seq'],0)

    def test_authorized_maintenance_has_priority_over_file_guard(self):
        self.maintenance.return_value={'authorized':True,'reason':'mandat_signe_valide','mandate_id':'permit-1','principal':'operator-1'}
        with self.assertRaisesRegex(ValueError,'preuve_ou_identite'):self.authorize()
        self.assertEqual(self.authorizer.journal.verify()['seq'],0)

    def test_unattributed_stale_and_changed_process_proofs_fail(self):
        for mutation in ('write_missing','old_event','different_process','old_observation'):
            with self.subTest(case=mutation):
                sensor,obs=copy.deepcopy(self.sensor),copy.deepcopy(self.obs)
                if mutation=='write_missing':sensor['events']=[]
                if mutation=='old_event':sensor['events'][0]['received_at_ms']=NOW-1501
                if mutation=='different_process':obs['invocation_id']='restarted'
                if mutation=='old_observation':obs['observed_at_ms']=NOW-1501
                self.observe.return_value=obs
                with self.assertRaises(ValueError):self.authorizer.authorize(self.request,self.initial,sensor)
        self.assertEqual(self.authorizer.journal.verify()['seq'],0)

    def test_corrupted_audit_does_not_issue_authorization(self):
        self.authorize()
        self.audit_path.write_bytes(self.audit_path.read_bytes().replace(b'infraction_locale',b'alteration_locale'))
        with self.assertRaises(Exception):self.authorize()

    def test_rotated_key_manifest_and_extra_required_control_fail_closed(self):
        self.manifest['generation']='g2';self.save()
        with self.assertRaisesRegex(ValueError,'manifeste_change'):self.authorize()
        self.manifest['generation']='g1';self.manifest['defense_profondeur']['controles_bloquants']=['capteur_lsm'];self.save()
        self.request['manifest_sha256']=self.read_manifest()['_sha256']
        with self.assertRaisesRegex(ValueError,'capteur_lsm'):self.authorize()
        self.manifest['defense_profondeur']['controles_bloquants']=[];self.save()
        self.request['manifest_sha256']=self.read_manifest()['_sha256']
        self.key_path.write_bytes(bytes(range(32)))
        with self.assertRaisesRegex(ValueError,'cle_changee'):self.authorize()

    def test_local_key_cannot_sign_other_action_target_or_controller_decision(self):
        for field,value in (('action','limiter-cpu'),('cible','labo-other.service'),('decision_id','cloud-decision')):
            request={**self.request,field:value}
            envelope=auth.sign_authorization(self.key,request,NOW)
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'hors_portee'):
                auth.verify_authorization(envelope,request,self.read_manifest(),NOW)
        request={k:v for k,v in self.request.items() if k!='expected_identity'}
        with self.assertRaisesRegex(ValueError,'hors_portee'):
            auth.verify_authorization(auth.sign_authorization(self.key,request,NOW),request,self.read_manifest(),NOW)

    def test_expired_ticket_key_reuse_or_revoked_scope_rejected(self):
        envelope=self.authorize()
        with self.assertRaises(ValueError):auth.verify_authorization(envelope,self.request,self.read_manifest(),NOW+5000)
        self.manifest['defense_profondeur']['cles_controleur']=[public(self.key)]
        self.save()
        self.assertIsNotNone(depth.policy(self.read_manifest())[2])
        with self.assertRaisesRegex(ValueError,'cle_partagee'):auth.local_guard_keys(self.manifest['defense_profondeur'])
        self.manifest['defense_profondeur']['cles_controleur']=[]
        self.manifest['defense_profondeur']['gardes_locales']=[];self.save()
        self.request['manifest_sha256']=self.read_manifest()['_sha256']
        with self.assertRaisesRegex(ValueError,'non_enrolee'):self.authorize()

    def test_local_enrollment_is_not_a_controller_authority(self):
        audit={**self.authorizer.journal.verify(),'verifie_a_ms':NOW}
        state={'mode':'DIRECT','telemetrie_invite':{'connectee':True,'age_ms':0},'invite':[{'mur_epoch_ms':NOW}]}
        self.assertIsNone(depth.refuse(self.read_manifest(),state,audit=audit,now_ms=NOW,authority_role='garde_locale'))
        self.assertIn('autorite_controleur',depth.refuse(self.read_manifest(),state,audit=audit,now_ms=NOW))

    def test_missing_key_is_never_created_and_symlinks_or_weak_modes_fail(self):
        self.key_path.unlink()
        with self.assertRaises(FileNotFoundError):
            guard.LocalGuardAuthorizer(key_path=self.key_path,audit_path=self.audit_path,manifest_path=self.manifest_path)
        self.assertFalse(self.key_path.exists())
        self.key_path.symlink_to(Path(str(self.key_path)+'.pub'))
        with self.assertRaises(ValueError):guard.trusted_path(self.key_path,private=True)
        self.key_path.unlink();self.key_path.write_bytes(bytes(32));self.key_path.chmod(0o644)
        with self.assertRaises(ValueError):guard.trusted_path(self.key_path,private=True)

    def test_proof_expiring_during_fsync_or_policy_change_cannot_be_signed(self):
        append = self.authorizer.journal.append
        clock = [NOW]
        def delayed(event):
            result=append(event);clock[0]=NOW+1501;return result
        with patch.object(guard.time,'time',side_effect=lambda:clock[0]/1000), \
                patch.object(self.authorizer.journal,'append',side_effect=delayed):
            with self.assertRaisesRegex(ValueError,'expiree_avant_signature'):self.authorize()
        def changed(event):
            result=append(event);self.manifest['generation']='g2';self.save();return result
        with patch.object(self.authorizer.journal,'append',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'expiree_avant_signature'):self.authorize()

    def test_stopped_protected_or_disabled_guard_never_gains_authority(self):
        for change in ('disabled','protected','not_allowed','automatic_false'):
            m=self.read_manifest()
            if change=='disabled':m['defense_fichiers']['enabled']=False
            if change=='protected':m['unites_protegees'].append(UNIT)
            if change=='not_allowed':m['unites_autorisees']=[]
            if change=='automatic_false':m['defense_fichiers']['targets'][0]['automatic_containment']=False
            envelope=auth.sign_authorization(self.key,self.request,NOW)
            with self.subTest(change=change),self.assertRaisesRegex(ValueError,'hors_portee'):
                auth.verify_authorization(envelope,self.request,m,NOW)

    def test_runtime_without_authorizer_refuses_and_record_failure_is_visible(self):
        m=self.read_manifest()
        item=runtime.inspect_target(m,self.target,self.sensor,self.observe,self.maintenance,guard.diagnostiquer)
        execute=Mock(return_value={'applique':True})
        result=runtime.contain(m,item,execute)
        self.assertFalse(result['applique']);execute.assert_not_called()
        result=runtime.contain(m,item,execute,authorize=lambda request,item:self.authorizer.authorize(request,item,self.sensor),
                               record_result=Mock(side_effect=OSError('disk full')))
        self.assertTrue(result['applique']);self.assertEqual(result['audit_local_resultat'],'ecriture_incomplete_a_examiner')
        request=execute.call_args.args[0]
        self.assertTrue(auth.verify_authorization(request['defense_profondeur_autorisation'],request,m,NOW))


if __name__=='__main__':unittest.main()
