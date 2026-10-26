"""Mandat court du contrôleur : crypto réelle, exécution simulée, aucun OS externe."""
from contextlib import ExitStack
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from invite.executeur import defense_autorisation as a

NOW = 1_800_000_000_000


def public_hex(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.key=Ed25519PrivateKey.generate()
        self.request={'decision_id':'decision-1','action':'arreter-service','cible':'labo-example.service','manifest_sha256':'a'*64}
        self.manifest={'_sha256':'a'*64,'defense_profondeur':{
            'profil':a.PROFILE,'controles_bloquants':[], 'cles_controleur':[public_hex(self.key)]}}
        self.envelope=a.sign_authorization(self.key,self.request,NOW)

    def verify(self,envelope=None,request=None,manifest=None,now=NOW):
        return a.verify_authorization(self.envelope if envelope is None else envelope,
            self.request if request is None else request,self.manifest if manifest is None else manifest,now)

    def resign(self,payload):
        envelope=copy.deepcopy(self.envelope);envelope['payload']=payload
        envelope['signature']=self.key.sign(a.canonical(payload)).hex();return envelope

    def test_exact_signature_roundtrip_and_ascii_canonical_form(self):
        self.assertTrue(self.verify())
        self.assertEqual(self.envelope['key_id'],hashlib.sha256(bytes.fromhex(public_hex(self.key))).hexdigest())
        self.assertEqual(self.envelope['payload']['expires_ms']-NOW,5000)
        request={**self.request,'cible':'/opt/sawm-labo/fixtures/pièce'}
        envelope=a.sign_authorization(self.key,request,NOW)
        self.assertIn(b'\\u00e8',a.canonical(envelope['payload']))
        self.assertTrue(self.verify(envelope=envelope,request=request))
        self.assertNotIn('defense_profondeur_autorisation',self.request)

    def test_each_bound_field_cannot_be_substituted(self):
        for field,value in (('decision_id','other'),('action','geler-transfert'),('cible','labo-neighbor.service'),('manifest_sha256','b'*64)):
            with self.subTest(field=field),self.assertRaises(ValueError):
                self.verify(request={**self.request,field:value})
            altered=copy.deepcopy(self.envelope);altered['payload'][field]=value
            with self.subTest(payload=field),self.assertRaises(ValueError):self.verify(envelope=altered)

    def test_signature_and_unenrolled_key_cannot_authorize(self):
        altered=copy.deepcopy(self.envelope);altered['signature']='0'*128
        with self.assertRaises(ValueError):self.verify(envelope=altered)
        other=a.sign_authorization(Ed25519PrivateKey.generate(),self.request,NOW)
        with self.assertRaises(ValueError):self.verify(envelope=other)
        other['key_id']=self.envelope['key_id']
        with self.assertRaises(ValueError):self.verify(envelope=other)

    def test_missing_or_extra_envelope_and_payload_fields_rejected(self):
        cases=[{}, {'payload':self.envelope['payload']}, {**self.envelope,'public_key':public_hex(self.key)}]
        for field in a.PAYLOAD_FIELDS:
            payload=copy.deepcopy(self.envelope['payload']);payload.pop(field)
            cases.append(self.resign(payload))
        cases.append(self.resign({**self.envelope['payload'],'approved':True}))
        for envelope in cases:
            with self.subTest(envelope_fields=list(envelope)),self.assertRaises(ValueError):self.verify(envelope=envelope)
        with self.assertRaises(ValueError):self.verify(envelope=self.resign({**self.envelope['payload'],'schema':'other'}))

    def test_interval_is_inclusive_at_issue_exclusive_at_expiry(self):
        self.assertTrue(self.verify(now=NOW));self.assertTrue(self.verify(now=NOW+4999))
        for now in (NOW-1,NOW+5000,NOW+5001):
            with self.subTest(now=now),self.assertRaises(ValueError):self.verify(now=now)
        for issued,expires in ((NOW,NOW),(NOW,NOW-1),(NOW,NOW+5001),(NOW+1,NOW+4999)):
            envelope=self.resign({**self.envelope['payload'],'issued_ms':issued,'expires_ms':expires})
            with self.subTest(interval=(issued,expires)),self.assertRaises(ValueError):self.verify(envelope=envelope)

    def test_time_types_nonfinite_bool_and_overflow_rejected(self):
        for bad in (True,False,1.5,float('nan'),float('inf'),-1,2**63,'now',None):
            with self.subTest(now=bad),self.assertRaises(ValueError):self.verify(now=bad)
            with self.subTest(sign=bad),self.assertRaises(ValueError):a.sign_authorization(self.key,self.request,bad)
            for field in ('issued_ms','expires_ms'):
                envelope=copy.deepcopy(self.envelope);envelope['payload'][field]=bad
                with self.subTest(field=field,value=bad),self.assertRaises(ValueError):self.verify(envelope=envelope)

    def test_profile_and_keys_are_local_administrator_inputs_only(self):
        original=self.manifest['defense_profondeur']
        profiles=[None,{}, {**original,'profil':'unknown'}, {**original,'extra':True},
                  {**original,'cles_controleur':[]},{**original,'cles_controleur':['g'*64]},
                  {**original,'cles_controleur':[public_hex(self.key)]*2},
                  {**original,'cles_controleur':'not-a-list'},
                  {'profil':a.PROFILE,'controles_bloquants':[]}]
        for profile in profiles:
            with self.subTest(profile=profile),self.assertRaises(ValueError):
                self.verify(manifest={**self.manifest,'defense_profondeur':profile})
        with self.assertRaises(ValueError):self.verify(manifest={'_sha256':'a'*64})
        with self.assertRaises(ValueError):self.verify(manifest={**self.manifest,'_sha256':'c'*64})

    def test_malformed_values_are_rejected_before_signing(self):
        for field,value in (('decision_id',''),('action',True),('cible',None),('cible','bad\npath'),('manifest_sha256','abc')):
            with self.subTest(field=field),self.assertRaises(ValueError):
                a.sign_authorization(self.key,{**self.request,field:value},NOW)

    def test_identity_removal_substitution_and_legacy_ticket_are_rejected(self):
        identity={'cible':'labo-example.service','boot_id':'boot-1','InvocationID':'invocation-1',
                  'MainPID':'123','ControlGroup':'/sawm-charge.slice/labo-example.service'}
        request={**self.request,'expected_identity':identity}
        envelope=a.sign_authorization(self.key,request,NOW)
        self.assertTrue(self.verify(envelope=envelope,request=request))
        self.assertEqual(envelope['payload']['identity_sha256'],hashlib.sha256(a.canonical(identity)).hexdigest())
        for changed in (self.request,{**request,'expected_identity':None},
                        {**request,'expected_identity':{**identity,'MainPID':'124'}},
                        {**request,'expected_identity':{**identity,'boot_id':'boot-2'}}):
            with self.subTest(request=changed),self.assertRaises(ValueError):
                self.verify(envelope=envelope,request=changed)
        legacy=copy.deepcopy(envelope);legacy['payload'].pop('identity_sha256')
        legacy['signature']=self.key.sign(a.canonical(legacy['payload'])).hex()
        with self.assertRaises(ValueError):self.verify(envelope=legacy,request=request)
        # L'absence est liée explicitement : lui ajouter ensuite une identité ne passe pas.
        self.assertEqual(self.envelope['payload']['identity_sha256'],hashlib.sha256(b'null').hexdigest())
        with self.assertRaises(ValueError):self.verify(request=request)

    def test_identity_json_and_size_are_bounded(self):
        cyclic=[];cyclic.append(cyclic)
        for invalid in ({'x':'é'*3000},{'x':'a'*4096}, {'x':float('nan')}, {'x':float('inf')},
                        {1:'not-a-string-key'}, {'x':object()}, {'x':(1,2)}, cyclic):
            request={**self.request,'expected_identity':invalid}
            with self.subTest(kind=type(invalid).__name__),self.assertRaises(ValueError):
                a.sign_authorization(self.key,request,NOW)
            with self.assertRaises(ValueError):self.verify(request=request)


class ExecutorDepthTests(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('executeur_depth_test',Path(__file__).resolve().parents[1]/'invite/executeur/executeur.py')
        self.ex=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.ex)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.key=Ed25519PrivateKey.generate()
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        for key,value in {'RACINE':self.root,'MANIFESTE':self.root/'manifeste.json','RECUS':self.root/'recus.jsonl',
                          'ROOT_UID':os.geteuid()}.items():self.stack.enter_context(patch.object(self.ex,key,value))
        self.stack.enter_context(patch.object(self.ex.time,'time',return_value=NOW/1000))
        self.manifest={'generation':'g1','unites_autorisees':['labo-example.service'],
            'defense_profondeur':{'profil':a.PROFILE,'controles_bloquants':[], 'cles_controleur':[public_hex(self.key)]}}
        self.save()

    def save(self):
        self.ex.MANIFESTE.write_text(json.dumps(self.manifest));self.ex.MANIFESTE.chmod(0o600)

    def request(self, action='arreter-service', signed=True, identifier='decision-1'):
        req={'decision_id':identifier,'action':action,'cible':'labo-example.service','generation':'g1',
             'manifest_sha256':hashlib.sha256(self.ex.MANIFESTE.read_bytes()).hexdigest()}
        if signed:req['defense_profondeur_autorisation']=a.sign_authorization(self.key,req,NOW)
        return req

    def test_direct_mutation_without_controller_authorization_is_refused(self):
        for action in set(self.ex.ACTIONS)-self.ex._ACTIONS_SANS_MUTATION:
            mutation=Mock(return_value={})
            with self.subTest(action=action),patch.dict(self.ex.ACTIONS,{action:mutation}):
                receipt=self.ex.appliquer(self.request(action,signed=False,identifier=action))
            self.assertEqual(receipt['refus']['motif'],'defense_profondeur_autorisation_refusee')
            self.assertFalse(receipt['applique']);mutation.assert_not_called()
        self.assertFalse(self.ex.RECUS.exists())

    def test_valid_controller_authorization_is_applied_once_and_recorded(self):
        mutation=Mock(return_value={'effet_verifie':True});req=self.request()
        with patch.dict(self.ex.ACTIONS,{'arreter-service':mutation}):
            first=self.ex.appliquer(req);second=self.ex.appliquer(req)
        self.assertTrue(first['applique']);self.assertTrue(second['rejeu']);mutation.assert_called_once()
        self.assertTrue(first['defense_profondeur']['valide'])
        self.assertEqual(first['defense_profondeur']['key_id'],req['defense_profondeur_autorisation']['key_id'])

    def test_existing_maintenance_veto_still_precedes_authorization(self):
        mutation=Mock()
        with patch.dict(self.ex.ACTIONS,{'arreter-service':mutation}), \
             patch.object(self.ex,'verifier_maintenance',return_value={'veto':True}), \
             patch.object(self.ex,'verifier_defense_profondeur') as gate:
            receipt=self.ex.appliquer(self.request(signed=False))
        self.assertEqual(receipt['refus']['motif'],'maintenance_signee_preservee')
        mutation.assert_not_called();gate.assert_not_called()

    def test_readonly_and_legacy_profile_absent_keep_existing_behavior(self):
        for action in self.ex._ACTIONS_SANS_MUTATION:
            with patch.dict(self.ex.ACTIONS,{action:Mock(return_value={})}):
                self.assertTrue(self.ex.appliquer(self.request(action,signed=False,identifier=action))['applique'])
        self.manifest.pop('defense_profondeur');self.save()
        mutation=Mock(return_value={})
        with patch.dict(self.ex.ACTIONS,{'arreter-service':mutation}):
            self.assertTrue(self.ex.appliquer(self.request(signed=False,identifier='legacy'))['applique'])
        mutation.assert_called_once()

    def test_signed_ticket_cannot_bypass_local_action_restriction(self):
        self.manifest['actions_autorisees']=['ne-rien-faire'];self.save();mutation=Mock()
        with patch.dict(self.ex.ACTIONS,{'arreter-service':mutation}):receipt=self.ex.appliquer(self.request())
        self.assertEqual(receipt['refus']['motif'],'action_hors_manifeste');mutation.assert_not_called()

    def test_authorization_expiring_during_durable_write_does_not_mutate(self):
        req=self.request();real_journal=self.ex._journal;clock=[NOW/1000];mutation=Mock()
        def journal(entry):
            real_journal(entry)
            if entry['etat']=='en_cours':clock[0]+=5
        with patch.object(self.ex.time,'time',side_effect=lambda:clock[0]),patch.object(self.ex,'_journal',side_effect=journal), \
             patch.dict(self.ex.ACTIONS,{'arreter-service':mutation}):receipt=self.ex.appliquer(req)
        self.assertFalse(receipt['applique']);mutation.assert_not_called()
        self.assertEqual(receipt['refus']['motif'],'defense_profondeur_autorisation_refusee')


if __name__=='__main__':unittest.main()
