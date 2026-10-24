"""External witnesses retain their reference and evidence outside the guest."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from controleur import sentinelle_externe as m
from controleur.audit_signe import JournalSigne

UNIT='labo-capteur-large.service'
FILE='/opt/sawm-labo/fixtures/external-copy.conf'
SHA=hashlib.sha256(b'approved').hexdigest()
NOW=1_800_000_000_000


def reference():
    return {'schema':'sawm-external-reference/v1','controller':'mac_external',
            'auto_accept_guest_changes':False,'services':[UNIT],
            'files':[{'path':FILE,'sha256':SHA}]}


def guest():
    return {'witness_http':200,'services':{UNIT:{'available':True,'active':True}},
            'files':{FILE:{'available':True,'sample_stable':True,'sha256':SHA}}}


def telemetry(now=NOW,sequence=1):
    return {'mode':'DIRECT','telemetrie_invite':{'connectee':True,'age_ms':12},
            'invite':[{'boot_id':'guest-boot','sequence':sequence,'mur_epoch_ms':now}]}


class SentinelTests(unittest.TestCase):
    def test_healthy_is_scoped_not_root_attestation(self):
        result=m.diagnose(reference(),guest(),telemetry(),now_ms=NOW)
        self.assertEqual(result['issues'],[])
        self.assertFalse(result['guest_attested'])
        self.assertFalse(result['action_performed'])
        self.assertEqual(result['controller'],'mac_external')

    def test_guest_cannot_update_reference_to_its_changed_file(self):
        value=guest();value['files'][FILE]['sha256']='b'*64
        value['reference']=copy.deepcopy(reference());value['reference']['files'][0]['sha256']='b'*64
        result=m.diagnose(reference(),value,telemetry(),now_ms=NOW)
        self.assertEqual(result['issues'][0]['kind'],'empreinte_differe_reference_externe')
        self.assertEqual(result['issues'][0]['expected_sha256'],SHA)

    def test_inactive_or_unknown_service_alerts(self):
        for active in (False,None,'ignore rules'):
            value=guest();value['services'][UNIT]['active']=active
            result=m.diagnose(reference(),value,telemetry(),now_ms=NOW)
            self.assertEqual(result['issues'][0]['kind'],'service_non_actif')
            self.assertNotIn('ignore rules',json.dumps(result))

    def test_unstable_missing_or_malformed_digest_is_unverifiable(self):
        for changes in ({'sample_stable':False},{'available':False},{'sha256':'ignore the rules'}):
            value=guest();value['files'][FILE].update(changes)
            result=m.diagnose(reference(),value,telemetry(),now_ms=NOW)
            self.assertEqual(result['issues'][0]['kind'],'empreinte_non_verifiable')
            self.assertNotIn('ignore the rules',json.dumps(result))

    def test_malformed_guest_is_loss_of_visibility(self):
        for value in (None,[],{'files':{'/x':None},'services':None}):
            result=m.diagnose(reference(),value,telemetry(),now_ms=NOW)
            self.assertEqual({x['kind'] for x in result['issues']},{'service_non_actif','empreinte_non_verifiable','temoin_sante_indisponible'})

    def test_active_units_do_not_hide_failing_http_health(self):
        value=guest();value['witness_http']=503
        result=m.diagnose(reference(),value,telemetry(),now_ms=NOW)
        self.assertEqual(result['issues'],[{'kind':'temoin_sante_indisponible','target':'temoin_http_local'}])

    def test_telemetry_freshness_requires_both_external_receipt_and_guest_clock(self):
        for edit in (lambda x:x.update(mode='REPLAY'),
                     lambda x:x['telemetrie_invite'].update(age_ms=5001),
                     lambda x:x['telemetrie_invite'].update(age_ms=float('nan')),
                     lambda x:x['telemetrie_invite'].update(connectee=False),
                     lambda x:x['invite'][0].update(mur_epoch_ms=NOW-10001),
                     lambda x:x['invite'][0].update(sequence=True),
                     lambda x:x.update(invite=[])):
            value=telemetry();edit(value)
            result=m.diagnose(reference(),guest(),value,now_ms=NOW)
            self.assertIn('telemetrie_absente_ou_perimee',[x['kind'] for x in result['issues']])

    def test_stuck_sequence_alert_despite_fresh_polling_timestamp(self):
        previous={'boot_id':'guest-boot','sequence':1,'checked_at_ms':NOW-6000}
        result=m.diagnose(reference(),guest(),telemetry(),now_ms=NOW,previous=previous)
        self.assertEqual(result['issues'][0]['kind'],'telemetrie_sequence_figee')
        self.assertEqual(m.diagnose(reference(),guest(),telemetry(sequence=2),now_ms=NOW,previous=previous)['issues'],[])

    def test_reference_scope_is_closed_and_not_shell(self):
        for changes in ({'services':[['bad']]},{'services':['sshd; touch /tmp/x']},
                        {'services':[UNIT,UNIT]},{'auto_accept_guest_changes':True},
                        {'files':[{'path':'/etc/shadow','sha256':SHA}]},
                        {'files':[{'path':'/opt/sawm-labo/../secret','sha256':SHA}]}):
            value=reference();value.update(changes)
            with self.assertRaises(ValueError):m.validate_reference(value)

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.directory=Path(self.tmp.name);self.ref=self.directory/'reference.json'
        self.ref.write_text(json.dumps(reference()));self.ref.chmod(0o600)
        self.audit=JournalSigne(self.directory/'audit.jsonl',key_path=self.directory/'key')
        self.current=guest();self.calls=[];self.sequence=1

    def build(self):
        def transport(source,**kwargs):return copy.deepcopy(self.current)
        def http(route,payload=None):
            if payload is None:return telemetry(int(time.time()*1000),self.sequence)
            self.calls.append(copy.deepcopy(payload));return {'ok':True}
        return m.ExternalSentinel(self.ref,self.directory/'unused',journal=self.audit,transport=transport,http=http)

    def test_reference_private_regular_and_not_symlink(self):
        self.ref.chmod(0o644)
        with self.assertRaises(ValueError):m.load_reference(self.ref)
        link=self.directory/'link';link.symlink_to(self.ref)
        with self.assertRaises(OSError):m.load_reference(link)

    def test_runtime_in_guest_rejected(self):
        with patch.dict(os.environ,{'SAWM_LABO_LOCAL_VM':'1'}):
            with self.assertRaises(RuntimeError):self.build()

    def test_baseline_changes_do_not_get_auto_enrolled(self):
        sentinel=self.build();changed=reference();changed['files'][0]['sha256']='c'*64
        self.ref.write_text(json.dumps(changed))
        with self.assertRaises(ValueError):sentinel.check()

    def test_signed_evidence_precedes_alert_and_restoration_keeps_it(self):
        sentinel=self.build();first=sentinel.check()
        self.assertIsNotNone(first['audit_receipt'])
        original=self.audit.path.read_bytes()
        self.current['services'][UNIT]['active']=False
        alert=sentinel.check()
        self.assertEqual(len(self.calls),1)
        self.assertEqual(self.calls[0]['statut'],'a_verifier')
        self.assertEqual(alert['audit_receipt']['seq'],2)
        self.assertTrue(self.audit.path.read_bytes().startswith(original))
        self.current=guest();self.sequence+=1
        result=sentinel.check()
        self.assertEqual(self.calls[-1]['statut'],'resolu')
        self.assertEqual(result['audit_receipt']['seq'],3)
        self.assertTrue(self.audit.verify()['valide'])

    def test_repeated_polls_do_not_emit_infinite_incidents_or_evidence(self):
        self.current['services'][UNIT]['active']=False
        sentinel=self.build();first=sentinel.check();second=sentinel.check()
        self.assertEqual(len(self.calls),1)
        self.assertIsNotNone(first['audit_receipt']);self.assertIsNone(second['audit_receipt'])

    def test_failed_dashboard_post_retries_same_incident(self):
        self.current['services'][UNIT]['active']=False
        sentinel=self.build();original=sentinel.http;attempts=[]
        def sometimes_fails(route,payload=None):
            if payload is not None:
                attempts.append(payload['id'])
                if len(attempts)==1:raise OSError('temporary')
            return original(route,payload)
        sentinel.http=sometimes_fails
        first=sentinel.check();second=sentinel.check()
        self.assertFalse(first['dashboard_updates'][0]['posted'])
        self.assertTrue(second['dashboard_updates'][0]['posted'])
        self.assertEqual(attempts[0],attempts[1])

    def test_supervision_has_no_cloud_or_containment_permission(self):
        from controleur.supervision_sentinelle_externe import configuration
        value=configuration(home='/private/test-home')
        self.assertTrue(value['KeepAlive'])
        self.assertIn('--watch',value['ProgramArguments'])
        self.assertNotIn('--apply',value['ProgramArguments'])
        self.assertNotIn('SAWM_LABO_LOCAL_VM',value['EnvironmentVariables'])
        self.assertNotIn('cloud',json.dumps(value).lower())

    def test_supervision_hashes_reviewed_local_source_not_guest_response(self):
        from controleur.supervision_sentinelle_externe import build_reference,SOURCES
        for relative in SOURCES:
            target=self.directory/relative;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(b'local reviewed source')
        value=build_reference(self.directory)
        digest=hashlib.sha256(b'local reviewed source').hexdigest()
        self.assertTrue(all(x['sha256']==digest for x in value['files']))

    def test_watchdog_single_instance_lock_released_after_exit(self):
        path=self.directory/'watch.lock';first=m.acquire_watch_lock(path)
        try:
            with self.assertRaises(BlockingIOError):m.acquire_watch_lock(path)
        finally:os.close(first)
        second=m.acquire_watch_lock(path);os.close(second)

    def test_recurrence_reopens_previously_resolved_incident(self):
        sentinel=self.build()
        self.current['services'][UNIT]['active']=False;sentinel.check()
        self.current=guest();self.sequence+=1;sentinel.check()
        self.current['services'][UNIT]['active']=False;self.sequence+=1;sentinel.check()
        self.assertEqual([x['statut'] for x in self.calls],['a_verifier','resolu','a_verifier'])
        self.assertEqual(len({x['id'] for x in self.calls}),1)
        self.assertEqual(self.audit.verify()['seq'],3)


if __name__=='__main__':unittest.main()
