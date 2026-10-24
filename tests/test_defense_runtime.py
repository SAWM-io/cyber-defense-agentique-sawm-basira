from copy import deepcopy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

LAB = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(LAB), str(LAB / 'invite/agent_labo')]
import defense_runtime as r
from controleur.diagnostic_defense import diagnostiquer

UNIT = 'labo-fixture.service'
BOOT = '12345678-1234-1234-1234-123456789abc'


class DefenseRuntimeTests(unittest.TestCase):
    def test_sqlite_310_busy_has_closed_fallback_and_other_errors_stay_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'ledger';path.write_bytes(b'fixture')
            for message,expected in [('database is locked','SQLITE_BUSY'),('file is not a database','SQLITE_ERROR')]:
                with patch.object(r.sqlite3,'connect',side_effect=r.sqlite3.OperationalError(message)):
                    result=r.availability(str(path))
                self.assertEqual(result['read_error'],expected)
                self.assertEqual(result['write_error'],expected)

    def observation(self):
        return {'boot_id':BOOT,'pid':42,'process_start_ticks':55,'uid':0,
                'cgroup':'/sawm.slice/'+UNIT,'identity_stable':True,
                'observed_at_ms':10000,'invocation_id':'a'*32,'fd_on_object':True,
                'object':{'device':os.makedev(252,3),'inode':555},'kernel_locks':[]}

    def snapshot(self):
        obs = self.observation()
        return {'active':True,'events':[{'operation_succeeded':True,'boot_id':BOOT,
                'pid':42,'euid':0,'inode':555,'device':(252 << 20)|3,
                'received_at_ms':9999,'capture_latency_ms':0.3,
                'process':{'identity_stable':True,'start_ticks':55,
                           'cgroup':'0::'+obs['cgroup']}}]}

    def test_matching_write_requires_exact_device_inode_process_boot_and_fresh_capture(self):
        obs = self.observation()
        snap = self.snapshot()
        self.assertIsNotNone(r.matching_write(snap,obs,10000))
        for changes in ({'device':(251<<20)|3},{'device':(252<<20)|4},
                        {'inode':556},{'pid':43},{'euid':1000},{'boot_id':'other'},
                        {'operation_succeeded':False},{'received_at_ms':10001},
                        {'received_at_ms':8499},{'received_at_ms':True},
                        {'capture_latency_ms':float('nan')},{'capture_latency_ms':None},
                        {'capture_latency_ms':1500},{'capture_latency_ms':-1}):
            changed = deepcopy(snap);changed['events'][0].update(changes)
            self.assertIsNone(r.matching_write(changed,obs,10000),changes)
        for changes in ({'start_ticks':56},{'cgroup':'0::/other'},{'identity_stable':False}):
            changed = deepcopy(snap);changed['events'][0]['process'].update(changes)
            self.assertIsNone(r.matching_write(changed,obs,10000),changes)
        self.assertIsNone(r.matching_write({**snap,'active':False},obs,10000))
        self.assertIsNone(r.matching_write({**snap,'error':'lost'},obs,10000))
        self.assertIsNone(r.matching_write(snap,{**obs,'identity_stable':False},10000))

    def test_sensor_signature_detects_same_name_replacement_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp=Path(tmp).resolve()
            p=tmp/'file';p.write_bytes(b'original')
            first=r.sensor_signature([str(p)])
            p.write_bytes(b'changed')
            self.assertEqual(first,r.sensor_signature([str(p)]))
            p.rename(Path(tmp)/'old');p.write_bytes(b'replacement')
            self.assertNotEqual(first,r.sensor_signature([str(p)]))
            link=Path(tmp)/'link';link.symlink_to(p)
            with self.assertRaises(ValueError):r.sensor_signature([str(link)])

    def test_sensor_loss_and_local_eviction_are_explicit_coverage_flags(self):
        flags=r.sensor_health({'active':False,'error':'x','loss_notifications':1,
                               'evicted_events':256,'invalid_events':1})
        self.assertEqual(len(flags),5)
        self.assertIn('perte_evenements_noyau',flags)
        self.assertEqual(r.sensor_health({'active':True}),[])

    def test_lock_proof_uses_stable_fd_and_exact_exclusive_range_from_observer(self):
        obs=self.observation()
        obs['kernel_locks']=['3: POSIX ADVISORY WRITE 42 fc:03:555 1073741824 1073742335']
        self.assertTrue(r.exclusive_lock(obs))
        for changes in ({'identity_stable':False},{'fd_on_object':False},{'pid':43},
                        {'kernel_locks':['3: POSIX ADVISORY WRITE 42 fc:03:555 1073741825 1073741825']},
                        {'kernel_locks':['3: -> POSIX ADVISORY WRITE 42 fc:03:555 1073741824 1073742335']}):
            self.assertFalse(r.exclusive_lock({**obs,**changes}),changes)

    def inspect(self, *, obs=None, snap=None, authorized=False, hashed=None):
        observation=obs or self.observation()
        target={'unit':UNIT,'path':'/opt/sawm-labo/fixtures/db','kind':'file',
                'reference_sha256':'a'*64,'automatic_containment':True}
        manifest={'_sha256':'c'*64,'generation':'test','unites_autorisees':[UNIT],
                  'veille':{'actions_automatiques':['arreter-service']}}
        hashproof={'reference_sha256':'a'*64,'current_sha256':'b'*64,
                   'reference_verified':True,'sample_stable':True,
                   'device':os.makedev(252,3),'inode':555}
        if hashed:hashproof.update(hashed)
        receipt=({'authorized':True,'reason':'mandat_signe_valide','mandate_id':'valid',
                  'principal':'operator'} if authorized else
                 {'authorized':False,'reason':'aucun_mandat_pour_operation'})
        with patch.object(r,'integrity',return_value=hashproof), patch.object(r.time,'time',return_value=10):
            item=r.inspect_target(manifest,target,snap if snap is not None else self.snapshot(),
                                  lambda *args:observation,lambda *args,**kwargs:receipt,diagnostiquer)
        return manifest,item

    def test_unauthorized_attributed_changed_file_proposes_bounded_containment(self):
        manifest,item=self.inspect()
        self.assertEqual(item['diagnostic']['recommandation'],'contenir_sous_mandat')
        execute=Mock(return_value={'applique':True})
        with patch.object(r.time,'time',return_value=10):
            r.contain(manifest,item,execute)
        self.assertEqual(execute.call_count,1)
        self.assertEqual(execute.call_args.args[0]['cible'],UNIT)

    def test_authorized_maintenance_never_proposes_containment(self):
        manifest,item=self.inspect(authorized=True)
        self.assertEqual(item['diagnostic']['recommandation'],'surveiller')
        execute=Mock()
        self.assertIsNone(r.contain(manifest,item,execute))
        execute.assert_not_called()

    def test_absent_stale_or_wrong_object_attribution_alerts_without_action(self):
        for changes in ({'snap':{'active':False,'events':[]}},
                        {'snap':{'active':True,'events':[]}},
                        {'obs':{**self.observation(),'observed_at_ms':8000}},
                        {'hashed':{'inode':556}}):
            manifest,item=self.inspect(**changes)
            self.assertEqual(item['diagnostic']['recommandation'],'signaler',changes)
            execute=Mock();self.assertIsNone(r.contain(manifest,item,execute))
            execute.assert_not_called()

    def test_evidence_expiring_between_diagnosis_and_execution_cannot_act(self):
        manifest,item=self.inspect()
        execute=Mock()
        with patch.object(r.time,'time',return_value=12):
            result=r.contain(manifest,item,execute)
        self.assertFalse(result['applique']);execute.assert_not_called()

    def test_sensor_health_is_alerted_even_without_integrity_mismatch(self):
        manifest,item=self.inspect(snap={'active':False,'events':[]},hashed={'current_sha256':'a'*64})
        self.assertEqual(item['diagnostic']['raison'],'couverture_capteur_degradee')
        self.assertIn('capteur_ecritures_inactif',item['diagnostic']['inconnues'])


if __name__=='__main__':unittest.main()
