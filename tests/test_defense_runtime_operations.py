"""Scopes distincts : la maintenance d'une opération ne couvre pas tout l'incident."""
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

LAB = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(LAB), str(LAB/'invite/agent_labo')]
import defense_runtime as runtime
from controleur.diagnostic_defense import diagnostiquer

UNIT = 'labo-scope.service'
BOOT = '12345678-1234-1234-1234-123456789abc'


class RuntimeOperationScopeTests(unittest.TestCase):
    def inspect(self, grants, *, busy=True, changed=True, write=True, locked=True):
        device = os.makedev(252, 3)
        obs = {'boot_id':BOOT,'pid':42,'process_start_ticks':55,'uid':0,
               'cgroup':'/sawm.slice/'+UNIT,'identity_stable':True,'observed_at_ms':10000,
               'invocation_id':'a'*32,'fd_on_object':True,
               'object':{'device':device,'inode':555},
               'kernel_locks':['3: POSIX ADVISORY WRITE 42 fc:03:555 1073741824 1073742335'] if locked else []}
        sensor = {'active':True,'events':([{'operation_succeeded':True,'boot_id':BOOT,
                  'pid':42,'euid':0,'inode':555,'device':(252<<20)|3,'received_at_ms':9999,
                  'capture_latency_ms':0.3,'process':{'identity_stable':True,'start_ticks':55,
                  'cgroup':'0::'+obs['cgroup']}}] if write else [])}
        target = {'unit':UNIT,'path':'/opt/sawm-labo/fixtures/db','kind':'sqlite',
                  'reference_sha256':'a'*64,'automatic_containment':True}
        manifest = {'generation':'test','_sha256':'c'*64,'unites_autorisees':[UNIT],
                    'veille':{'actions_automatiques':['arreter-service']}}
        probe = {'sample_stable':True,'device':device,'inode':555,
                 'read_available':not busy,'write_available':not busy,
                 'read_error':'SQLITE_BUSY' if busy else None,'write_error':'SQLITE_BUSY' if busy else None}
        hashed = {'sample_stable':True,'reference_verified':True,'device':device,'inode':555,
                  'reference_sha256':'a'*64,'current_sha256':('b' if changed else 'a')*64}
        evaluated = []
        def evaluate(*args, operation, **kwargs):
            evaluated.append(operation)
            if operation in grants:
                return {'authorized':True,'reason':'mandat_signe_valide','mandate_id':'permit-'+operation,'principal':'institution:cto'}
            return {'authorized':False,'reason':'aucun_mandat_pour_operation'}
        with patch.object(runtime,'integrity',return_value=hashed), patch.object(runtime,'availability',return_value=probe), patch.object(runtime.time,'time',return_value=10):
            item = runtime.inspect_target(manifest,target,sensor,lambda *args:obs,evaluate,diagnostiquer)
        return manifest, item, evaluated

    def test_lock_permit_does_not_hide_unattributed_integrity_change(self):
        manifest,item,evaluated=self.inspect({'sqlite-exclusive-lock'},write=False)
        self.assertTrue(item['authorization']['authorized'])
        self.assertEqual(item['diagnostic']['recommandation'],'signaler')
        self.assertIn('alteration_non_couverte_auteur_non_attribue',item['diagnostic']['inconnues'])
        execute=Mock()
        self.assertIsNone(runtime.contain(manifest,item,execute))
        execute.assert_not_called()

    def test_lock_without_unavailability_does_not_override_valid_write_permission(self):
        manifest,item,evaluated=self.inspect({'file-write'},busy=False)
        self.assertEqual(evaluated,['file-write'])
        self.assertEqual(item['qualified_operations'],['file-write'])
        self.assertEqual(item['diagnostic']['recommandation'],'surveiller')
        execute=Mock();self.assertIsNone(runtime.contain(manifest,item,execute))
        execute.assert_not_called()

    def test_two_established_violations_require_two_permissions(self):
        for grants,expected in [({'file-write'},'contenir_sous_mandat'),
                                ({'sqlite-exclusive-lock'},'contenir_sous_mandat'),
                                ({'sqlite-exclusive-lock','file-write'},'surveiller')]:
            with self.subTest(grants=grants):
                _,item,evaluated=self.inspect(grants)
                self.assertEqual(evaluated,['sqlite-exclusive-lock','file-write'])
                self.assertEqual(len(item['authorizations']),2)
                self.assertEqual(item['diagnostic']['recommandation'],expected)

    def test_write_permit_does_not_hide_unattributed_unavailability(self):
        manifest,item,_=self.inspect({'file-write'},locked=False)
        self.assertEqual(item['qualified_operations'],['file-write'])
        self.assertEqual(item['diagnostic']['recommandation'],'signaler')
        self.assertIn('indisponibilite_non_couverte_detenteur_non_attribue',item['diagnostic']['inconnues'])
        execute=Mock();self.assertIsNone(runtime.contain(manifest,item,execute))
        execute.assert_not_called()

    def test_valid_lock_without_extra_effect_is_preserved(self):
        _,item,evaluated=self.inspect({'sqlite-exclusive-lock'},changed=False,write=False)
        self.assertEqual(evaluated,['sqlite-exclusive-lock'])
        self.assertEqual(item['diagnostic']['recommandation'],'surveiller')


if __name__ == '__main__': unittest.main()
