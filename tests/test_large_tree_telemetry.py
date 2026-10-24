"""The staging summary cannot become current continuous protection telemetry."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

AGENT=Path(__file__).resolve().parents[1]/'invite/agent_labo'
sys.path.insert(0,str(AGENT))
spec=importlib.util.spec_from_file_location('telemetry_large_tree_tests',AGENT/'telemetrie.py')
t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
NOW=1800000000000


def fixture():
    return dict(schema='sawm-large-tree-integrity/v1',status='unchanged',root='/fixture/tree',
                scan_started_ms=NOW-20000,observed_ms=NOW-100,counts={},changes=[],
                metrics={'bytes_read':1207959552,'scan_seconds':18,'cpu_seconds':2.3},
                attribution='unknown',action_performed=False,baseline_sha256='a'*64)


class LargeTreeTelemetryTests(unittest.TestCase):
    def emit(self,value):
        with patch.object(t,'_lire_prive',return_value=(json.dumps(value).encode(),False)):
            return t.integrite_arbres(now_ms=NOW)

    def test_recent_historical_and_absent_are_distinct_without_continuous_claim(self):
        value=fixture();result=self.emit(value)
        self.assertTrue(result['available']);self.assertEqual(result['status'],'dernier_scan')
        self.assertEqual(result['snapshot']['metrics']['bytes_read'],1207959552)
        self.assertFalse(result['continuous_monitoring'])
        value.update(scan_started_ms=NOW-400000,observed_ms=NOW-300001)
        result=self.emit(value);self.assertEqual(result['status'],'scan_ancien')
        self.assertEqual(result['age_ms'],300001)
        with patch.object(t,'_lire_prive',side_effect=FileNotFoundError):
            self.assertEqual(t.integrite_arbres(now_ms=NOW)['status'],'scan_absent')

    def test_unknown_fields_are_not_relayed_and_changes_are_bounded(self):
        value=fixture();value['private_key']='NEVER_RELAY'
        value['metrics']['other']='NEVER_RELAY'
        value['changes']=[{'kind':'added','path':str(i),'private':'NEVER_RELAY'} for i in range(220)]
        result=self.emit(value)
        self.assertNotIn('NEVER_RELAY',str(result));self.assertEqual(len(result['snapshot']['changes']),200)
        self.assertTrue(result['snapshot']['changes_truncated'])

    def test_forged_authority_future_clock_or_nonfinite_numbers_are_rejected(self):
        for changes in ({'attribution':'root-user-identified'},{'action_performed':True},
                        {'observed_ms':NOW+1},{'scan_started_ms':NOW+1},
                        {'metrics':{'scan_seconds':-1}},{'metrics':{'bytes_read':10**400}},{'counts':{'added':True}},
                        {'status':'safe_forever'},{'changes':[{'kind':'delete-all','path':'x'}]}):
            with self.subTest(changes=changes):
                result=self.emit({**fixture(),**changes})
                self.assertEqual(result['status'],'scan_non_verifiable');self.assertIsNone(result['snapshot'])
        raw=json.dumps(fixture()).replace('"scan_seconds": 18','"scan_seconds": 1e999').encode()
        with patch.object(t,'_lire_prive',return_value=(raw,False)):
            self.assertEqual(t.integrite_arbres(now_ms=NOW)['status'],'scan_non_verifiable')


if __name__=='__main__':unittest.main()
