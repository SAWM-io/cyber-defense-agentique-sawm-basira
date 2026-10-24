import importlib.util,pathlib,sys,unittest
from unittest.mock import patch
P=pathlib.Path(__file__).resolve().parents[1]/'invite/agent_labo'
sys.path.insert(0,str(P))
spec=importlib.util.spec_from_file_location('capteur_identite',P/'telemetrie.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def stat(t):return '42 (nom ) avec espaces) '+' '.join(['S']+['0']*18+[str(t)]+['0']*5)
class IdentiteCapteurTest(unittest.TestCase):
 def test_stable_ticks_and_cgroup(self):
  with patch.object(m,'lire',side_effect=[stat(55),'0::/a.service\n',stat(55)]):
   self.assertEqual(m.identite_processus(42),(55,'0::/a.service'))
 def test_pid_reused_fails_closed(self):
  with patch.object(m,'lire',side_effect=[stat(55),'0::/a.service',stat(56)]):
   self.assertEqual(m.identite_processus(42),(None,None))
 def test_process_vanished_unknown(self):
  with patch.object(m,'lire',return_value=None):self.assertEqual(m.identite_processus(42),(None,None))
