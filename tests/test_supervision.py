import pathlib,sys,unittest,plistlib
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from controleur.supervision import configuration
class SupervisionTest(unittest.TestCase):
 def test_supervised_restart_and_private_no_credentials(self):
  for role in ('veille','collecteur'):
   c=configuration(role,python='/python',racine=pathlib.Path('/lab'),home='/private-user')
   self.assertTrue(c['KeepAlive']);self.assertTrue(c['RunAtLoad']);self.assertEqual(c['ThrottleInterval'],15)
   self.assertEqual(c['Umask'],63);self.assertNotIn('TOKEN',str(c));self.assertNotIn('SECRET',str(c))
   self.assertEqual(plistlib.loads(plistlib.dumps(c)),c)
 def test_continuous_analysis_stays_budgeted_and_typed(self):
  c=configuration('veille');a=c['ProgramArguments']
  self.assertIn('--permanent',a);self.assertNotIn('--apply',a);self.assertNotIn('--cloud',a)
  self.assertEqual(a[-2:],['--cloud-per-hour','4'])
  self.assertEqual(configuration('veille',racine=pathlib.Path('/lab'))['ProgramArguments'][0],'/lab/.venv/bin/python')
 def test_cloud_and_actions_require_separate_explicit_opt_in(self):
  self.assertIn('--cloud',configuration('veille',cloud=True)['ProgramArguments'])
  self.assertNotIn('--apply',configuration('veille',cloud=True)['ProgramArguments'])
  self.assertIn('--apply',configuration('veille',cloud=True,apply=True)['ProgramArguments'])
  with self.assertRaises(ValueError):configuration('veille',apply=True)
 def test_no_arbitrary_role(self):
  with self.assertRaises(ValueError):configuration('shell')
