import copy
import pathlib
import sys
import unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from controleur.validation_continuite_reseau import stable_baseline


class BaselineTest(unittest.TestCase):
    def test_lease_countdown_is_not_configuration_change(self):
        a={'management_addresses':[{'local':'192.0.2.1','prefixlen':24,'valid_life_time':99,'preferred_life_time':99}], 'http':200}
        b=copy.deepcopy(a);b['management_addresses'][0]['valid_life_time']=98
        self.assertEqual(stable_baseline(a),stable_baseline(b))
        self.assertEqual(a['management_addresses'][0]['valid_life_time'],99)

    def test_address_or_health_change_remains_visible(self):
        a={'management_addresses':[{'local':'192.0.2.1'}],'http':200}
        b=copy.deepcopy(a);b['management_addresses'][0]['local']='192.0.2.2'
        self.assertNotEqual(stable_baseline(a),stable_baseline(b))
        b=copy.deepcopy(a);b['http']=503
        self.assertNotEqual(stable_baseline(a),stable_baseline(b))
