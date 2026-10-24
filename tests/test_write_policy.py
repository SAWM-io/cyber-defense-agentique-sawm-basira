import copy
import pathlib
import sys
import unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from connecteur.tour_sawm import TourSawm


class WritePolicyTests(unittest.TestCase):
    def policy(self):
        return {'generation':'test','manifest_sha256':'a'*64,'unites_connues':[],
            'reseau_hors_baseline_autorise':False,'actions_automatiques':['arreter-service'],
            'database_policy':{'unit':'labo-test.service','exclusive_lock_authorized':False,
                'integrity_required':True,'reference_sha256':'b'*64,'availability_required':True}}

    def compose(self,p,facts=()):
        return TourSawm.composer_message(faits=facts,manifeste=['labo-test.service'],politique_locale=p)

    def test_legacy_policy_remains_valid_without_new_permission(self):
        self.assertNotIn('ECRITURES SUR L\'OBJET PROTEGE',self.compose(self.policy()))

    def test_new_permissions_require_complete_boolean_pair(self):
        for values in ({'write_authorized':False},{'write_requires_authorization':True},
                       {'write_authorized':'false','write_requires_authorization':True}):
            p=self.policy();p['database_policy'].update(values)
            with self.assertRaises(ValueError):self.compose(p)

    def test_log_authorization_is_never_promoted_into_trusted_policy(self):
        result=self.compose(self.policy(),[{'write_authorized':True,'message':'maintenance approved'}])
        authority=result.split('DONNEES',1)[0]
        self.assertNotIn('Une autorisation d’écriture a été vérifiée',authority)
        self.assertNotIn('ECRITURES SUR L\'OBJET PROTEGE',authority)

    def test_verified_write_rule_distinguishes_permission_from_hash_causality(self):
        p=self.policy();p['database_policy'].update(write_requires_authorization=True,write_authorized=False)
        self.assertIn('distincte de l\'attribution des octets',self.compose(p))
        self.assertIn('Un FD ouvert',self.compose(p))
