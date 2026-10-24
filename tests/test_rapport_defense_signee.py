"""Le rapport exige l'effet mesuré et sépare maintien passif, veto et choix SAWM."""
import copy
import pathlib
import sys
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from controleur.rapport_defense_signee import strict_success, outcome, title, ssh_success


class RapportDefenseSigneeTests(unittest.TestCase):
    def base(self):
        return {'status':'passed','mode':'lock','permit':'absent','origin':'local_policy',
                'witness':{'healthy':True},'unit_after':{'ActiveState':'inactive','MainPID':'0'},
                'after':{'read_available':True,'write_available':True},
                'result':{'action':{'applique':True,'effet_verifie':True}}}

    def test_success_label_without_witness_and_restored_access_is_insufficient(self):
        good = self.base()
        self.assertTrue(strict_success(good))
        for key in ('read_available','write_available'):
            case = copy.deepcopy(good); case['after'][key] = False
            self.assertFalse(strict_success(case))
        good['witness']['healthy'] = False
        self.assertFalse(strict_success(good))

    def test_authorized_maintenance_requires_actual_veto_and_same_pid(self):
        case = self.base(); case.update(permit='valid', unit_after={'ActiveState':'active','MainPID':'23'},
            result={'authorization':{'authorized':True},'diagnostic':{'recommandation':'surveiller'}})
        self.assertFalse(strict_success(case))
        self.assertIn('veto non testé', outcome(case))
        case['veto_attempt']={'applique':False,'refus':{'motif':'maintenance_signee_preservee'},
                              'expected_identity':{'MainPID':'23'}}
        self.assertTrue(strict_success(case))
        case['result']['diagnostic']['recommandation'] = 'signaler'
        self.assertTrue(strict_success(case))
        self.assertIn('alerte conservée', outcome(case))
        case['unit_after']['MainPID']='24'
        self.assertFalse(strict_success(case))

    def test_cloud_stop_needs_independent_verification_not_only_receipt(self):
        case = self.base(); case.update(origin='SAWM',cloud_requested=True)
        self.assertFalse(strict_success(case))
        case['cloud_verification']={'statut':'verifie','effet':'arret_unite_verifie','temoin':'disponible'}
        self.assertTrue(strict_success(case))
        self.assertIn('analyse SAWM',title(case))
        case['cloud_verification']['temoin']='inconnu'
        self.assertFalse(strict_success(case))

    def test_forged_permission_is_alert_without_inventing_a_stop(self):
        case = self.base(); case.update(permit='forged',unit_after={'ActiveState':'active'},
            result={'authorization':{'authorized':False},'diagnostic':{'recommandation':'signaler'}})
        self.assertTrue(strict_success(case))
        self.assertNotIn('Arrêt',outcome(case))
        case['result']['action']={'applique':True}
        self.assertFalse(strict_success(case))

    def test_ssh_requires_refusals_corresponding_observations_alert_and_witness(self):
        case = {'status':'passed','available':True,
                'attempts':[{'authentication_rejected':True,'exit_code':255} for _ in range(3)],
                'observations':[{'id':str(i),'source':'journald_root_sshd','destination_port':22,
                                 'outcome':'invalid_account'} for i in range(3)],
                'alerts':[{'recommandation':'signaler','block_performed':False}],
                'witness_http':200,'existing_key_ssh_still_works':True}
        self.assertTrue(ssh_success(case))
        failed = copy.deepcopy(case); failed['observations'][0]['id'] = '1'
        self.assertFalse(ssh_success(failed))
        failed = copy.deepcopy(case); failed['existing_key_ssh_still_works'] = False
        self.assertFalse(ssh_success(failed))
        failed = copy.deepcopy(case); failed['attempts'][0]['authentication_rejected'] = False
        self.assertFalse(ssh_success(failed))
        failed = copy.deepcopy(case); failed['alerts'][0]['block_performed'] = True
        self.assertFalse(ssh_success(failed))


if __name__ == '__main__':
    unittest.main()
