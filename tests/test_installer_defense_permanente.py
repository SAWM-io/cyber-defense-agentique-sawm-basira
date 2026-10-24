"""Plan additif d'installation ; ces tests n'appellent jamais la VM."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from controleur.installer_defense_permanente import manifeste_permanent,UNIT,DB,ACTIONS


class PermanentDefensePlanTests(unittest.TestCase):
    def original(self):
        return {'generation':'existing','unites_autorisees':['labo-existing.service'],
                'unites_protegees':['labo-temoin.service'],'actions_autorisees':['arreter-service','geler-transfert'],
                'actions_par_unite':{'labo-existing.service':['geler-transfert']},
                'veille':{'unites_connues':['labo-temoin.service'],'actions_automatiques':['arreter-service'],
                          'budget_cloud':4,'sources_connues':['source-a']},'other':{'keep':'verbatim'}}

    def test_additive_idempotent_preserves_generation_budget_and_existing_rights(self):
        original=self.original();before=copy.deepcopy(original)
        result=manifeste_permanent(original,reference_sha256='a'*64,machine_id='vm')
        self.assertEqual(original,before)
        self.assertEqual(result['generation'],original['generation'])
        self.assertEqual(result['other'],original['other'])
        self.assertEqual(result['veille']['budget_cloud'],4)
        self.assertEqual(result['actions_autorisees'],original['actions_autorisees'])
        self.assertEqual(result['actions_par_unite']['labo-existing.service'],['geler-transfert'])
        self.assertEqual(result['actions_par_unite'][UNIT],ACTIONS)
        self.assertIn('ssh.service',result['unites_protegees'])
        self.assertEqual(result['defense_fichiers']['targets'][0]['path'],DB)
        self.assertEqual(result,manifeste_permanent(result,reference_sha256='a'*64,machine_id='vm'))

    def test_existing_reference_never_replaced_by_current_unexplained_content(self):
        result=manifeste_permanent(self.original(),reference_sha256='a'*64,machine_id='vm')
        with self.assertRaisesRegex(ValueError,'cible_existante_divergente'):
            manifeste_permanent(result,reference_sha256='b'*64,machine_id='vm')

    def test_existing_trust_registry_preserved_and_wrong_machine_rejected(self):
        original=self.original();original['maintenance']={'machine_id':'vm','keys':['opaque'],'mandates':['existing']}
        result=manifeste_permanent(original,reference_sha256='a'*64,machine_id='vm')
        self.assertEqual(result['maintenance'],original['maintenance'])
        with self.assertRaisesRegex(ValueError,'machine_divergente'):
            manifeste_permanent(original,reference_sha256='a'*64,machine_id='other')


if __name__=='__main__':unittest.main()
