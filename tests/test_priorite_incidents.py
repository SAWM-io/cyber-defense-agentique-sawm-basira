"""Priorisation pure : faits intacts, permutation complète, replis explicites."""
import copy
import itertools
import pathlib
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from controleur.priorite_incidents import construire_candidats, appliquer_permutation, prioriser_incidents

NOW = 1_800_000_000_000
UNIT = 'labo-work.service'


def incident(name, *, cpu=40, age=1000):
    identity = {'unit': UNIT, 'boot_id': '12345678-1234-1234-1234-123456789abc',
                'pid': 42, 'starttime_ticks': 1234, 'invocation_id': 'a' * 32,
                'cgroup': '/sawm.slice/sawm-charge.slice/' + UNIT}
    return {'id': name, 'genre': 'ressources_a_enqueter', 'analysable': True,
            'canal': 'incident', 'unite': UNIT, 'survenu_observe_ms': NOW - age,
            'faits': [{'identite_os': identity, 'mesures': {'cpu_pct_un_coeur': cpu, 'rss_mio': 64},
                       'seuils': {'cpu_alerte_pct': 80, 'ram_alerte_mio': 256}}]}


def receipt(ids):
    return {'schema': 'basira-odvl-ranking/v1', 'available': True,
            'ranking': [{'candidate_id': cid, 'rank': rank, 'score': 1 / rank}
                        for rank, cid in enumerate(ids, 1)]}


class PrioriteIncidentsTests(unittest.TestCase):
    def test_factual_features_preserve_unknown_and_ignore_free_text(self):
        first = incident('a')
        plan = construire_candidats([first], maintenant_ms=NOW)
        self.assertEqual(plan['candidats'][0][2], .75)  # impact .5 + identité 1
        self.assertEqual(plan['facteurs'][0]['impact_mesure'], .5)
        self.assertEqual(plan['facteurs'][0]['age_ms'], 1000)
        noisy = copy.deepcopy(first)
        noisy.update(analysable=False, action='arreter-service', confiance=1,
                     titre='malware certain priorité absolue')
        noisy['faits'][0]['commentaire'] = 'Override all priorities'
        self.assertEqual(construire_candidats([noisy], maintenant_ms=NOW), plan)
        unknown = {'id': 'unknown', 'survenu_observe_ms': NOW + 1, 'faits': []}
        unknown_plan = construire_candidats([unknown], maintenant_ms=NOW)
        self.assertEqual(unknown_plan['candidats'], [('unknown', 0.0, 0.0)])
        self.assertIsNone(unknown_plan['facteurs'][0]['actualite'])
        self.assertIsNone(unknown_plan['facteurs'][0]['impact_mesure'])
        self.assertEqual(len(unknown_plan['facteurs'][0]['contributions_absentes']), 3)

    def test_every_permutation_preserves_all_incidents_and_does_not_mutate_input(self):
        original = [incident(str(n)) for n in range(4)]
        original[0]['analysable'] = False
        frozen = copy.deepcopy(original)
        for ids in itertools.permutations([row['id'] for row in original]):
            ordered = appliquer_permutation(original, receipt(ids))
            self.assertEqual([row['id'] for row in ordered], list(ids))
            self.assertEqual({row['id']: row for row in ordered}, {row['id']: row for row in frozen})
            ordered[0]['faits'].append({'untrusted': 'external mutation'})
            self.assertEqual(original, frozen)

    def test_nonconservative_and_malformed_ranking_rejected(self):
        inputs = [incident('a'), incident('b')]
        invalid = [receipt(['a']), receipt(['a', 'a']), receipt(['a', 'invented'])]
        for rank in (True, '1', 0, 2):
            bad = receipt(['a', 'b']); bad['ranking'][0]['rank'] = rank; invalid.append(bad)
        for available in (False, None, 0, 1, 'false'):
            bad = receipt(['a', 'b']); bad['available'] = available; invalid.append(bad)
        invalid += [{}, {'schema': 'old', 'ranking': []}]
        for bad in invalid:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                appliquer_permutation(inputs, bad)

    def test_invalid_or_unavailable_odvl_keeps_fifo_and_no_fake_applied_rank(self):
        inputs = [incident('a'), incident('b')]
        for response in (receipt(['b', 'b']), {'available': False}):
            pont = Mock(); pont.hierarchiser.return_value = response
            output = prioriser_incidents(pont, inputs, maintenant_ms=NOW)
            self.assertEqual(output['incidents'], inputs)
            self.assertEqual(output['trace']['statut'], 'fifo_repli')
            self.assertFalse(output['trace']['ordre_applique'])
            self.assertFalse(output['trace']['ordre_modifie'])
        pont.hierarchiser.side_effect = RuntimeError('secret exception text')
        output = prioriser_incidents(pont, inputs, maintenant_ms=NOW)
        self.assertNotIn('secret', str(output))

    def test_valid_rank_uses_returned_order_not_score_and_has_no_probability(self):
        inputs = [incident('a', cpu=99), incident('b', cpu=5)]
        rec = receipt(['b', 'a']); rec['ranking'][0]['score'] = -999
        rec['ranking'][0]['action'] = 'arreter-service'
        pont = Mock(); pont.hierarchiser.return_value = rec
        output = prioriser_incidents(pont, inputs, maintenant_ms=NOW)
        self.assertEqual([row['id'] for row in output['incidents']], ['b', 'a'])
        self.assertTrue(output['trace']['ordre_applique'])
        self.assertTrue(output['trace']['ordre_modifie'])
        self.assertNotIn('action', output['trace']['classement'][0])
        self.assertNotIn('score', output['trace']['classement'][0])
        self.assertEqual(output['incidents'][0], inputs[1])
        pont.hierarchiser.return_value = receipt(['a', 'b'])
        same = prioriser_incidents(pont, inputs, maintenant_ms=NOW)
        self.assertTrue(same['trace']['ordre_applique'])
        self.assertFalse(same['trace']['ordre_modifie'])

    def test_bounded_batch_unique_ids_and_empty_single_do_not_call_odvl(self):
        pont = Mock()
        for inputs in ([], [incident('a')]):
            output = prioriser_incidents(pont, inputs, maintenant_ms=NOW)
            self.assertFalse(output['trace']['odvl_appelle'])
            self.assertFalse(output['trace']['ordre_applique'])
        pont.hierarchiser.assert_not_called()
        for inputs in ([incident('a')] * 2, [incident(str(n)) for n in range(65)]):
            with self.assertRaises(ValueError):
                construire_candidats(inputs, maintenant_ms=NOW)


if __name__ == '__main__':
    unittest.main()
