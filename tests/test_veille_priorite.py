"""Worker ODVL et budget SAWM, sans Cloud/VM : aucune preuve retirée par rang."""
import json
import pathlib
import sys
import threading
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from controleur import veille as v
from controleur.collecteur import valider_evenement

NOW = 1_800_000_000_000


def incident(name, age=1000):
    return {'id': name, 'genre': 'ressources_a_enqueter', 'faits': [],
            'unite': 'labo-work.service', 'analysable': True, 'canal': 'incident',
            'survenu_observe_ms': NOW - age}


def receipt(ids):
    return {'schema': 'basira-odvl-ranking/v1',
            'ranking': [{'candidate_id': cid, 'rank': rank} for rank, cid in enumerate(ids, 1)]}


class VeillePrioriteTests(unittest.TestCase):
    def watcher(self, budget=True):
        journal = Mock(); journal.reserver.return_value = budget
        post = Mock(return_value={})
        watch = v.Veille({'veille': {}}, journal, cloud=True, poster=post,
                         fin=time.monotonic() + 120)
        watch.analyser_cloud = Mock()
        return watch

    def test_budget_reserved_for_actual_ranked_choice_and_other_queue_entries_preserved(self):
        watch = self.watcher()
        inputs = [incident('a'), incident('b'), incident('c')]
        for inc in inputs: watch.attente.put_nowait(inc)
        pont = Mock(); pont.hierarchiser.return_value = receipt(['b', 'c', 'a'])
        with patch('connecteur.pont_memoire.PontMemoire', return_value=pont), patch.object(v.time, 'time', return_value=NOW/1000):
            watch.traiter_attente()
        watch.journal.reserver.assert_called_once_with('b', watch.limite_cloud)
        watch.analyser_cloud.assert_called_once_with(inputs[1])
        self.assertEqual(list(watch.attente.queue), [inputs[0], inputs[2]])
        pont.close.assert_called_once()
        trace = next(call.kwargs['trace'] for call in watch.journal.ecrire.call_args_list if call.args[0] == 'priorite_incidents')
        self.assertEqual(trace['incident_choisi'], 'b')
        self.assertTrue(trace['budget_sawm_reserve'])
        self.assertTrue(any(call.args[1].get('phase') == 'priorite_incidents' for call in watch.poster.call_args_list))

    def test_budget_exhaustion_leaves_entire_queue_and_uses_selected_id(self):
        watch = self.watcher(budget=False)
        inputs = [incident('a'), incident('b')]
        for inc in inputs: watch.attente.put_nowait(inc)
        pont = Mock(); pont.hierarchiser.return_value = receipt(['b', 'a'])
        with patch('connecteur.pont_memoire.PontMemoire', return_value=pont), patch.object(v.time, 'time', return_value=NOW/1000):
            watch.traiter_attente()
        watch.journal.reserver.assert_called_once_with('b', watch.limite_cloud)
        watch.analyser_cloud.assert_not_called()
        self.assertEqual(list(watch.attente.queue), inputs)

    def test_invalid_receipt_keeps_fifo_and_does_not_drop_other_incident(self):
        watch = self.watcher()
        inputs = [incident('a'), incident('b')]
        for inc in inputs: watch.attente.put_nowait(inc)
        pont = Mock(); pont.hierarchiser.return_value = receipt(['b', 'b'])
        with patch('connecteur.pont_memoire.PontMemoire', return_value=pont), patch.object(v.time, 'time', return_value=NOW/1000):
            watch.traiter_attente()
        watch.journal.reserver.assert_called_once_with('a', watch.limite_cloud)
        watch.analyser_cloud.assert_called_once_with(inputs[0])
        self.assertEqual(list(watch.attente.queue), [inputs[1]])

    def test_incident_expiring_during_odvl_is_not_charged_or_analysed(self):
        watch = self.watcher()
        inputs = [incident('old', age=599900), incident('fresh')]
        for inc in inputs: watch.attente.put_nowait(inc)
        clock = [NOW]
        def rank(_rows):
            clock[0] += 200
            return receipt(['old', 'fresh'])
        pont = Mock(); pont.hierarchiser.side_effect = rank
        with patch('connecteur.pont_memoire.PontMemoire', return_value=pont), patch.object(v.time, 'time', side_effect=lambda: clock[0]/1000):
            watch.traiter_attente()
        watch.journal.reserver.assert_called_once_with('fresh', watch.limite_cloud)
        watch.analyser_cloud.assert_called_once_with(inputs[1])
        self.assertTrue(watch.attente.empty())
        self.assertTrue(any(call.args[0] == 'observation_expiree' and call.kwargs['incident_id'] == 'old'
                            for call in watch.journal.ecrire.call_args_list))

    def test_ranking_runs_outside_sensor_thread_and_new_arrival_is_not_lost(self):
        watch = self.watcher()
        inputs = [incident('a'), incident('b')]
        watch.detecteur = Mock(); watch.detecteur.analyser.return_value = inputs
        watch.journal.nouveau.return_value = True
        entered, release = threading.Event(), threading.Event()
        ranking_threads = []
        def rank(_rows):
            ranking_threads.append(threading.get_ident()); entered.set()
            if not release.wait(2): raise RuntimeError('test rank timeout')
            return receipt(['b', 'a'])
        pont = Mock(); pont.hierarchiser.side_effect = rank
        state = {'mode': 'DIRECT', 'telemetrie_invite': {'connectee': True, 'age_ms': 10}, 'invite': [{}]}
        with patch('connecteur.pont_memoire.PontMemoire', return_value=pont), patch.object(v.time, 'time', return_value=NOW/1000):
            try:
                watch.observer(state)
                self.assertTrue(entered.wait(1))
                self.assertNotEqual(ranking_threads, [threading.get_ident()])
                watch.journal.reserver.assert_not_called()
                self.assertEqual(list(watch.attente.queue), inputs)
                fresh = incident('arrival'); watch.attente.put_nowait(fresh)
                watch.detecteur.analyser.return_value = []
                watch.observer(state)  # Le capteur continue pendant l'appel ODVL.
            finally:
                release.set()
                watch.worker.join(2)
        self.assertFalse(watch.worker.is_alive())
        self.assertEqual(list(watch.attente.queue), [inputs[0], fresh])
        watch.journal.reserver.assert_called_once_with('b', watch.limite_cloud)

    def test_all_expired_public_marker_is_valid_bounded_json_without_selected_id(self):
        watch = self.watcher()
        inputs = [incident(f'{i:02d}-' + 'x' * 157, age=599900) for i in range(64)]
        for inc in inputs: watch.attente.put_nowait(inc)
        clock = [NOW]
        def rank(_rows):
            clock[0] += 200
            return receipt([inc['id'] for inc in inputs])
        pont = Mock(); pont.hierarchiser.side_effect = rank
        with patch('connecteur.pont_memoire.PontMemoire', return_value=pont), patch.object(v.time, 'time', side_effect=lambda: clock[0]/1000):
            watch.traiter_attente()
        watch.journal.reserver.assert_not_called()
        watch.analyser_cloud.assert_not_called()
        self.assertTrue(watch.attente.empty())
        trace = next(call.kwargs['trace'] for call in watch.journal.ecrire.call_args_list
                     if call.args[0] == 'priorite_incidents')
        self.assertEqual(len(trace['incidents_expires_apres_classement']), 64)
        marqueur = next(call.args[1] for call in watch.poster.call_args_list
                        if call.args[1].get('phase') == 'priorite_incidents')
        self.assertNotIn('incident_id', marqueur)
        valider_evenement('marqueur', marqueur)
        public = json.loads(marqueur['texte'])
        self.assertIsNone(public['incident_choisi'])
        self.assertTrue(public['listes_resumees'])
        self.assertEqual(public['taille_lot'], 64)
        for key in ('ordre_entree', 'ordre_sortie', 'incidents_expires_apres_classement'):
            self.assertLessEqual(len(public[key]), 8)


if __name__ == '__main__':
    unittest.main()
