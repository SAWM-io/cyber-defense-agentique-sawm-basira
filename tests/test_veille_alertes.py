"""Alertes d'incertitude publiées et relues, sans Cloud réel ni accès VM."""
import copy
import dataclasses
import json
import pathlib
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from connecteur.contrat import Proposition
from connecteur.tour_sawm import Decision
from controleur import collecteur, validation, veille as v
from controleur.audit_signe import JournalSigne
from test_veille import manifeste, etat

UNIT = 'labo-copie-b.service'
PRIVATE_TEXT = 'PRIVATE_MODEL_TEXT_NEVER_PUBLIC'
PRIVATE_ERROR = 'PRIVATE_TRANSPORT_SECRET api_key=never-publish'


def decision(action='demander-clarification', cible=None):
    return Decision('decision-alert', 'turn-alert', 'session-alert',
        Proposition(action, cible, 'Le mandat de cette activité reste à établir.', .63,
            inconnues=('La fenêtre de maintenance autorise-t-elle cette activité ?',)
            if action == 'demander-clarification' else ()),
        None, PRIVATE_TEXT, (), 12, False, None, None, None)


class VeilleAlertesTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name).resolve()
        self.series = self.root/'releves/series'
        self.enterContext(patch.object(collecteur.Etat, '_versions', return_value={'collecteur': 'test'}))
        self.state = collecteur.Etat('alert-test', series=self.series, racine=self.root)
        audit = JournalSigne(self.root/'veille/audit.jsonl', key_path=self.root/'private/key')
        self.journal = v.Journal(self.root/'veille', audit=audit)
        self.addCleanup(self.journal.close)
        self.m = manifeste()
        self.m['veille'].update(reseau_hors_baseline_autorise=False)
        self.inc = {'id': 'incident-alert', 'genre': 'processus_reseau_hors_baseline',
            'unite': UNIT, 'faits': [{'constat_initial': 'socket observée', 'pid': 42}],
            'analysable': True, 'canal': 'incident', 'survenu_observe_ms': int(time.time()*1000)}
        self.publications, self.publication_errors = [], []
        self.watch = v.Veille(self.m, self.journal, cloud=True, appliquer=True,
            poster=self.poster, lire_manifest=lambda: copy.deepcopy(self.m),
            fin=time.monotonic()+300)
        self.cloud = self.enterContext(patch.object(validation, 'decision_cloud'))
        self.execute = self.enterContext(patch.object(validation, 'execute', side_effect=AssertionError('execution forbidden')))
        self.vm = self.enterContext(patch('controleur.vm_labo.json_code', side_effect=AssertionError('VM forbidden')))
        self.bridge = self.enterContext(patch('connecteur.pont_memoire.PontMemoire'))
        self.bridge.return_value.espace = 'space-alert'
        self.bridge.return_value.entite = 'entity-alert'

    def tearDown(self):
        self.execute.assert_not_called()
        self.vm.assert_not_called()
        self.assertEqual(self.publication_errors, [], 'Un événement public a été refusé par le collecteur')
        public = json.dumps(self.publications, ensure_ascii=False)
        self.assertNotIn(PRIVATE_TEXT, public)
        self.assertNotIn(PRIVATE_ERROR, public)

    def poster(self, route, obj=None):
        if obj is None:
            self.assertEqual(route, '/api/etat?n=1')
            return etat()
        try:
            genre = route.removeprefix('/api/')
            checked = collecteur.valider_evenement(genre, obj)
            getattr(self.state, 'ajouter_'+genre)(checked)
        except Exception as error:
            self.publication_errors.append(type(error).__name__)
            raise
        self.publications.append((route, copy.deepcopy(checked)))
        return {}

    def seed(self, inc=None):
        inc = self.inc if inc is None else inc
        self.assertTrue(self.journal.nouveau(inc))
        self.poster('/api/incident', {'id': inc['id'], 'titre': 'Observation à vérifier',
            'statut': 'a_verifier', 'faits': [json.dumps(f, ensure_ascii=False) for f in inc['faits']]})

    def check_alert(self, status, *, inc=None):
        inc = self.inc if inc is None else inc
        alert = self.state.incidents[inc['id']]
        self.assertEqual(alert['statut'], status)
        self.assertTrue(alert.get('raison_publique'))
        self.assertEqual(alert['id'], inc['id'])
        decoded = []
        for fact in alert.get('faits', []):
            try:
                decoded.append(json.loads(fact))
            except ValueError:
                pass
        for original in inc['faits']:
            self.assertIn(original, decoded, 'Les faits initiaux doivent survivre à la mise à jour')
        # Le vrai collecteur valide à nouveau chaque ligne lors du redémarrage.
        replay = collecteur.Etat('alert-replay', series=self.series, racine=self.root)
        self.assertEqual(replay.reprise['lignes_invalides'], 0)
        self.assertEqual(replay.incidents[inc['id']], alert)
        return alert

    def test_cloud_exception_publishes_unavailability_without_raw_secret_and_replays(self):
        self.seed()
        self.cloud.side_effect = RuntimeError(PRIVATE_ERROR)
        self.watch.analyser_cloud(self.inc)
        alert = self.check_alert('analyse_indisponible')
        self.assertIn('RuntimeError', json.dumps(alert))
        self.assertEqual(self.watch.echecs_cloud, 1)
        self.assertEqual(list(self.watch.attente.queue), [self.inc])
        self.cloud.assert_called_once()

    def test_clarification_keeps_unknowns_original_facts_and_open_status_after_replay(self):
        self.seed()
        self.m['veille']['enquete_autonome'] = True
        proposed = decision()
        self.cloud.return_value = (proposed, {})
        self.watch.analyser_cloud(self.inc)
        alert = self.check_alert('en_attente_preuves')
        body = json.dumps(alert, ensure_ascii=False)
        for unknown in proposed.proposition.inconnues:
            self.assertIn(unknown, body)
        self.assertTrue(self.watch.attente.empty())
        self.assertEqual(self.journal.a_recuperer(), [])
        self.assertFalse(any(item.get('statut') == 'resolu' for _, item in self.publications))

    def test_nonexecutable_cloud_proposal_publishes_review_without_private_model_text(self):
        self.seed()
        refused = dataclasses.replace(decision(), proposition=None,
            refus='proposition_invalide:json_absent')
        self.cloud.return_value = (refused, {})
        self.watch.analyser_cloud(self.inc)
        self.check_alert('a_revoir')
        self.assertTrue(self.watch.attente.empty())
        self.cloud.assert_called_once()

    def test_outside_mandate_restoration_is_visible_without_substituting_another_action(self):
        self.seed()
        self.m['veille']['enquete_autonome'] = True
        self.cloud.return_value = (decision('restaurer-fixtures', UNIT), {})
        self.watch.analyser_cloud(self.inc)
        alert = self.check_alert('a_revoir')
        self.assertIn('action_hors_mandat', json.dumps(alert))
        self.cloud.assert_called_once()
        self.assertTrue(self.watch.attente.empty())

    def test_expired_observation_is_published_without_cloud_budget_or_analysis(self):
        self.inc['survenu_observe_ms'] -= 600001
        self.seed()
        self.watch.attente.put_nowait(self.inc)
        self.watch.traiter_attente()
        self.check_alert('observation_expiree')
        self.cloud.assert_not_called()
        self.assertEqual(self.journal.reservations, [])
        self.assertTrue(self.watch.attente.empty())

    def test_observations_expiring_during_ranking_are_each_published_and_not_charged(self):
        wall_ms = int(time.time()*1000)
        clock = [wall_ms]
        inputs = [dict(copy.deepcopy(self.inc), id='expired-'+str(i),
                       survenu_observe_ms=wall_ms-599900) for i in range(2)]
        for inc in inputs:
            self.seed(inc)
            self.watch.attente.put_nowait(inc)
        def rank(_candidates):
            clock[0] += 200
            return {'schema': 'basira-odvl-ranking/v1', 'ranking': [
                {'candidate_id': inc['id'], 'rank': i+1} for i, inc in enumerate(inputs)]}
        self.bridge.return_value.hierarchiser.side_effect = rank
        with patch.object(v.time, 'time', side_effect=lambda: clock[0]/1000):
            self.watch.traiter_attente()
        for inc in inputs:
            self.check_alert('observation_expiree', inc=inc)
        self.cloud.assert_not_called()
        self.assertEqual(self.journal.reservations, [])
        self.assertTrue(self.watch.attente.empty())

    def test_zero_cloud_budget_publishes_pending_budget_and_preserves_queue(self):
        self.seed()
        self.watch.limite_cloud = 0
        self.watch.attente.put_nowait(self.inc)
        self.watch.traiter_attente()
        self.check_alert('attente_budget')
        self.cloud.assert_not_called()
        self.assertEqual(self.journal.reservations, [])
        self.assertEqual(list(self.watch.attente.queue), [self.inc])

    def test_attention_helper_only_publishes_without_adding_audit_events(self):
        self.seed()
        before = self.journal.path.read_bytes()
        self.watch.publier_attention(self.inc, 'a_revoir', 'Une vérification indépendante reste nécessaire.',
            decision=decision(), details=({'preuve_manquante': 'attribution noyau'},))
        self.check_alert('a_revoir')
        self.assertEqual(self.journal.path.read_bytes(), before)
        self.cloud.assert_not_called()


if __name__ == '__main__':
    unittest.main()
