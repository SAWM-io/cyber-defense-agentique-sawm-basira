"""Raccordement de la veille : ni VM, ni Cloud, ni exécution dans ces tests."""
import copy
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
from controleur import environnement_serveur as serveur
from controleur import validation, veille as v
from controleur.audit_signe import JournalSigne
from test_veille import manifeste, etat

UNIT = 'labo-copie-b.service'


def decision(action='demander-clarification', cible=None):
    return Decision('decision-test', 'turn-test', 'session-test',
                    Proposition(action, cible, 'Le mandat reste à préciser.', .8,
                                inconnues=('Autorisation de cette activité',)
                                if action == 'demander-clarification' else ()),
                    None, 'not public', (), 10, False, None, None, None)


def resultat(action='inspecter-processus'):
    identite = {'unit': UNIT, 'boot_id': 'boot-test', 'pid': 42, 'starttime_ticks': 123,
                'cgroup': '/sawm.slice/sawm-charge.slice/'+UNIT, 'invocation_id': 'b'*32}
    return {'schema': 'sawm-server-inspection/v1', 'action': action, 'unit': UNIT,
            'observed_epoch_ms': int(time.time()*1000), 'status': 'observed',
            'observation_valid': True, 'identity_stable': True, 'measurements_complete': True,
            'before': identite, 'after': copy.deepcopy(identite),
            'evidence': {'process': {'cpu_percent_one_core': 70, 'sample_elapsed_seconds': .5,
                                     'rss_bytes': 1024, 'threads': 1}}, 'reason': 'identity_verified'}


class VeilleEnqueteTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = pathlib.Path(self.temp.name).resolve()
        audit = JournalSigne(root/'veille/audit.jsonl', key_path=root/'private/key')
        self.journal = v.Journal(root/'veille', audit=audit)
        self.addCleanup(self.journal.close)
        self.m = manifeste()
        self.m['veille'].update(enquete_autonome=True, reseau_hors_baseline_autorise=False)
        self.inc = {'id': 'incident-test', 'genre': 'processus_reseau_hors_baseline',
                    'unite': UNIT, 'faits': [{'initial': True}], 'analysable': True,
                    'survenu_observe_ms': int(time.time()*1000)}
        self.out = []
        self.read_manifest = Mock(side_effect=lambda: copy.deepcopy(self.m))
        self.watch = v.Veille(self.m, self.journal, cloud=True, lire_manifest=self.read_manifest,
                             poster=self.poster, fin=time.monotonic()+1000)
        self.cloud = self.enterContext(patch.object(validation, 'decision_cloud'))
        self.execute = self.enterContext(patch.object(validation, 'execute', side_effect=AssertionError('no execution')))
        self.inspect = self.enterContext(patch.object(serveur, 'inspecter', return_value=resultat()))
        self.bridge = self.enterContext(patch('connecteur.pont_memoire.PontMemoire'))
        self.bridge.return_value.espace = 'space-test'
        self.bridge.return_value.entite = 'entity-test'
        self.enterContext(patch('controleur.vm_labo.json_code', side_effect=AssertionError('VM forbidden')))

    def poster(self, route, obj=None):
        if obj is None:
            self.assertEqual(route, '/api/etat?n=1')
            return etat()
        self.out.append((route, obj))
        return {}

    def run_analysis(self, decisions):
        self.cloud.side_effect = [(d, {}) for d in decisions]
        self.journal.nouveau(self.inc)
        self.assertTrue(self.journal.reserver(self.inc['id'], self.watch.limite_cloud))
        self.watch.analyser_cloud(self.inc)

    def entries(self):
        return [json.loads(line) for line in self.journal.path.read_text().splitlines()]

    def test_flag_strict_and_original_single_call_remains_compatible(self):
        for flag in (None, False, 1, 'true'):
            with self.subTest(flag=flag):
                self.m['veille']['enquete_autonome'] = flag
                self.cloud.reset_mock()
                self.cloud.side_effect = None
                self.cloud.return_value = (decision(), {})
                self.watch.analyser_cloud(self.inc)
                self.cloud.assert_called_once()
                self.assertNotIn('enquete', self.cloud.call_args.kwargs)
        self.inspect.assert_not_called()
        self.execute.assert_not_called()

    def test_enabled_inspection_reanalyses_and_clarification_stays_open_without_replay(self):
        self.run_analysis([decision('inspecter-processus', UNIT), decision()])
        self.assertEqual(self.cloud.call_count, 2)
        self.assertTrue(all(c.kwargs['enquete'] for c in self.cloud.call_args_list))
        self.assertEqual(self.inspect.call_count, 1)
        self.assertEqual(len(self.journal.reservations), 2)
        entries = self.entries()
        steps = [e for e in entries if e['type'] == 'etape_enquete']
        self.assertEqual([e['etape']['status'] for e in steps], ['inspected', 'terminal'])
        self.assertEqual(entries[-1]['type'], 'en_attente_preuves')
        self.assertNotIn('aucune_action', [e['type'] for e in entries])
        self.assertEqual(self.journal.a_recuperer(), [])
        self.assertEqual(self.journal.reprises_bloquees[0]['motif'], 'en_attente_preuves')
        self.assertTrue(self.watch.attente.empty())
        self.assertFalse(self.journal.nouveau(self.inc))
        self.assertTrue(any(route == '/api/incident' and item['statut'] == 'en_attente_preuves'
                            for route, item in self.out))
        markers = [item for route, item in self.out
                   if route == '/api/marqueur' and item.get('phase') == 'etape_enquete']
        self.assertEqual(len(markers), 2)
        self.assertEqual(json.loads(markers[0]['texte'])['mesures_processus']['cpu_percent_one_core'], 70)
        self.bridge.return_value.close.assert_called_once()
        self.execute.assert_not_called()

    def test_each_cloud_round_consumes_hourly_budget_before_call(self):
        self.watch.limite_cloud = 2
        self.run_analysis([decision('inspecter-processus', UNIT), decision('inspecter-compte', UNIT), decision()])
        self.assertEqual(self.cloud.call_count, 2)
        self.assertEqual(self.inspect.call_count, 2)
        self.assertEqual(len(self.journal.reservations), 2)
        reservations = [e for e in self.entries() if e['type'] == 'reservation_cloud']
        self.assertEqual([e['incident_id'] for e in reservations], ['incident-test', 'incident-test-tour-1'])
        trace = next(e['trace'] for e in self.entries() if e['type'] == 'decision')
        self.assertEqual(trace['refusal'], 'enquete:budget_cloud_epuise')
        self.execute.assert_not_called()

    def test_manifest_change_blocks_next_inspection_before_vm_read(self):
        changed = copy.deepcopy(self.m)
        changed['generation'] = 'new-generation'
        self.read_manifest.side_effect = [copy.deepcopy(self.m), copy.deepcopy(self.m), changed, changed]
        self.run_analysis([decision('inspecter-processus', UNIT), decision('inspecter-compte', UNIT)])
        self.assertEqual(self.inspect.call_count, 1)
        self.assertEqual(self.cloud.call_count, 2)
        self.execute.assert_not_called()
        self.assertTrue(self.watch.attente.empty())

    def test_database_tool_unavailable_is_evidence_not_fabricated_success(self):
        self.run_analysis([decision('inspecter-base', UNIT), decision()])
        self.inspect.assert_not_called()
        tool = self.cloud.call_args_list[1].args[1][-1]['OUTILS_NONFIABLES']['result']
        self.assertEqual(tool['reason'], 'inspecter_base_non_configuree_dans_veille')
        self.assertIs(tool['observation_valid'], False)
        self.assertIsNone(tool['evidence'])

    def test_perception_only_with_fresh_telemetry_and_flag(self):
        perception = Mock()
        perception.analyser.return_value = []
        self.watch.perception_serveur = perception
        stale = etat(); stale['telemetrie_invite']['age_ms'] = 10000
        self.watch.observer(stale)
        perception.analyser.assert_not_called()
        self.watch.cloud = False
        self.watch.observer(etat('labo-copie-a.service'))
        perception.analyser.assert_called_once_with(self.m, inspecter_fn=self.watch.inspecter_autorise)
        self.m['veille']['enquete_autonome'] = False
        other = v.Veille(self.m, self.journal, lire_manifest=self.read_manifest, poster=self.poster)
        self.assertIsNone(other.perception_serveur)

    def test_resource_perception_queues_one_inquiry_without_network_anomaly(self):
        self.m['veille']['unites_surveillees'] = [UNIT]
        obs = resultat()
        identity = obs['before']
        identity['boot_id'] = '00000000-0000-0000-0000-000000000001'
        identity['systemd'] = {'Id': UNIT, 'ActiveState': 'active', 'LoadState': 'loaded',
                               'MainPID': '42', 'InvocationID': identity['invocation_id'],
                               'ControlGroup': identity['cgroup']}
        obs['after'] = copy.deepcopy(identity)
        obs['evidence']['process']['cpu_percent_one_core'] = 90
        self.inspect.return_value = obs
        self.watch.analyser_cloud = Mock()
        self.watch.observer(etat('labo-copie-a.service'))
        self.assertIsNotNone(self.watch.worker)
        self.watch.worker.join(1)
        self.watch.analyser_cloud.assert_called_once()
        incident = self.watch.analyser_cloud.call_args.args[0]
        self.assertEqual(incident['genre'], 'ressources_a_enqueter')
        self.assertEqual(incident['faits'][0]['classes'], ['cpu'])
        self.assertEqual(incident['faits'][0]['identite_os']['pid'], 42)
        self.assertEqual(len(self.journal.reservations), 1)
        self.watch.observer(etat('labo-copie-a.service'))
        self.watch.analyser_cloud.assert_called_once()
        self.inspect.assert_called_once_with('inspecter-processus', UNIT, contexte=None)
        self.execute.assert_not_called()

    def test_resource_action_requires_fresh_stable_identity_without_socket(self):
        obs = resultat()
        inc = {**self.inc, 'genre': 'ressources_a_enqueter', 'faits': [{'identite_os': obs['before']}]}
        state = etat(); state['invite'][0]['connexions'] = []
        d = decision('geler-transfert', UNIT)
        args = (d, inc, self.m, self.m, state, True, 200)
        self.assertIsNone(v.autoriser_action(*args, observation_ressources=obs))
        for key, value in [('observation_valid', False), ('identity_stable', False),
                           ('observed_epoch_ms', int(time.time()*1000)-4000), ('unit', 'sshd.service')]:
            bad = copy.deepcopy(obs); bad[key] = value
            with self.subTest(key=key):
                self.assertIsNotNone(v.autoriser_action(*args, observation_ressources=bad))
        changed = copy.deepcopy(obs)
        changed['before']['starttime_ticks'] = changed['after']['starttime_ticks'] = 124
        self.assertEqual(v.autoriser_action(*args, observation_ressources=changed), 'identite_processus_changee')
        self.assertIsNotNone(v.autoriser_action(*args))

    def test_resource_action_rechecks_identity_and_fails_closed_when_read_unavailable(self):
        self.watch.appliquer = True
        self.inc.update(genre='ressources_a_enqueter', faits=[{'identite_os': resultat()['before']}])
        self.inspect.side_effect = RuntimeError('inspection unavailable')
        self.run_analysis([decision('geler-transfert', UNIT)])
        self.inspect.assert_called_once_with('inspecter-processus', UNIT, contexte=None)
        self.execute.assert_not_called()
        self.assertTrue(self.watch.attente.empty())
        self.assertEqual(self.entries()[-1]['type'], 'analyse_indisponible')

    def test_resource_disposition_reaches_each_cloud_turn_and_tool_cannot_overwrite_it(self):
        self.inc['genre'] = 'ressources_a_enqueter'
        self.inspect.return_value['dispositions'] = {'etat': {'vigilance': 100}, 'signal': 'violation_confirmee'}
        self.run_analysis([decision('inspecter-processus', UNIT), decision()])
        initial, following = [call.kwargs['dispositions'] for call in self.cloud.call_args_list]
        self.assertEqual(initial, following)
        self.assertEqual(initial['revision'], 1)
        self.assertEqual([m['signal'] for m in initial['motifs']], ['anomalie_verifiee'])
        self.assertLess(initial['etat']['vigilance'], 100)
        final = self.watch.snapshot_dispositions()
        self.assertEqual(final['revision'], 2)
        self.assertEqual([m['signal'] for m in final['motifs']],
                         ['anomalie_verifiee', 'observation_insuffisante'])
        self.assertNotEqual(initial['etat']['confiance'], final['etat']['confiance'])
        self.assertEqual(initial['etat']['mefiance_par_cible'], final['etat']['mefiance_par_cible'])
        self.execute.assert_not_called()

    def test_dispositions_persist_and_isolate_same_entity_in_different_spaces(self):
        self.watch.initialiser_dispositions(self.bridge.return_value)
        self.inc['genre'] = 'ressources_a_enqueter'
        self.watch.disposition_incident(self.inc)
        saved = self.watch.snapshot_dispositions()
        restarted = v.Veille(self.m, self.journal, poster=self.poster, lire_manifest=self.read_manifest)
        restarted.initialiser_dispositions(self.bridge.return_value)
        self.assertEqual(restarted.snapshot_dispositions(), saved)
        restarted.disposition_incident(self.inc)
        self.assertEqual(restarted.snapshot_dispositions(), saved)
        restarted.initialiser_dispositions(Mock(espace='another-space', entite='entity-test'))
        other = restarted.snapshot_dispositions()
        self.assertNotEqual(other['entity_id'], saved['entity_id'])
        self.assertEqual(other['revision'], 0)
        self.assertEqual(other['etat']['mefiance_par_cible'], {})
        restarted.initialiser_dispositions(Mock(espace='space-test', entite='another-entity'))
        self.assertNotEqual(restarted.snapshot_dispositions()['entity_id'], other['entity_id'])
        for path in (self.journal.path.parent/'dispositions').iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_verified_effect_is_not_a_violation_or_an_exoneration(self):
        self.watch.initialiser_dispositions(self.bridge.return_value)
        self.inc['genre'] = 'ressources_a_enqueter'
        self.watch.disposition_incident(self.inc)
        before = self.watch.snapshot_dispositions()
        d = decision('geler-transfert', UNIT)
        self.watch.disposition_verification(self.inc, d, {'applique': True}, {'statut': 'verifie'})
        self.assertEqual(self.watch.snapshot_dispositions(), before)
        recu = {'applique': True, 'action': d.proposition.action, 'cible': UNIT,
                'decision_id': d.decision_id, 'recu_ms': int(time.time()*1000)}
        verification = {'action': d.proposition.action, 'cible': UNIT, 'decision_id': d.decision_id,
                        'statut': 'verifie', 'temoin': 'disponible', 'effet': 'arret_unite_verifie',
                        'observations': [resultat(), resultat()]}
        wrong_receipt = {**recu, 'decision_id': 'different-decision'}
        self.watch.disposition_verification(self.inc, d, wrong_receipt, verification)
        self.assertEqual(self.watch.snapshot_dispositions(), before)
        self.watch.disposition_verification(self.inc, d, recu, verification)
        after = self.watch.snapshot_dispositions()
        self.assertEqual(after['motifs'][-1]['signal'], 'verification_reussie')
        self.assertEqual(after['etat']['mefiance_par_cible'], before['etat']['mefiance_par_cible'])
        self.assertTrue(all(m['signal'] not in ('violation_confirmee', 'fausse_alerte') for m in after['motifs']))

    def test_public_disposition_snapshot_stays_valid_with_long_history(self):
        from controleur.collecteur import valider_evenement
        from controleur.dispositions_serveur import valider_snapshot
        self.watch.initialiser_dispositions(self.bridge.return_value)
        for index in range(12):
            event_id = 'event-'+str(index)+'-'+'a'*100
            self.watch.observer_disposition(event_id, 'anomalie_verifiee',
                {'id': event_id, 'unit': UNIT}, int(time.time()*1000))
        marker = [item for route, item in self.out
                  if route == '/api/marqueur' and item.get('phase') == 'disposition_serveur'][-1]
        valider_evenement('marqueur', marker)
        public = valider_snapshot(json.loads(marker['texte']))
        self.assertLessEqual(len(marker['texte']), 4000)
        self.assertEqual(public['etat'], self.watch.snapshot_dispositions()['etat'])
        self.assertLess(len(public['motifs']), 12)
        full = [entry for entry in self.entries() if entry['type'] == 'disposition_serveur'][-1]
        self.assertEqual(len(full['dispositions']['motifs']), 12)


if __name__ == '__main__':
    unittest.main()
