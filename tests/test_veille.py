"""Détection et décisions sûres, sans VM, Cloud ni serveur HTTP."""
import copy
import importlib.util
import json
import pathlib
import tempfile
import time
import types
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1]/'controleur/veille.py'
spec = importlib.util.spec_from_file_location('veille_test', SCRIPT)
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


def manifeste():
    return {'generation': 'protection-1', '_sha256': 'a'*64,
            'unites_autorisees': ['labo-copie-b.service'],
            'unites_protegees': ['labo-copie-a.service'],
            'veille': {'unites_connues': ['labo-copie-a.service', 'labo-recepteur.service'],
                       'sources_connues': ['source-a'],
                       'actions_automatiques': ['geler-transfert']}}


def etat(unite='labo-copie-b.service', pid=42):
    return {'mode': 'DIRECT', 'telemetrie_invite': {'connectee': True, 'age_ms': 30},
            'invite': [{'capteurs': {'ebpf_exec_actif': True, 'lsm_attache': True},
                        'connexions': [{'pid': pid, 'cgroup': '0::/sawm.slice/sawm-charge.slice/'+unite,
                                        'locale': '127.0.0.1:43000', 'distante': '127.0.0.1:9009',
                                        'etat': 'ESTAB', 'processus': 'untrusted secret omitted'}],
                        'recepteur': {'flux': {}}}]}


class VeilleTest(unittest.TestCase):
    def test_detect_unknown_unit_without_scenario_label(self):
        inc = v.Detecteur().analyser(etat(), manifeste())
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]['unite'], 'labo-copie-b.service')
        self.assertTrue(inc[0]['analysable'])
        self.assertFalse(inc[0]['faits'][0]['identite_processus_complete'])
        self.assertNotIn('untrusted secret', str(inc))

    def test_known_service_does_not_alert_for_new_pid(self):
        self.assertEqual(v.Detecteur().analyser(etat('labo-copie-a.service', 999), manifeste()), [])

    def test_sender_source_is_not_an_os_identity(self):
        e = etat('labo-copie-a.service')
        e['invite'][0]['recepteur']['flux']['declared-run:source-b:1'] = {
            'source_id': 'source-b', 'run_id': 'attack-scenario-not-forwarded',
            'recus': 500, 'etat': 'en_cours', 'debut_ms': 100}
        inc = v.Detecteur().analyser(e, manifeste())
        self.assertEqual(len(inc), 1)
        self.assertFalse(inc[0]['analysable'])
        self.assertIsNone(inc[0]['unite'])
        self.assertNotIn('attack-scenario', str(inc))

    def test_missing_baseline_does_not_invent_knowledge(self):
        self.assertEqual(v.Detecteur().analyser(etat(), {})[0]['genre'], 'baseline_absente')

    def test_hidden_file_is_observation_not_automatic_attack(self):
        e = etat('labo-copie-a.service')
        e['invite'][0]['fichiers'] = {
            'source': 'inotify', 'perimetre': '/opt/sawm-labo/fixtures',
            'pertes_file': 0, 'attribution_pid': False,
            'evenements': [{'mur_epoch_ms': 100, 'chemin': '.dossier/nouveau.txt',
                            'operations': ['creation'], 'pid': None, 'cookie': 0}]}
        inc = v.Detecteur().analyser(e, manifeste())
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]['genre'], 'activite_fichier_observee')
        self.assertFalse(inc[0]['analysable'])
        self.assertIsNone(inc[0]['unite'])

    def test_inotify_losses_are_explicit(self):
        e = etat('labo-copie-a.service')
        e['invite'][0]['fichiers'] = {'source': 'inotify', 'pertes_file': 3,
                                    'evenements': [], 'erreur': None}
        inc = v.Detecteur().analyser(e, manifeste())
        self.assertEqual(inc[0]['genre'], 'pertes_capteur_fichiers')
        self.assertEqual(inc[0]['faits'][0]['pertes_file'], 3)

    def test_time_wait_without_pid_is_one_coverage_observation_not_incidents(self):
        e = etat('labo-copie-a.service')
        e['invite'][0]['connexions'] += [
            {'pid': None, 'etat': 'TIME-WAIT', 'locale': '127.0.0.1:8080',
             'distante': '127.0.0.1:' + str(40000 + n)} for n in range(70)]
        events = v.Detecteur().analyser(e, manifeste())
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['genre'], 'couverture_attribution_sockets')
        self.assertEqual(events[0]['canal'], 'observation')
        self.assertFalse(events[0]['analysable'])
        self.assertEqual(events[0]['faits'][0]['nombre_echantillonne'], 70)
        self.assertEqual(len(events[0]['faits'][0]['groupes']), 1)

    def test_closed_sockets_and_benign_files_publish_markers_no_cloud(self):
        e = etat('labo-copie-a.service')
        e['invite'][0]['connexions'].append({'pid': None, 'etat': 'SYN-RECV',
            'locale': '127.0.0.1:9009', 'distante': '127.0.0.1:43000'})
        e['invite'][0]['fichiers'] = {'source': 'inotify', 'pertes_file': 0,
            'evenements': [{'chemin': 'document.txt', 'operations': ['lecture']},
                           {'chemin': '.cache/fichier', 'operations': ['creation']}]}
        with tempfile.TemporaryDirectory() as tmp:
            j = v.Journal(pathlib.Path(tmp))
            out = []
            veille = v.Veille(manifeste(), j, cloud=True, poster=lambda route, obj: out.append((route, obj)))
            veille.observer(e)
            self.assertEqual(len(out), 3)
            self.assertTrue(all(route == '/api/marqueur' for route, _ in out))
            self.assertIsNone(veille.worker)
            self.assertEqual(j.reservations, [])
            e['invite'][0]['connexions'][-1]['distante'] = '127.0.0.1:45000'
            veille.observer(e)
            self.assertEqual(len(out), 3)
            self.assertTrue(all(json.loads(line)['type'] in ('observation', 'etat_capteurs')
                                for line in j.path.read_text().splitlines()))
            j.close()

    def test_stale_and_replay_are_degraded_not_silence(self):
        e = etat()
        e['telemetrie_invite']['age_ms'] = 10000
        self.assertEqual(v.Detecteur().analyser(e, manifeste())[0]['genre'], 'telemetrie_indisponible')
        e['mode'] = 'REJEU'
        self.assertEqual(v.Detecteur().analyser(e, manifeste())[0]['genre'], 'mode_non_direct')

    def test_observation_publishes_once_no_cloud_or_execute(self):
        with tempfile.TemporaryDirectory() as tmp:
            j = v.Journal(pathlib.Path(tmp))
            out = []
            veille = v.Veille(manifeste(), j, poster=lambda route, obj: out.append((route, obj)))
            veille.observer(etat())
            veille.observer(etat())
            self.assertEqual(len(out), 1)
            self.assertEqual(out[0][0], '/api/incident')
            self.assertIsNone(veille.worker)
            self.assertEqual(j.reservations, [])
            j.close()

    def test_budget_survives_restart_and_reserves_before_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            dossier = pathlib.Path(tmp)
            j = v.Journal(dossier)
            for i in range(4):
                self.assertTrue(j.reserver(str(i), maintenant=time.time()))
            self.assertFalse(j.reserver('5'))
            j.close()
            j = v.Journal(dossier)
            self.assertFalse(j.reserver('6'))
            self.assertTrue(j.reserver('7', maintenant=time.time()+3601))
            j.close()

    def test_singleton_preserves_global_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            j = v.Journal(pathlib.Path(tmp))
            with self.assertRaises(BlockingIOError):
                v.Journal(pathlib.Path(tmp))
            j.close()

    def test_cloud_worker_only_for_new_meaningful_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            j = v.Journal(pathlib.Path(tmp))
            called = []
            veille = v.Veille(manifeste(), j, cloud=True, poster=lambda *_: {})
            veille.analyser_cloud = lambda inc: called.append(inc['id'])
            veille.observer(etat())
            veille.worker.join(1)
            veille.observer(etat())
            self.assertEqual(len(called), 1)
            self.assertEqual(len(j.reservations), 1)
            j.close()

    def test_action_requires_all_authority_and_freshness_checks(self):
        m = manifeste()
        e = etat(); e['invite'][0]['boot_id'] = 'boot-test'
        e['invite'][0]['connexions'][0]['starttime'] = 123
        identity = {'boot_id': 'boot-test', 'pid': 42, 'starttime': 123,
                    'cgroup': e['invite'][0]['connexions'][0]['cgroup']}
        inc = {'unite': 'labo-copie-b.service', 'faits': [{'identite_os': identity}]}
        d = types.SimpleNamespace(executable=True, proposition=types.SimpleNamespace(
            action='geler-transfert', cible='labo-copie-b.service'))
        self.assertIsNone(v.autoriser_action(d, inc, m, m, e, True, 200))
        changed = copy.deepcopy(e); changed['invite'][0]['connexions'][0]['starttime'] = 124
        self.assertEqual(v.autoriser_action(d, inc, m, m, changed, True, 200), 'identite_processus_changee')
        self.assertIsNotNone(v.autoriser_action(d, inc, m, m, etat(), False, 200))
        self.assertIsNotNone(v.autoriser_action(d, inc, m, m, etat(), True, 100))
        current = copy.deepcopy(m)
        current['generation'] = 'new-generation'
        self.assertIsNotNone(v.autoriser_action(d, inc, m, current, etat(), True, 200))
        current = copy.deepcopy(m)
        current['veille']['actions_automatiques'] = []
        self.assertIsNotNone(v.autoriser_action(d, inc, current, current, etat(), True, 200))
        self.assertIsNotNone(v.autoriser_action(d, {'unite': None}, m, m, etat(), True, 200))
        self.assertIsNotNone(v.autoriser_action(d, inc, m, m, etat('labo-copie-a.service'), True, 200))
        replay = etat()
        replay['mode'] = 'REJEU'
        self.assertIsNotNone(v.autoriser_action(d, inc, m, m, replay, True, 200))

    def test_protected_service_excluded_even_if_allowed_list_mistake(self):
        m = manifeste()
        m['unites_autorisees'] += ['labo-temoin.service', 'labo-copie-a.service']
        self.assertEqual(v.ressources(m), ['labo-copie-b.service'])


if __name__ == '__main__':
    unittest.main()
