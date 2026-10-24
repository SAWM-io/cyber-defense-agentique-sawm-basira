"""Tests sans VM, sans réseau externe, sans secret et sans service en production."""
import importlib.util
import json
import pathlib
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch
from http.server import ThreadingHTTPServer

SPEC = importlib.util.spec_from_file_location('collecteur', pathlib.Path(__file__).parents[1] / 'controleur' / 'collecteur.py')
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class EtatTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.series = self.root / 'releves' / 'series'
        self.versions = patch.object(c.Etat, '_versions', return_value={'collecteur': 'test'})
        self.versions.start()
        self.etat = c.Etat('run-test', series=self.series, racine=self.root)

    def tearDown(self):
        self.versions.stop()
        self.tmp.cleanup()

    def test_tous_les_appels_pagination_reprise_et_deduplication(self):
        for i in range(173):
            self.etat.ajouter_appel_cloud({'event_id': f'e-{i}', 'appel': 'GET /jobs', 'statut': 202, 'ms': i, 'tentative': 1})
        self.etat.ajouter_appel_cloud({'event_id': 'e-0', 'appel': 'GET /jobs', 'statut': 500})
        s = self.etat.instantane()
        self.assertEqual(s['cumuls_cloud']['appels'], 173)
        self.assertEqual(s['cumuls_cloud']['reussis'], 173)
        self.assertEqual(s['cumuls_cloud']['latence_mediane_ms'], 86)
        self.assertEqual(len(s['appels_cloud']), 50)
        self.assertIsNone(s['cumuls_cloud']['jetons_total'])
        appels, avant = [], None
        while True:
            page = self.etat.historique_cloud(avant, 50)
            appels.extend(page['appels'])
            avant = page['avant']
            if avant is None:
                break
        self.assertEqual(len(appels), 173)
        self.assertEqual({a['event_id'] for a in appels}, {f'e-{i}' for i in range(173)})
        reprise = c.Etat('run-suivant', series=self.series, racine=self.root)
        self.assertEqual(reprise.instantane()['cumuls_cloud'], s['cumuls_cloud'])
        reprise.ajouter_appel_cloud({'event_id': 'e-0', 'appel': 'GET /jobs', 'statut': 500})
        self.assertEqual(reprise.instantane()['cumuls_cloud']['appels'], 173)
        self.assertFalse((self.series / 'run-suivant.jsonl').exists())

    def test_statuts_sse_et_jetons_rejoues(self):
        for a in [
            {'appel': 'SSE', 'statut': 200, 'resultat': 'stream_error'},
            {'appel': 'GET', 'statut': None, 'resultat': 'transport_error'},
            {'appel': 'POST', 'statut': 201, 'resultat': 'ok', 'jetons_total': 12, 'jetons_entree': 8},
            {'appel': 'SSE', 'statut': 200, 'resultat': 'ok', 'jetons_total': 12, 'replayed': True},
            {'appel': 'historique', 'statut': None},
        ]:
            self.etat.ajouter_appel_cloud(a)
        s = self.etat.instantane()['cumuls_cloud']
        self.assertEqual((s['reussis'], s['erreurs'], s['inconnus']), (2, 2, 1))
        self.assertEqual(s['jetons_total'], 12)
        self.assertEqual(s['jetons_entree'], 8)
        self.assertIsNone(s['jetons_sortie'])
        self.assertEqual(s['rejoues'], 1)
        self.assertEqual(s['appels_avec_jetons'], 2)

    def test_journal_tronque_reprise_et_append(self):
        self.etat.ajouter_appel_cloud({'appel': 'ok', 'statut': 200})
        with self.etat.fichier.open('ab') as f:
            f.write(b'null\n[]\n{"genre":')
        reprise = c.Etat('run-test', series=self.series, racine=self.root)
        self.assertEqual(reprise.reprise['lignes_invalides'], 3)
        reprise.ajouter_appel_cloud({'appel': 'apres', 'statut': 200})
        deux = c.Etat('run-test', series=self.series, racine=self.root)
        self.assertEqual(deux.instantane()['cumuls_cloud']['appels'], 2)
        self.assertEqual([a['appel'] for a in deux.historique_cloud()['appels']], ['ok', 'apres'])

    def test_incident_decision_mise_a_jour_et_validation(self):
        self.etat.ajouter_incident({'id': 'inc-1', 'titre': 'Constat', 'statut': 'ouvert', 'faits': ['octets observés']})
        self.etat.ajouter_incident({'id': 'inc-1', 'titre': 'Constat', 'statut': 'clos'})
        self.etat.ajouter_decision({'id': 'dec-1', 'action': 'ne-rien-faire', 'statut': 'proposée', 'raison_publique': 'Témoin autorisé', 'incident_id': 'inc-1'})
        reprise = c.Etat('run-test', series=self.series, racine=self.root)
        self.assertEqual(len(reprise.instantane()['incidents']), 1)
        self.assertEqual(reprise.instantane()['incidents'][0]['statut'], 'clos')
        self.assertEqual(reprise.instantane()['decisions'][0]['raison_publique'], 'Témoin autorisé')
        with self.assertRaises(ValueError):
            reprise.ajouter_decision({'id': 'x', 'action': 'a', 'statut': 's', 'raison_publique': 'r', 'commande': 'shell'})
        with self.assertRaises(ValueError):
            reprise.ajouter_appel_cloud({'appel': 'x', 'ms': float('nan')})
        with self.assertRaises(ValueError):
            reprise.ajouter_appel_cloud({'appel': 'x', 'replayed': 'true'})
        with self.assertRaises(ValueError):
            c.Etat('../hors', series=self.series, racine=self.root)

    def test_telemetrie_age_manquants_et_objets_bornes(self):
        self.assertIsNone(self.etat.instantane()['telemetrie_invite']['age_ms'])
        self.assertFalse(self.etat.instantane()['telemetrie_invite']['connectee'])
        with patch.object(c, 'maintenant_ms', return_value=1000):
            self.etat.ajouter_invite({'mur_epoch_ms': 1000, 'memoire': {'utilisee_o': None}})
        with patch.object(c, 'maintenant_ms', return_value=4000):
            e = self.etat.instantane()
        self.assertEqual(e['telemetrie_invite']['age_ms'], 3000)
        self.assertFalse(e['telemetrie_invite']['connectee'])
        self.assertIsNone(e['invite'][0]['memoire']['utilisee_o'])
        with self.assertRaises(ValueError):
            self.etat.ajouter_invite([])
        with self.assertRaises(ValueError):
            self.etat.ajouter_invite({'liste': [0] * 1001})

    def test_preuves_allowlist_et_symlinks(self):
        rapports = self.root / 'releves' / 'rapports'
        rapports.mkdir()
        (rapports / 'rapport-test.html').write_text('<h1>Preuve</h1>')
        (self.root / 'releves' / 'preuve-test.txt').write_text('ok')
        (self.root / 'secret.txt').write_text('NE PAS SERVIR')
        (rapports / 'lien.txt').symlink_to(self.root / 'secret.txt')
        self.assertEqual(len(self.etat.preuves()), 2)
        for p in ['../secret.txt', 'releves/../secret.txt', '/etc/passwd', 'releves/rapports/.env', 'releves/series/run-test.jsonl', 'releves/secret.txt', 'releves/rapports/lien.txt']:
            with self.subTest(p=p), self.assertRaises(ValueError):
                c.preuve_autorisee(p, self.root)


class HTTPTests(unittest.TestCase):
    def setUp(self):
        EtatTests.setUp(self)
        self.handler = type('TestService', (c.Service,), {'etat': self.etat})
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), self.handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f'http://127.0.0.1:{self.server.server_port}'

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        EtatTests.tearDown(self)

    def request(self, path, body=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, headers=headers or ({'Content-Type': 'application/json'} if data else {}))
        try:
            return urllib.request.urlopen(req, timeout=2)
        except urllib.error.HTTPError as e:
            return e

    def test_http_validation_sans_mutation(self):
        for body, code in [([], 400), ({'appel': 'test'}, 200), ({'appel': 'test', 'secret': 'forbidden'}, 400)]:
            with self.request('/api/cloud', body) as r:
                self.assertEqual(r.status, code)
        self.assertEqual(self.etat.instantane()['cumuls_cloud']['appels'], 1)
        with self.request('/api/cloud', {'appel': 'bad'}, {'Content-Type': 'text/plain'}) as r:
            self.assertEqual(r.status, 415)
        with self.request('/api/cloud', {'appel': 'bad'}, {'Content-Type': 'application/json', 'Origin': 'https://externe.invalid'}) as r:
            self.assertEqual(r.status, 403)
        with self.request('/api/etat-autre') as r:
            self.assertEqual(r.status, 404)
        with self.request('/api/etat?n=oops') as r:
            self.assertEqual(r.status, 400)
        with self.request('/api/cloud', {'appel': 'x' * c.MAX_CORPS}) as r:
            self.assertEqual(r.status, 413)

    def test_console_delegue_avec_origine_locale_obligatoire(self):
        class OperateurFactice:
            def __init__(self):
                self.commandes = []

            def etat(self):
                return {'schema': 'sawm-operateur/v1', 'actif': False, 'operation': None}

            def traite(self, corps):
                self.commandes.append(corps)
                return {'ok': True, **self.etat()}

        operateur = OperateurFactice()
        self.handler.operateur = operateur
        corps = {'action': 'lancer', 'scenario': 'transfert', 'volume_gio': 1}
        with self.request('/api/operateur', corps) as r:
            self.assertEqual(r.status, 403)
        self.assertEqual(operateur.commandes, [])
        with self.request('/api/operateur', corps, {'Content-Type': 'application/json', 'Origin': self.base}) as r:
            self.assertEqual(r.status, 200)
            self.assertEqual(json.load(r)['schema'], 'sawm-operateur/v1')
        self.assertEqual(operateur.commandes, [corps])
        with self.request('/api/operateur') as r:
            self.assertFalse(json.load(r)['actif'])

    def test_http_rapport_sandbox_et_traversee(self):
        rapports = self.root / 'releves' / 'rapports'
        rapports.mkdir()
        (rapports / 'preuve.html').write_text('<script>alert(1)</script>')
        with self.request('/api/preuve?f=releves%2Frapports%2Fpreuve.html') as r:
            self.assertEqual(r.status, 200)
            self.assertIn('sandbox;', r.headers['Content-Security-Policy'])
            self.assertEqual(r.headers['X-Content-Type-Options'], 'nosniff')
        with self.request('/api/preuve?f=releves%2F..%2Fsecret.txt') as r:
            self.assertEqual(r.status, 400)
        with self.request('/api/cloud?limite=999999') as r:
            self.assertLessEqual(len(json.load(r)['appels']), 100)


class HoteTests(unittest.TestCase):
    def test_qemu_uuid_exact_exclut_autre_vm(self):
        def commande(args, **kwargs):
            if args[:2] == ['ps', '-axo']:
                text = '42 95.0 9000 /x/qemu-aarch64-softmmu -uuid AUTRE-VM\n43 7.0 2048 /x/qemu-aarch64-softmmu -uuid ' + c.VM_UUID
            elif args[:2] == ['utmctl', 'status']:
                self.assertEqual(args[2], c.VM_UUID)
                text = 'started'
            else:
                text = '1.0 1024'
            return type('Result', (), {'stdout': text, 'returncode': 0})()
        with patch.object(c.subprocess, 'run', side_effect=commande):
            h = c.mesurer_hote(None)
        self.assertEqual(h['qemu']['pid'], 43)
        self.assertEqual(h['qemu']['rss_o'], 2048 * 1024)
        self.assertEqual(h['qemu']['cpu_pct'], 7)

    def test_qemu_introuvable_reste_inconnu(self):
        with patch.object(c.subprocess, 'run', return_value=type('Result', (), {'stdout': '42 95.0 9000 /x/qemu-aarch64-softmmu -uuid AUTRE-VM', 'returncode': 0})()):
            h = c.mesurer_hote(None)
        self.assertIsNone(h['qemu']['cpu_pct'])
        self.assertIsNone(h['qemu']['pid'])


if __name__ == '__main__':
    unittest.main()
