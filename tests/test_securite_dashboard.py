"""Vue de sécurité : vraie vérification, seuil de fraîcheur et aucune clé privée."""
import importlib.util
import json
import pathlib
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from controleur.audit_signe import JournalSigne
spec = importlib.util.spec_from_file_location('collecteur_securite', ROOT/'controleur/collecteur.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class SecuriteTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.dossier = self.root/'releves/veille'
        self.dossier.mkdir(parents=True)
        self.key = self.root/'secret/ed25519.key'
        self.journal = JournalSigne(self.dossier/'audit.jsonl', key_path=self.key)
        self.journal.append({'type': 'observation', 'fait': 'fixture'})
        self.now = 1000.0
        self.mono = 10.0
        self.vue = c.EtatSecurite(self.root, public_key_path=str(self.key)+'.pub',
                                 horloge=lambda: self.now, monotone=lambda: self.mono)
        self.ecrire()

    def ecrire(self, **extra):
        obj = {'schema': 'sawm-veille/v2', 'mur_epoch_ms': 1000000,
               'mode': 'analyse_cloud', 'budget_analyses_par_heure': 4,
               'analyses_reservees_derniere_heure': 2, 'analyses_en_attente': 1,
               'repli_cloud_secondes': 30, 'analyse_en_cours': False,
               'journal_signe': True, 'private_key': 'NEVER_FORWARD',
               'erreur': 'SECRET_INTERNAL_ERROR'}
        obj.update(extra)
        (self.dossier/'etat.json').write_text(json.dumps(obj))

    def test_verified_chain_without_private_key_and_public_fields_only(self):
        self.key.unlink()
        out = self.vue.instantane()
        self.assertTrue(out['veille']['active'])
        self.assertTrue(out['audit']['valide'])
        self.assertEqual(out['audit']['seq'], 1)
        self.assertEqual(out['veille']['repli_cloud_secondes'], 30)
        self.assertNotIn('NEVER_FORWARD', str(out))
        self.assertNotIn('SECRET_INTERNAL_ERROR', str(out))
        self.assertNotIn(str(self.root), str(out))
        self.assertFalse(out['audit']['coffre_immuable'])
        self.assertFalse(out['audit']['ancre_externe_verifiee'])

    def test_heartbeat_stale_boundary_future_and_stopped_not_green(self):
        self.now = 1014.999
        self.assertTrue(self.vue.instantane()['veille']['active'])
        self.now = 1015
        self.assertFalse(self.vue.instantane()['veille']['active'])
        self.now = 999
        self.assertFalse(self.vue.instantane()['veille']['active'])
        self.now = 1000
        for mode in ('arretee', 'attente_manifeste', 'telemetrie_indisponible'):
            self.ecrire(mode=mode)
            self.assertFalse(self.vue.instantane()['veille']['active'])

    def test_missing_or_oversized_heartbeat_fail_closed(self):
        path = self.dossier/'etat.json'
        path.unlink()
        self.assertFalse(self.vue.instantane()['veille']['active'])
        path.write_text(' ' * 16385)
        self.assertFalse(self.vue.instantane()['veille']['active'])
        path.unlink()
        path.symlink_to(self.key)
        self.assertFalse(self.vue.instantane()['veille']['active'])

    def test_nan_or_unknown_mode_do_not_reach_response(self):
        self.ecrire(mode='<script>bad()</script>')
        out = self.vue.instantane()
        self.assertFalse(out['veille']['active'])
        self.assertNotIn('<script>', str(out))
        self.ecrire(repli_cloud_secondes=float('nan'))
        self.assertFalse(self.vue.instantane()['veille']['active'])
        json.dumps(self.vue.instantane(), allow_nan=False)

    def test_missing_proof_or_key_not_green(self):
        (self.dossier/'audit.jsonl').unlink()
        self.assertFalse(self.vue.instantane()['audit']['valide'])
        self.assertNotIn('secret', self.vue.instantane()['audit']['erreur'].lower())

    def test_tampering_and_truncation_fail_signature_verification(self):
        p = self.dossier/'audit.jsonl'
        original = p.read_bytes()
        p.write_bytes(original.replace(b'fixture', b'tamper!'))
        self.assertFalse(self.vue.instantane()['audit']['valide'])
        self.mono += 11
        p.write_bytes(b'')
        self.assertFalse(self.vue.instantane()['audit']['valide'])

    def test_integral_verification_cached_at_most_ten_seconds(self):
        first = self.vue.instantane()
        (self.dossier/'audit.jsonl').write_bytes(b'bad')
        self.now += 5
        self.mono += 5
        cached = self.vue.instantane()
        self.assertTrue(cached['audit']['valide'])
        self.assertEqual(cached['audit']['verifie_a_ms'], first['audit']['verifie_a_ms'])
        self.mono += 5
        self.assertFalse(self.vue.instantane()['audit']['valide'])

    def test_http_endpoint_readonly_and_no_state_measurement_lock(self):
        with patch.object(c.Etat, '_versions', return_value={}):
            etat = c.Etat('security-test', series=self.root/'series', racine=self.root)
        etat.securite = self.vue
        class Handler(c.Service):
            pass
        Handler.etat = etat
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        url = f'http://127.0.0.1:{server.server_port}/api/securite'
        try:
            # Le thread HTTP répond même si le verrou des mesures est pris ailleurs.
            with etat.verrou:
                with urllib.request.urlopen(url, timeout=2) as response:
                    out = json.load(response)
            self.assertTrue(out['audit']['valide'])
            request = urllib.request.Request(url, data=b'{}', headers={'Content-Type': 'application/json'})
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(request, timeout=2)
            self.assertEqual(cm.exception.code, 404)
            cm.exception.close()
        finally:
            server.shutdown()
            server.server_close()
            worker.join(2)

    def test_panel_uses_safe_text_and_discloses_copy_limit(self):
        html = (ROOT/'controleur/tableau.html').read_text()
        block = html.split('async function chargerSecurite()', 1)[1].split('async function rafraichir()', 1)[0]
        self.assertNotIn('innerHTML', block)
        self.assertIn('/api/securite', block)
        self.assertIn('texte("#securite-audit"', block)
        self.assertIn('Ce n’est pas un coffre immuable', html)


if __name__ == '__main__':
    unittest.main()
