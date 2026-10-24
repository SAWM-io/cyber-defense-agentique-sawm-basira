"""Charges bornées : aucune VM, aucun privilège, socket substituée."""
import importlib
import json
import pathlib
import socket
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

DOSSIER = pathlib.Path(__file__).resolve().parents[1]/'invite/charges_test'
sys.path.insert(0, str(DOSSIER))
transfert = importlib.import_module('transfert')
commun = importlib.import_module('commun')
tache = importlib.import_module('tache')
cpu = importlib.import_module('cpu')
fichiers = importlib.import_module('fichiers')


class SocketFactice:
    def __init__(self):
        self.header = b''
        self.payload = bytearray()
        self.max_chunk = 0

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def settimeout(self, *_):
        pass

    def sendall(self, data):
        self.header += data

    def send(self, data):
        self.max_chunk = max(self.max_chunk, len(data))
        n = min(len(data), 401)  # écritures courtes comme une vraie socket
        self.payload.extend(data[:n])
        return n

    def shutdown(self, *_):
        pass


class ChargesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.tmp.name).resolve()
        (self.base/'fixtures').mkdir()
        (self.base/'fixtures/a.txt').write_bytes(b'abcd'*1024)

    def tearDown(self):
        self.tmp.cleanup()

    def test_real_fixture_bytes_repeated_counted_and_bounded(self):
        sock = SocketFactice()
        with patch.object(transfert.socket, 'create_connection', return_value=sock) as connect:
            r = transfert.copier('a', 'run1', 20000, 1, 10_000_000, racine=self.base)
        self.assertEqual(connect.call_args.args[0], ('127.0.0.1', 9009))
        self.assertEqual(sock.header, b'ANNONCE 20000 a run1\n')
        self.assertEqual(bytes(sock.payload), (b'abcd'*5000))
        self.assertLessEqual(sock.max_chunk, 65536)
        self.assertEqual(r['octets_envoyes'], 20000)
        self.assertEqual(r['octets_uniques_fixture'], 4096)
        self.assertEqual(r['cause_fin'], 'fin_naturelle_volume')
        self.assertEqual(r['attribution_arret'], 'non_etablie')
        self.assertEqual(json.loads((self.base/'charges-etat/a.json').read_text())['cause_fin'],
                         'fin_naturelle_volume')

    def test_duration_stop_is_not_sawm_interruption(self):
        sock = SocketFactice()
        with patch.object(transfert.socket, 'create_connection', return_value=sock):
            debut = time.monotonic()
            r = transfert.copier('a', 'run1', 20000, .08, 100, racine=self.base)
        self.assertLess(time.monotonic()-debut, .3)
        self.assertLess(r['octets_envoyes'], 20000)
        self.assertEqual(r['cause_fin'], 'fin_naturelle_duree')
        self.assertEqual(r['attribution_arret'], 'non_etablie')

    def test_limits_checked_before_any_connection(self):
        for octets, duree, debit in ((0, 1, 10), (commun.MAX_OCTETS+1, 1, 10),
                                     (10, 301, 10), (10, 1, commun.MAX_DEBIT+1)):
            with patch.object(transfert.socket, 'create_connection', side_effect=AssertionError('réseau interdit')):
                with self.assertRaises(ValueError):
                    transfert.copier('a', 'run1', octets, duree, debit, racine=self.base)

    def test_fixture_traversal_and_symlink_refused(self):
        (self.base/'secret').write_bytes(b'not a fixture')
        (self.base/'fixtures/lien.txt').symlink_to(self.base/'secret')
        for nom in ('../secret', 'lien.txt'):
            with self.subTest(nom=nom), patch.object(transfert.socket, 'create_connection',
                                                   side_effect=AssertionError('réseau interdit')):
                with self.assertRaises((ValueError, OSError)):
                    transfert.copier('a', 'run1', 10, 1, 100, nom, racine=self.base)

    def test_source_lock_prevents_overlapping_runs(self):
        with commun.Mesure('a', 'r1', 1, racine=self.base):
            with self.assertRaises(BlockingIOError):
                commun.Mesure('a', 'r2', 1, racine=self.base)

    def test_restart_task_expires_with_systemd_prevent_status(self):
        r = tache.travailler('t', 'r', .06, time.time()+.2, .05, racine=self.base)
        self.assertEqual(r, 78)
        etat = json.loads((self.base/'charges-etat/t.json').read_text())
        self.assertEqual(etat['cause_fin'], 'fin_naturelle_duree')
        self.assertTrue(etat['termine'])
        self.assertEqual(tache.travailler('t', 'r', 1, time.time()-1, racine=self.base), 78)

    def test_cpu_naturally_bounded(self):
        r = cpu.charger('c', 'r', .06, 20, racine=self.base)
        self.assertTrue(r['termine'])
        self.assertGreater(r['iterations'], 0)
        self.assertLess(r['ecoule_s'], .3)

    def test_hidden_file_operations_remain_in_fixtures(self):
        r = fichiers.exercer('f', 'r', .06, True, racine=self.base)
        self.assertTrue(r['repertoire'].startswith('.activite-'))
        self.assertGreater(r['cycles'], 0)
        self.assertEqual(list((self.base/'fixtures'/r['repertoire']).iterdir()), [])
        self.assertEqual((self.base/'fixtures/a.txt').read_bytes(), b'abcd'*1024)


if __name__ == '__main__':
    unittest.main()
