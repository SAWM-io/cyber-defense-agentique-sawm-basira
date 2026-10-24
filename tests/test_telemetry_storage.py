"""Plafond disque sans suppression ni arrêt des mesures ou preuves rares."""
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('collecteur_stockage', ROOT/'controleur/collecteur.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class StockageTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.series = self.root/'series'
        self.series.mkdir()
        self.versions = patch.object(c.Etat, '_versions', return_value={})
        self.versions.start()
        self.addCleanup(self.versions.stop)

    def nouveau(self, limite=300, run='stockage'):
        return c.Etat(run, series=self.series, racine=self.root, max_stockage_telemetrie_o=limite)

    def test_live_continues_without_raw_disk_and_cloud_persists_after_cap(self):
        etat = self.nouveau(limite=0)
        etat.ajouter_invite({'mur_epoch_ms': 1, 'sequence': 1})
        etat.ajouter_hote({'mur_epoch_ms': 1, 'source': 'hote'})
        self.assertFalse(etat.fichier.exists())
        snap = etat.instantane()
        self.assertEqual(len(snap['invite']), 1)
        self.assertTrue(snap['telemetrie_invite']['connectee'])
        self.assertEqual(len(snap['hote']), 1)
        self.assertEqual(snap['retention_telemetrie']['echantillons_non_archives'], 2)
        etat.ajouter_appel_cloud({'appel': 'POST memory', 'statut': 200, 'event_id': 'cloud1'})
        etat.ajouter_incident({'id': 'i1', 'titre': 'Observation', 'statut': 'ouvert'})
        etat.ajouter_decision({'id': 'd1', 'action': 'ne-rien-faire', 'statut': 'choisie', 'raison_publique': 'test'})
        size = etat.fichier.stat().st_size
        etat.ajouter_invite({'mur_epoch_ms': 2, 'sequence': 2})
        self.assertEqual(etat.fichier.stat().st_size, size)
        self.assertEqual(etat.instantane()['invite'][-1]['sequence'], 2)
        restart = self.nouveau(limite=0, run='apres')
        self.assertEqual(restart.instantane()['cumuls_cloud']['appels'], 1)
        self.assertEqual(restart.instantane()['incidents'][0]['id'], 'i1')
        self.assertEqual(restart.instantane()['decisions'][0]['id'], 'd1')
        self.assertEqual(restart.historique_cloud()['appels'][0]['event_id'], 'cloud1')

    def test_budget_covers_all_existing_series_and_never_deletes(self):
        ancien = self.series/'ancien.jsonl'
        ancien.write_bytes(b'\n' * 350)
        original = ancien.read_bytes()
        etat = self.nouveau(limite=300)
        etat.ajouter_invite({'mur_epoch_ms': 1})
        self.assertFalse(etat.fichier.exists())
        self.assertEqual(ancien.read_bytes(), original)
        self.assertEqual(etat.retention['taille_series_o'], 350)
        self.assertTrue(etat.retention['ecriture_telemetrie_suspendue'])

    def test_frame_that_would_cross_cap_is_not_partly_written(self):
        etat = self.nouveau(limite=200)
        etat.ajouter_invite({'mur_epoch_ms': 1})
        before = etat.fichier.read_bytes()
        etat.ajouter_invite({'mur_epoch_ms': 2, 'padding': 'x' * 300})
        self.assertEqual(etat.fichier.read_bytes(), before)
        self.assertLessEqual(len(before), 200)
        self.assertEqual(etat.invite[-1]['mur_epoch_ms'], 2)
        self.assertTrue(etat.retention['ecriture_telemetrie_suspendue'])
        self.assertEqual(etat.retention['taille_series_o'], len(before))

    def test_restart_only_parses_recent_telemetry_but_all_cloud_metadata(self):
        path = self.series/'old.jsonl'
        records = []
        for i in range(20):
            records.append({'genre': 'invite', 'mur_epoch_ms': i, 'sequence': i})
            records.append({'genre': 'hote', 'mur_epoch_ms': i})
            records.append({'genre': 'cloud', 'appel': 'request', 'statut': 200,
                            'event_id': 'c'+str(i), 'mur_epoch_ms': i})
        path.write_text(''.join(json.dumps(x)+'\n' for x in records))
        real_loads = json.loads
        parsed = []
        def compter(value, **kwargs):
            parsed.append(value)
            return real_loads(value, **kwargs)
        with patch.object(c, 'FENETRE', 3), patch.object(c.json, 'loads', side_effect=compter):
            etat = self.nouveau(limite=999999)
        self.assertEqual(len(parsed), 26)  # 20 Cloud + 3 derniers invités + 3 hôtes.
        self.assertEqual([x['sequence'] for x in etat.invite], [17, 18, 19])
        self.assertEqual(etat.reprise['telemetrie_ancienne_non_rechargee'], 34)
        self.assertEqual(etat.cumuls_cloud['appels'], 20)
        self.assertEqual(len(etat.historique_cloud()['appels']), 20)
        self.assertEqual(len(path.read_text().splitlines()), 60)

    def test_recent_invalid_sample_is_validated_and_not_loaded(self):
        path = self.series/'old.jsonl'
        path.write_text('{"genre": "invite", "wrong": NaN}\n')
        etat = self.nouveau()
        self.assertEqual(etat.invite, [])
        self.assertEqual(etat.reprise['lignes_invalides'], 1)

    def test_environment_and_invalid_budget(self):
        with patch.dict(c.os.environ, {'LABO_MAX_SERIES_O': '128'}):
            etat = c.Etat('env', series=self.series, racine=self.root)
        self.assertEqual(etat.retention['limite_series_o'], 128)
        with self.assertRaises(ValueError):
            self.nouveau(limite=-1)

    def test_guest_cannot_overwrite_persisted_record_kind(self):
        etat = self.nouveau(limite=999999)
        etat.ajouter_invite({'mur_epoch_ms': 1, 'genre': 'cloud'})
        self.assertEqual(json.loads(etat.fichier.read_text())['genre'], 'invite')
        restart = self.nouveau(limite=999999)
        self.assertEqual(restart.cumuls_cloud['appels'], 0)
        self.assertEqual(len(restart.invite), 1)


if __name__ == '__main__':
    unittest.main()
