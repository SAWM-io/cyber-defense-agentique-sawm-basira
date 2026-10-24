"""Motifs locaux et relecture historique, sans Cloud ni modification de preuve."""
import copy
import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from controleur import collecteur, veille
from controleur.motifs_incidents import motif_detection
from test_correlation import etat, manifeste
from controleur.correlation import Correlateur


def evenement():
    c = Correlateur()
    for second in (1, 2):
        c.analyser(etat(second), manifeste())
    return c.analyser(etat(3), manifeste())[0]


class MotifsIncidentsTests(unittest.TestCase):
    def test_measured_summary_same_before_and_after_serialization_without_mutation(self):
        event = evenement()
        frozen = copy.deepcopy(event)
        reason = motif_detection(event)
        for expected in ('PID 42', '3 inventaires', '2.0 s', '127.0.0.1:9009',
                         'labo-copie-b.service', 'ne prouve ni malware ni exfiltration'):
            self.assertIn(expected, reason)
        published = {'titre': event['genre'].replace('_', ' '),
                     'faits': [json.dumps(x) for x in event['faits']]}
        self.assertEqual(motif_detection(published), reason)
        self.assertEqual(event, frozen)

    def test_session_without_unit_is_explained_not_called_unauthorized(self):
        event = evenement()
        event['faits'][0]['identite_os']['cgroup'] = '0::/user.slice/user-1000.slice/session-42.scope'
        reason = motif_detection(event)
        self.assertIn('Aucune unité .service identifiée', reason)
        self.assertNotIn('activité non autorisée', reason)

    def test_malformed_or_truncated_data_never_invents_measurements(self):
        for facts in (None, ['{"identite_os":'], [None], ['['*1900], [{'identite_os': {}, 'sequence': []}]):
            self.assertIn('incomplètes ou illisibles', motif_detection({'titre':'sequence reseau hors baseline','faits':facts}))
        for bad in (True, '3', -1):
            event = evenement()
            event['faits'][0]['sequence'][1]['echantillons_distincts'] = bad
            self.assertIn('incomplètes ou illisibles', motif_detection(event))
        self.assertEqual(motif_detection({'titre': 'autre incident', 'faits': []}), '')

    def test_historical_projection_preserves_disk_state_dates_and_existing_reason(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(collecteur.Etat, '_versions', return_value={}):
            root=pathlib.Path(tmp); series=root/'releves/series'
            state=collecteur.Etat('reason-test',series=series,racine=root)
            event=evenement()
            original={'id':event['id'],'titre':event['genre'].replace('_',' '),
                      'statut':'attente_budget','mur_epoch_ms':1234,
                      'raison_publique':'Budget épuisé, analyse reportée.',
                      'faits':[json.dumps(f) for f in event['faits']]}
            state.ajouter_incident(original)
            before=state.fichier.read_bytes()
            saved=copy.deepcopy(state.incidents)
            row=state.instantane()['incidents'][0]
            self.assertIn('3 inventaires',row['motif_detection'])
            self.assertEqual({k:v for k,v in row.items() if k!='motif_detection'},state.incidents[event['id']])
            self.assertEqual(state.incidents,saved)
            self.assertEqual(state.fichier.read_bytes(),before)
            replay=collecteur.Etat('reason-replay',series=series,racine=root)
            self.assertEqual(replay.instantane()['incidents'][0],row)
            self.assertEqual(row['raison_publique'],original['raison_publique'])
            self.assertEqual(row['mur_epoch_ms'],1234)
            self.assertEqual(row['statut'],'attente_budget')

    def test_creation_publishes_detection_before_any_cloud_analysis(self):
        event=evenement(); posted=[]; journal=Mock();journal.nouveau.return_value=True
        watcher=veille.Veille({},journal,cloud=False,poster=lambda route,body:posted.append((route,body)))
        watcher.detecteur=Mock();watcher.detecteur.analyser.return_value=[event]
        with patch('controleur.perception_defense.incidents_defense',return_value=[]):
            watcher.observer(etat())
        incident=next(body for route,body in posted if route=='/api/incident')
        checked=collecteur.valider_evenement('incident',incident)
        self.assertIn('3 inventaires',checked['motif_detection'])
        self.assertNotIn('raison_publique',checked)
        self.assertEqual(checked['statut'],'a_verifier')
        self.assertTrue(watcher.attente.empty())
        watcher.publier_attention(event,'attente_budget','Budget épuisé')
        update=collecteur.valider_evenement('incident',posted[-1][1])
        self.assertEqual(update['motif_detection'],checked['motif_detection'])
        self.assertEqual(update['raison_publique'],'Budget épuisé')


if __name__ == '__main__':
    unittest.main()
