import json
import pathlib
import tempfile
import unittest

from controleur import mesures_rapport as m


def invite(recu, mur, mono, cpu, sequence=1):
    return {'genre': 'invite', 'recu_ms': recu, 'mur_epoch_ms': mur,
            'monotone_ns': mono, 'sequence': sequence,
            'tranches': {'defense': {'cpu_usage_usec': cpu, 'memoire_o': 42}},
            'service_temoin': {'disponible': True, 'latence_ms': 3}}


class MesuresTests(unittest.TestCase):
    def test_cloud_deduplique_tentatives_erreurs_usage_et_percentiles(self):
        evenements = [
            {'genre': 'cloud', 'event_id': 'a', 'correlation_id': 'same', 'statut': 503, 'resultat': 'http_error', 'ms': 10},
            {'genre': 'cloud', 'event_id': 'b', 'correlation_id': 'same', 'statut': 200, 'resultat': 'stream_error', 'ms': 20, 'tentative': 2},
            {'genre': 'cloud', 'event_id': 'c', 'statut': 202, 'resultat': 'ok', 'ms': 30, 'jetons_total': 12},
            {'genre': 'cloud', 'event_id': 'd', 'statut': 200, 'resultat': 'ok', 'ms': 40, 'jetons_total': 12, 'replayed': True},
        ]
        evenements.append(dict(evenements[2]))
        appels, dedup = m.dedupliquer_cloud(evenements)
        c = m.mesurer_cloud(appels)
        self.assertEqual(c['appels'], 4)
        self.assertEqual(dedup['doublons_event_id'], 1)
        self.assertEqual((c['erreurs_http'], c['erreurs_sse'], c['erreurs']), (1, 1, 2))
        self.assertEqual(c['usage_hors_replays']['jetons_total']['somme_fournie'], 12)
        self.assertIsNone(c['usage_hors_replays']['jetons_entree']['somme_fournie'])
        self.assertEqual(c['latence_ms']['mediane'], 25)
        self.assertEqual(c['latence_ms']['p95'], 40)

    def test_fenetre_reception_hote_et_cpu_monotone_guest_decale(self):
        donnees = [invite(900, 3600900, 0, 0, 1),
                   invite(1100, 3601100, 1_000_000_000, 100, 2),
                   invite(2100, 3602100, 2_000_000_000, 1_000_100, 3),
                   invite(3100, 3603100, 3_000_000_000, 9_000_100, 4),
                   {'genre': 'hote', 'mur_epoch_ms': 1500, 'qemu': {'vm_uuid': 'AUTRE-VM', 'cpu_pct': 999}},
                   {'genre': 'hote', 'mur_epoch_ms': 1501, 'qemu': {'vm_uuid': m.VM_UUID, 'cpu_pct': 7}}]
        r = m.mesurer_ressources(donnees, 1000, 3000)
        self.assertEqual(r['echantillons_invite'], 2)
        cpu = r['invite']['roles']['defense']['cpu']
        self.assertEqual(cpu['cpu_cumule_s'], 1)
        self.assertEqual(cpu['cpu_pct_moyen_pondere'], 100)
        self.assertEqual(r['horloges']['reception_moins_horloge_invitee_ms']['mediane'], -3600000)
        self.assertEqual(r['horloges']['ecarts_negatifs'], 2)
        self.assertEqual(r['hote']['qemu_cpu_pct_ps']['moyenne'], 7)
        self.assertEqual(r['hote']['qemu_echantillons_non_attribuables'], 1)

    def test_lacunes_et_compteurs_reinitialises_non_extrapoles(self):
        donnees = [invite(i * 1000, i * 1000, i * 1_000_000_000, cpu, n)
                   for n, (i, cpu) in enumerate([(0, 100), (1, 200), (10, 300), (11, 50)])]
        r = m.mesurer_ressources(donnees)
        cpu = r['invite']['roles']['defense']['cpu']
        self.assertEqual(cpu['delta_cumule'], 100)
        self.assertEqual(cpu['duree_mesuree_s'], 1)
        self.assertEqual(cpu['reinitialisations_compteur'], 1)
        self.assertEqual(r['intervalles_invite_exclus']['lacune_superieure_a_5s'], 1)
        self.assertIsNone(r['invite']['roles']['charge']['cpu']['delta_cumule'])
        self.assertIsNone(r['invite']['roles']['charge']['memoire_o']['moyenne'])

    def test_rapport_sans_fin_et_sondes_inconnues(self):
        r = m.mesures_experience({'run_id': 'x', 'debut': '2026-09-22T11:00:00+00:00'}, [], [])
        self.assertFalse(r['fenetre']['valide'])
        self.assertIsNone(r['ressources'])
        self.assertIsNone(m.iso_ms('2026-09-22T11:00:00'))
        s = m.sonder_service([{'disponible': True}, {'disponible': False}, {}], 'test')
        self.assertEqual(s['sondes'], 3)
        self.assertEqual(s['non_renseignees'], 1)
        self.assertEqual(s['disponibilite_pct_sondes_connues'], 50)

    def test_extraction_sources_sha_journal_partiel_et_run_exact(self):
        with tempfile.TemporaryDirectory() as dossier:
            base = pathlib.Path(dossier)
            journal = base / 'series.jsonl'
            lignes = [{'genre': 'cloud', 'event_id': 'a', 'run_id': 'run-a', 'mur_epoch_ms': 1500, 'statut': 200},
                      {'genre': 'cloud', 'event_id': 'b', 'run_id': 'run-b', 'mur_epoch_ms': 1500, 'statut': 200},
                      {'genre': 'cloud', 'event_id': 'c', 'run_id': 'run-a', 'mur_epoch_ms': 5000, 'statut': 200}]
            journal.write_text(''.join(json.dumps(x) + '\n' for x in lignes) + 'null\n{"incomplet":')
            rapport = {'run_id': 'run-a', 'debut': '1970-01-01T00:00:01+00:00', 'fin': '1970-01-01T00:00:02+00:00',
                       'analyses': [{'decision': {'usage': {'total_tokens': 999}}}]}
            (base / 'experience-a.json').write_text(json.dumps(rapport))
            (base / 'experience-partielle.json').write_text('{')
            resultat = m.extraire(journal, base)
            self.assertEqual(resultat['global']['cloud']['appels'], 3)
            self.assertEqual(resultat['experiences'][0]['cloud']['appels'], 2)
            self.assertEqual(resultat['experiences'][0]['cloud']['appels_hors_fenetre_du_rapport'], 1)
            self.assertIsNone(resultat['global']['cloud']['usage_hors_replays']['jetons_total']['somme_fournie'])
            self.assertEqual(resultat['source_journal']['lignes_invalides'], 1)
            self.assertEqual(resultat['source_journal']['lignes_incompletes'], 1)
            self.assertEqual(len(resultat['source_journal']['sha256']), 64)
            self.assertEqual(len(resultat['rapports_ignores']), 1)
            sortie = base / 'mesures.json'
            m.ecrire_atomique(sortie, resultat)
            self.assertEqual(json.loads(sortie.read_text())['schema'], 'sawm-lab-mesures/v1')


if __name__ == '__main__':
    unittest.main()
