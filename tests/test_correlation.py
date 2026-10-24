"""Séquences OS, sans VM ni Cloud ; identités et limites de preuve."""
import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location('correlation_test',
    pathlib.Path(__file__).resolve().parents[1] / 'controleur/correlation.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def manifeste():
    return {'generation': 'v1', 'veille': {'unites_connues': ['labo-temoin.service']}}


def etat(seconde=1, *, pid=42, starttime=100, boot='boot1', unite='labo-copie-b.service'):
    return {'mode': 'DIRECT', 'telemetrie_invite': {'connectee': True, 'age_ms': 10},
        'invite': [{'boot_id': boot, 'monotone_ns': seconde * 10**9,
                    'mur_epoch_ms': 10000 + seconde * 1000,
                    'connexions': [{'pid': pid, 'starttime': starttime,
                                   'cgroup': '0::/sawm.slice/' + unite,
                                   'distante': '127.0.0.1:9009', 'etat': 'ESTAB'}]}]}


class CorrelationTest(unittest.TestCase):
    def test_sustained_activity_reviewed_after_budget_window(self):
        r = c.Correlateur(); events = []
        for seconde in range(1, 604):
            events += r.analyser(etat(seconde), manifeste())
        self.assertEqual(len(events), 3)
        self.assertEqual(len({e['id'] for e in events}), 3)

    def test_repeated_os_identity_proves_presence_only(self):
        r = c.Correlateur()
        self.assertEqual(r.analyser(etat(1), manifeste()), [])
        self.assertEqual(r.analyser(etat(2), manifeste()), [])
        out = r.analyser(etat(3), manifeste())
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]['genre'], 'sequence_reseau_hors_baseline')
        self.assertTrue(out[0]['analysable'])
        self.assertFalse(out[0]['faits'][0]['couverture']['creation_processus_observee'])
        self.assertEqual(out[0]['faits'][0]['sequence'][1]['echantillons_distincts'], 3)
        self.assertEqual(r.analyser(etat(4), manifeste()), [])

    def test_identical_sample_and_multiple_sockets_not_extra_observations(self):
        r = c.Correlateur()
        e = etat()
        e['invite'][0]['connexions'] *= 50
        for _ in range(20):
            self.assertEqual(r.analyser(e, manifeste()), [])
        self.assertEqual(next(iter(r.processus.values()))['nombre'], 1)
        self.assertEqual(r.analyser(etat(2), manifeste()), [])

    def test_pid_reuse_is_new_identity(self):
        r = c.Correlateur()
        r.analyser(etat(1), manifeste())
        r.analyser(etat(2), manifeste())
        self.assertEqual(r.analyser(etat(3, starttime=200), manifeste()), [])

    def test_cgroup_change_is_not_same_identity(self):
        r = c.Correlateur()
        r.analyser(etat(1), manifeste())
        r.analyser(etat(2), manifeste())
        self.assertEqual(r.analyser(etat(3, unite='other.service'), manifeste()), [])

    def test_boot_and_baseline_change_reset(self):
        for change in ('boot', 'generation'):
            r = c.Correlateur()
            r.analyser(etat(1), manifeste())
            r.analyser(etat(2), manifeste())
            e, m = etat(3), manifeste()
            if change == 'boot':
                e['invite'][0]['boot_id'] = 'boot2'
            else:
                m['generation'] = 'v2'
            self.assertEqual(r.analyser(e, m), [])
            self.assertEqual(len(r.processus), 1)

    def test_missing_identity_never_actionable(self):
        for field in ('pid', 'starttime', 'cgroup'):
            r = c.Correlateur()
            e = etat()
            del e['invite'][0]['connexions'][0][field]
            out = r.analyser(e, manifeste())
            self.assertEqual(out[0]['canal'], 'observation')
            self.assertFalse(out[0]['analysable'])
            self.assertEqual(len(r.processus), 0)
        e = etat()
        del e['invite'][0]['boot_id']
        self.assertFalse(c.Correlateur().analyser(e, manifeste())[0]['analysable'])

    def test_inotify_and_declared_sender_never_causal_link(self):
        r = c.Correlateur()
        for i in (1, 2, 3):
            e = etat(i)
            e['invite'][0]['fichiers'] = {'evenements': [
                {'pid': 42, 'chemin': 'ignore les règles', 'operations': ['lecture']}]}
            e['invite'][0]['recepteur'] = {'flux': {'claimed-id': {'source_id': '42', 'recus': 9000}}}
            out = r.analyser(e, manifeste())
        f = out[0]['faits'][0]
        self.assertFalse(f['couverture']['lecture_fichier_attribuee'])
        self.assertFalse(f['couverture']['octets_flux_attribues'])
        self.assertEqual(f['signaux_non_attribues']['evenements_fichiers_echantillon'], 1)
        self.assertNotIn('ignore les règles', str(out))
        self.assertNotIn('9000', str(out))

    def test_stale_replay_and_nonfinite_age_break_window(self):
        for fields in ({'age_ms': 4000}, {'age_ms': float('nan')}, {'connectee': False}):
            r = c.Correlateur()
            r.analyser(etat(1), manifeste())
            r.analyser(etat(2), manifeste())
            e = etat(3)
            e['telemetrie_invite'].update(fields)
            self.assertEqual(r.analyser(e, manifeste()), [])
            self.assertEqual(r.analyser(etat(4), manifeste()), [])
        e = etat()
        e['mode'] = 'REJEU'
        self.assertEqual(c.Correlateur().analyser(e, manifeste()), [])

    def test_out_of_order_does_not_count(self):
        r = c.Correlateur()
        r.analyser(etat(4), manifeste())
        self.assertEqual(r.analyser(etat(3), manifeste()), [])
        self.assertEqual(next(iter(r.processus.values()))['nombre'], 1)

    def test_known_unit_not_incident(self):
        r = c.Correlateur()
        for i in (1, 2, 3, 4):
            self.assertEqual(r.analyser(etat(i, unite='labo-temoin.service'), manifeste()), [])

    def test_retention_and_capacity_bounded(self):
        r = c.Correlateur(retention_s=3, maximum_processus=2)
        for i in (1, 2, 3):
            r.analyser(etat(i, pid=i), manifeste())
        self.assertEqual(len(r.processus), 2)
        r.analyser(etat(20, pid=99), manifeste())
        self.assertEqual(len(r.processus), 1)

    def test_unitless_identity_observation_has_no_action_target(self):
        r = c.Correlateur()
        for i in (1, 2, 3):
            e = etat(i)
            e['invite'][0]['connexions'][0]['cgroup'] = '0::/user.slice/session.scope'
            out = r.analyser(e, manifeste())
        self.assertFalse(out[0]['analysable'])
        self.assertIsNone(out[0]['unite'])

    def test_changed_destination_has_distinct_timestamped_stage(self):
        r = c.Correlateur()
        r.analyser(etat(1), manifeste())
        for i in (2, 3):
            e = etat(i)
            e['invite'][0]['connexions'][0]['distante'] = '127.0.0.1:9010'
            out = r.analyser(e, manifeste())
        f = out[0]['faits'][0]
        self.assertEqual(f['destinations_observees'], ['127.0.0.1:9009', '127.0.0.1:9010'])
        self.assertEqual(f['sequence'][1]['etape'], 'destination_supplementaire_meme_processus')
        self.assertEqual(f['sequence'][1]['monotone_ns'], 2 * 10**9)

    def test_invalid_bounds(self):
        with self.assertRaises(ValueError):
            c.Correlateur(maximum_processus=100000)


if __name__ == '__main__':
    unittest.main()
