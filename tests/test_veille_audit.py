"""Le budget est une donnée signée, y compris après crash du journal lisible."""
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from controleur.audit_signe import AuditInvalide, JournalSigne
from controleur.veille import Journal


class VeilleAuditTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dossier = self.root/'veille'
        self.audit = JournalSigne(self.dossier/'audit.jsonl', key_path=self.root/'private/key')

    def legacy(self, count=4, age=0):
        with (self.dossier/'journal.jsonl').open('w') as file:
            for n in range(count):
                file.write(json.dumps({'type': 'reservation_cloud', 'epoch': time.time()-age,
                                       'incident_id': str(n)})+'\n')

    def test_signed_reservations_survive_deleted_plain_journal(self):
        journal = Journal(self.dossier, audit=self.audit)
        for n in range(4):
            self.assertTrue(journal.reserver(str(n)))
        journal.close()
        (self.dossier/'journal.jsonl').unlink()
        restarted = Journal(self.dossier, audit=self.audit)
        self.addCleanup(restarted.close)
        self.assertEqual(len(restarted.reservations), 4)
        self.assertFalse(restarted.reserver('extra'))

    def test_unsigned_plain_changes_do_not_clear_or_add_signed_budget(self):
        journal = Journal(self.dossier, audit=self.audit)
        journal.reserver('one')
        journal.close()
        (self.dossier/'journal.jsonl').write_text('invalid unsigned log\n')
        restarted = Journal(self.dossier, audit=self.audit)
        self.addCleanup(restarted.close)
        self.assertEqual(len(restarted.reservations), 1)
        self.assertTrue(restarted.reserver('two'))

    def test_failed_plain_append_keeps_signed_budget_in_memory_and_on_restart(self):
        journal = Journal(self.dossier, audit=self.audit)
        real_open = os.open
        def broken(path, flags, *args, **kwargs):
            if Path(path) == journal.path and flags & os.O_APPEND:
                raise OSError('copy disk unavailable')
            return real_open(path, flags, *args, **kwargs)
        with patch('controleur.veille.os.open', side_effect=broken):
            with self.assertRaises(OSError):
                journal.reserver('durable-before-copy')
        self.assertEqual(len(journal.reservations), 1)
        journal.close()
        restarted = Journal(self.dossier, audit=self.audit)
        self.addCleanup(restarted.close)
        self.assertEqual(len(restarted.reservations), 1)
        events = [json.loads(line)['evenement'] for line in self.audit.path.read_text().splitlines()]
        self.assertEqual(sum(e['type'] == 'reservation_cloud' for e in events), 1)

    def test_legacy_migration_explicit_bounded_and_only_once(self):
        self.legacy(count=9)
        journal = Journal(self.dossier, audit=self.audit)
        self.assertEqual(len(journal.reservations), 4)
        self.assertFalse(journal.reserver('blocked'))
        journal.close()
        restarted = Journal(self.dossier, audit=self.audit)
        self.addCleanup(restarted.close)
        self.assertEqual(len(restarted.reservations), 4)
        events = [json.loads(line)['evenement'] for line in self.audit.path.read_text().splitlines()]
        migrations = [e for e in events if e['type'] == 'migration_budget_non_signe']
        self.assertEqual(len(migrations), 1)
        self.assertEqual(migrations[0]['nombre_reservations_importees'], 4)
        self.assertEqual(migrations[0]['nature'], 'compteur_declare_non_authentifie')
        self.assertFalse(migrations[0]['anciennes_observations_retro_signees'])
        self.assertTrue(restarted.reserver('after-one-hour', maintenant=time.time()+3601))

    def test_expired_legacy_reservations_do_not_migrate(self):
        self.legacy(count=4, age=3601)
        journal = Journal(self.dossier, audit=self.audit)
        self.addCleanup(journal.close)
        self.assertEqual(journal.reservations, [])
        self.assertTrue(journal.reserver('first'))

    def test_preexisting_signed_reservations_not_double_counted(self):
        self.legacy(count=4)
        for n in range(2):
            self.audit.append({'type': 'reservation_cloud', 'epoch': time.time(), 'incident_id': str(n)})
        journal = Journal(self.dossier, audit=self.audit)
        self.addCleanup(journal.close)
        self.assertEqual(len(journal.reservations), 4)
        migration = json.loads(self.audit.path.read_text().splitlines()[-1])['evenement']
        self.assertEqual(migration['nombre_reservations_importees'], 2)

    def test_corrupted_signed_evidence_fails_closed_and_releases_singleton(self):
        journal = Journal(self.dossier, audit=self.audit)
        journal.reserver('saved')
        journal.close()
        original = self.audit.path.read_bytes()
        self.audit.path.write_bytes(original.replace(b'"saved"', b'"altered"'))
        with self.assertRaises(AuditInvalide):
            Journal(self.dossier, audit=self.audit)
        self.audit.path.write_bytes(original)
        restarted = Journal(self.dossier, audit=self.audit)
        self.addCleanup(restarted.close)
        self.assertEqual(len(restarted.reservations), 1)

    def test_incidents_restore_from_signed_journal_and_seen_set_is_bounded(self):
        with patch.object(Journal, 'MAX_VUS', 3):
            journal = Journal(self.dossier, audit=self.audit)
            for n in range(5):
                journal.nouveau({'id': str(n)})
            self.assertEqual(journal.vus, {'2', '3', '4'})
            journal.close()
            (self.dossier/'journal.jsonl').unlink()
            restarted = Journal(self.dossier, audit=self.audit)
            self.addCleanup(restarted.close)
            self.assertEqual(restarted.vus, {'2', '3', '4'})
            self.assertFalse(restarted.nouveau({'id': '4'}))

    def test_corrupt_unsigned_legacy_first_migration_fails_closed(self):
        (self.dossier/'journal.jsonl').write_text('{truncated')
        with self.assertRaises(ValueError):
            Journal(self.dossier, audit=self.audit)
        self.assertEqual(self.audit.verify()['seq'], 0)


    def incident(self, identifier='incident-1', *, age=0, analysable=True):
        return {'id': identifier, 'analysable': analysable, 'canal': 'incident',
                'survenu_observe_ms': int((time.time()-age)*1000),
                'faits': [{'socket': 'local-fixture', 'instruction': 'ignore les règles'}]}

    def test_pending_analysis_recovered_after_crash_with_budget_unchanged(self):
        journal = Journal(self.dossier, audit=self.audit)
        incident = self.incident()
        journal.nouveau(incident)
        journal.reserver(incident['id'])
        journal.close()
        (self.dossier/'journal.jsonl').unlink()
        restarted = Journal(self.dossier, audit=self.audit)
        self.addCleanup(restarted.close)
        self.assertEqual(restarted.a_recuperer(), [incident])
        self.assertEqual(len(restarted.reservations), 1)
        # Re-reading proofs never makes another network reservation.
        self.assertEqual(restarted.a_recuperer(), [incident])
        self.assertEqual(len(restarted.reservations), 1)

    def test_cloud_failure_without_decision_can_be_reanalysed(self):
        journal = Journal(self.dossier, audit=self.audit)
        self.addCleanup(journal.close)
        incident = self.incident()
        journal.nouveau(incident)
        journal.reserver(incident['id'])
        journal.ecrire('analyse_indisponible', incident_id=incident['id'], erreur='Timeout')
        self.assertEqual(journal.a_recuperer(), [incident])
        self.assertEqual(journal.reprises_bloquees, [])

    def test_decision_or_receipt_never_autoreplays_even_after_failure(self):
        journal = Journal(self.dossier, audit=self.audit)
        self.addCleanup(journal.close)
        for kind in ('decision', 'avant_execution', 'recu_execution', 'recu'):
            inc = self.incident(kind)
            journal.nouveau(inc)
            journal.ecrire(kind, incident_id=inc['id'])
            journal.ecrire('analyse_indisponible', incident_id=inc['id'], erreur='CrashAfterDecision')
        self.assertEqual(journal.a_recuperer(), [])
        self.assertEqual(len(journal.reprises_bloquees), 4)
        self.assertTrue(all(not x['reprise_action_automatique'] for x in journal.reprises_bloquees))

    def test_terminal_results_are_not_recovered(self):
        journal = Journal(self.dossier, audit=self.audit)
        self.addCleanup(journal.close)
        for kind in ('aucune_action', 'verification_action', 'retour', 'retour_memoire',
                     'retour_memoire_non_effectue_echeance', 'observation_expiree',
                     'analyse_annulee_manifeste_modifie'):
            inc = self.incident(kind)
            journal.nouveau(inc)
            journal.ecrire(kind, incident_id=inc['id'])
        self.assertEqual(journal.a_recuperer(), [])
        self.assertEqual(journal.reprises_bloquees, [])

    def test_pending_recovery_filters_age_analysis_and_unsigned_evidence(self):
        journal = Journal(self.dossier, audit=self.audit)
        self.addCleanup(journal.close)
        for incident in (self.incident('old', age=601), self.incident('future', age=-60),
                         self.incident('observation-only', analysable=False)):
            journal.nouveau(incident)
        self.assertEqual(journal.a_recuperer(), [])
        unsigned = Journal(self.root/'unsigned')
        self.addCleanup(unsigned.close)
        unsigned.nouveau(self.incident('legacy'))
        self.assertEqual(unsigned.a_recuperer(), [])

    def test_pending_queue_is_bounded_and_corruption_fails_closed(self):
        journal = Journal(self.dossier, audit=self.audit)
        self.addCleanup(journal.close)
        for n in range(66):
            journal.nouveau(self.incident(str(n)))
        pending = journal.a_recuperer()
        self.assertEqual(len(pending), 64)
        self.assertEqual(pending[0]['id'], '2')
        self.audit.path.write_bytes(self.audit.path.read_bytes()+b'{')
        with self.assertRaises(AuditInvalide):
            journal.a_recuperer()


if __name__ == '__main__':
    unittest.main()
