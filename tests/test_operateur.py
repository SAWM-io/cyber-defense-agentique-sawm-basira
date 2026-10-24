"""Console : processus simulés, aucun SSH, Cloud ou scénario réel."""
import importlib.util
import json
import os
import pathlib
import tempfile
import types
import unittest
from unittest import mock

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / 'controleur/operateur.py'
spec = importlib.util.spec_from_file_location('operateur_test', SCRIPT)
o = importlib.util.module_from_spec(spec)
spec.loader.exec_module(o)


class Processus:
    def __init__(self, cmd, **kw):
        self.cmd, self.kw = cmd, kw
        self.pid = 900000
        self.returncode = None
        self.terminaisons = 0
        self.ignore_term = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminaisons += 1
        if not self.ignore_term:
            self.returncode = -15

    def wait(self, **kw):
        return self.returncode


class OperateurTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name).resolve()
        (self.root / 'controleur').mkdir()
        for nom in ('validation.py', 'validation_reprise.py'):
            (self.root / 'controleur' / nom).write_text('# jamais exécuté\n')
        (self.root / 'releves/rapports').mkdir(parents=True)
        self.controle = o.ControleOperateur(self.root)
        self.addCleanup(self.liberer)
        self.popen = mock.patch.object(o.subprocess, 'Popen', side_effect=self.creer_processus).start()
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(o.threading, 'Thread', return_value=types.SimpleNamespace(start=lambda: None)).start()
        mock.patch.object(o.time, 'sleep').start()
        self.secours = mock.patch.object(o, '_nettoyage_invite', return_value={'confirme': True, 'actions_vm': True}).start()

    def liberer(self):
        if self.controle._fd_verrou is not None:
            os.close(self.controle._fd_verrou)
            self.controle._fd_verrou = None

    def creer_processus(self, cmd, **kw):
        self.proc = Processus(cmd, **kw)
        return self.proc

    def lancer(self, scenario='transfert', volume=1):
        return self.controle.traite({'action': 'lancer', 'scenario': scenario, 'volume_gio': volume})

    def rapport(self, succes=True):
        relative = 'releves/rapports/experience-vm-test.json'
        path = self.root / relative
        path.write_text(json.dumps({'run_id': 'vm-test', 'succes_mesure': succes,
                                   'nettoyage_operateur': [{'code': 0}]}))
        log = self.controle.dossier / (self.controle._operation['id'] + '.log')
        log.write_text('information interne non publiée\n' + json.dumps({'rapport': str(path)}) + '\n')
        return relative, log

    def test_construction_and_status_do_not_launch_or_access_vm(self):
        self.assertFalse(self.controle.etat()['actif'])
        self.popen.assert_not_called()
        self.secours.assert_not_called()
        self.assertFalse(self.controle.dossier.exists())

    def test_fixed_argv_volume_env_and_inherited_singleton(self):
        result = self.lancer(volume=20)
        self.assertTrue(result['actif'])
        self.assertEqual(self.proc.cmd[1:], [str(self.root / 'controleur/validation.py'),
            'transfert', '--bytes', str(20 * 1024**3), '--rate', str(8 * 1024**2)])
        self.assertFalse(self.proc.kw['shell'])
        self.assertTrue(self.proc.kw['start_new_session'])
        self.assertEqual(self.proc.kw['env']['SAWM_OPERATEUR_ID'], result['operation']['id'])
        self.assertEqual(self.proc.kw['pass_fds'], (self.controle._fd_verrou,))
        result['operation']['id'] = 'tamper'
        self.assertNotEqual(self.controle.etat()['operation']['id'], 'tamper')

    def test_authorized_scenario_is_explicit_fixed_flag(self):
        self.lancer('transfert-autorise', 5)
        self.assertEqual(self.proc.cmd[-1], '--authorized')

    def test_repetition_no_injected_volume_argument(self):
        state = self.lancer('repetition', 20)
        self.assertEqual(self.proc.cmd, [o.sys.executable, str(self.root / 'controleur/validation_reprise.py')])
        self.assertIsNone(state['operation']['volume_gio'])

    def test_reject_parameters_before_popen(self):
        for payload in ([], {}, {'action': 'shell'},
                        {'action': 'lancer', 'scenario': '../../bad'},
                        {'action': 'lancer', 'scenario': []},
                        {'action': 'lancer', 'scenario': 'transfert', 'volume_gio': True},
                        {'action': 'lancer', 'scenario': 'transfert', 'volume_gio': '1'},
                        {'action': 'lancer', 'scenario': 'transfert', 'volume_gio': 2},
                        {'action': 'lancer', 'scenario': 'transfert', 'cmd': 'echo hello'}):
            with self.subTest(payload=payload), self.assertRaises(o.ValidationErreur):
                self.controle.traite(payload)
        self.popen.assert_not_called()

    def test_singleton_across_instances_and_same_instance(self):
        self.lancer()
        other = o.ControleOperateur(self.root)
        self.assertTrue(other.etat()['controle_externe'])
        with self.assertRaises(o.ValidationErreur):
            self.lancer()
        with self.assertRaises(o.ValidationErreur):
            other.traite({'action': 'lancer', 'scenario': 'repetition'})
        self.assertEqual(self.popen.call_count, 1)

    def test_stop_requires_exact_console_operation_and_cleanup(self):
        state = self.lancer()
        with self.assertRaises(o.ValidationErreur):
            self.controle.traite({'action': 'arreter', 'operation_id': 'previous-operation'})
        self.assertFalse(self.controle._stop.is_set())
        state = self.controle.traite({'action': 'arreter', 'operation_id': state['operation']['id']})
        self.assertEqual(state['operation']['statut'], 'arret_demande')
        _, log = self.rapport()
        self.controle._surveiller(log)
        self.assertEqual(self.proc.terminaisons, 1)
        self.secours.assert_called_once_with(state['operation']['id'], 'transfert')
        state = self.controle.etat()
        self.assertFalse(state['actif'])
        self.assertEqual(state['operation']['statut'], 'arrete')
        self.assertEqual(state['operation']['origine_arret'], 'demande_operateur')

    def test_result_is_reported_without_inventing_success_from_exit_zero(self):
        self.lancer()
        relative, log = self.rapport(succes=False)
        self.proc.returncode = 0
        self.controle._surveiller(log)
        state = self.controle.etat()['operation']
        self.assertEqual(state['statut'], 'termine')
        self.assertFalse(state['rapport']['succes_mesure'])
        self.assertEqual(state['rapport']['chemin'], relative)
        self.assertNotIn('information interne', json.dumps(state))
        self.secours.assert_not_called()

    def test_previous_report_cannot_be_credited_to_new_run(self):
        self.lancer()
        relative, log = self.rapport()
        os.utime(self.root / relative, (1, 1))
        self.proc.returncode = 0
        self.controle._surveiller(log)
        self.assertEqual(self.controle.etat()['operation']['statut'], 'erreur')
        self.assertIsNone(self.controle.etat()['operation']['rapport'])

    def test_process_failure_is_not_hidden_by_valid_report(self):
        self.lancer()
        _, log = self.rapport()
        self.proc.returncode = 1
        self.controle._surveiller(log)
        self.assertEqual(self.controle.etat()['operation']['statut'], 'erreur')
        self.secours.assert_called_once()

    def test_timeout_kills_only_owned_process_group_and_requests_scoped_cleanup(self):
        self.lancer()
        _, log = self.rapport()
        self.proc.ignore_term = True
        def killed(pid, sig):
            self.assertEqual(pid, self.proc.pid)
            self.assertEqual(sig, o.signal.SIGKILL)
            self.proc.returncode = -9
        with mock.patch.object(o, 'DUREE_MAX_S', 0), mock.patch.object(o, 'GRACE_ARRET_S', 0), \
                mock.patch.object(o.os, 'killpg', side_effect=killed) as kill:
            self.controle._surveiller(log)
        kill.assert_called_once()
        state = self.controle.etat()['operation']
        self.assertEqual(state['origine_arret'], 'limite_console')
        self.assertTrue(state['arret_force'])
        self.assertEqual(state['statut'], 'erreur')

    def test_replay_is_read_only_even_while_console_runs(self):
        relative = 'releves/rapports/experience-vm-old.json'
        (self.root / relative).write_text('{"run_id":"old","succes_mesure":false}')
        replay = self.controle.traite({'action': 'rejouer', 'rapport': relative})
        self.assertEqual(replay['mode'], 'REJEU')
        self.assertFalse(replay['actions_vm'])
        self.assertEqual(replay['rapport']['contenu']['run_id'], 'old')
        self.popen.assert_not_called()
        self.secours.assert_not_called()
        self.lancer()
        identifiant = self.controle.etat()['operation']['id']
        self.controle.traite({'action': 'rejouer', 'rapport': relative})
        self.assertEqual(self.controle.etat()['operation']['id'], identifiant)
        self.assertTrue(self.controle.etat()['actif'])

    def test_replay_rejects_path_traversal_symlink_and_oversize(self):
        relative = 'releves/rapports/experience-vm-link.json'
        (self.root / 'outside.json').write_text('{}')
        (self.root / relative).symlink_to(self.root / 'outside.json')
        for chemin in (None, '../../outside.json', '/etc/passwd', relative,
                       'releves/rapports/../outside.json', 'releves/rapports/a/b.json',
                       'releves/rapports/cle.json', 'releves/rapports/experience-\x00.json'):
            with self.subTest(chemin=chemin), self.assertRaises(o.ValidationErreur):
                self.controle.traite({'action': 'rejouer', 'rapport': chemin})
        (self.root / relative).unlink()
        (self.root / relative).write_text('{"long":"1234567890"}')
        with mock.patch.object(o, 'MAX_RAPPORT', 10), self.assertRaises(o.ValidationErreur):
            self.controle.traite({'action': 'rejouer', 'rapport': relative})
        self.secours.assert_not_called()

    def test_symlink_report_directory_is_rejected(self):
        (self.root / 'releves/rapports').rmdir()
        (self.root / 'outside').mkdir()
        (self.root / 'outside/experience-vm-test.json').write_text('{}')
        (self.root / 'releves/rapports').symlink_to(self.root / 'outside', target_is_directory=True)
        with self.assertRaises(o.ValidationErreur):
            self.controle.traite({'action': 'rejouer', 'rapport': 'releves/rapports/experience-vm-test.json'})


if __name__ == '__main__':
    unittest.main()
