"""Identité OS attendue avant mutation, y compris relecture dans l'action."""
import contextlib
import copy
import importlib.util
import pathlib
import unittest
from unittest.mock import Mock, patch

SCRIPT = pathlib.Path(__file__).resolve().parents[1]/'invite/executeur/executeur.py'
spec = importlib.util.spec_from_file_location('executeur_identity_test', SCRIPT)
ex = importlib.util.module_from_spec(spec); spec.loader.exec_module(ex)
UNIT = 'labo-copie-b.service'
GROUP = '/sawm.slice/sawm-charge.slice/' + UNIT


def manifest():
    return {'generation': 'g1', '_sha256': 'a'*64, 'unites_autorisees': [UNIT],
            'tranches_autorisees': ['sawm-charge.slice']}


def identity():
    return {'cible': UNIT, 'boot_id': 'boot-1', 'InvocationID': 'inv-1',
            'MainPID': '42', 'ControlGroup': GROUP}


def state():
    return {'Id': UNIT, 'LoadState': 'loaded', 'Slice': 'sawm-charge.slice',
            'ActiveState': 'active', **{k:v for k,v in identity().items() if k not in ('cible','boot_id')}}


def request():
    return {'decision_id': 'dec-identity', 'action': 'geler-transfert', 'cible': UNIT,
            'generation': 'g1', 'manifest_sha256': 'a'*64, 'expected_identity': identity()}


class ExecutorIdentityTests(unittest.TestCase):
    def setUp(self):
        self.journal = []
        self.action = Mock(return_value={'effet_verifie': True})
        self.boot = Mock(); self.boot.read_text.return_value = 'boot-1\n'
        self.stack = contextlib.ExitStack(); self.addCleanup(self.stack.close)
        for obj, name, value in [(ex, 'BOOT_ID', self.boot),
            (ex, 'manifeste', lambda: manifest()), (ex, 'verrou', contextlib.nullcontext),
            (ex, '_journal', self.journal.append), (ex, '_precedent', lambda _: None),
            (ex, '_etat_unite', lambda _: state())]:
            self.stack.enter_context(patch.object(obj, name, value))
        self.stack.enter_context(patch.dict(ex.ACTIONS, {'geler-transfert': self.action}))

    def test_exact_os_identity_is_checked_and_receipt_retains_it(self):
        r = ex.appliquer(request())
        self.assertTrue(r['applique'], r)
        self.assertEqual(r['expected_identity'], identity())
        self.action.assert_called_once()
        self.assertEqual(self.action.call_args.args[1]['_identite_attendue'], identity())

    def test_reboot_invocation_pid_group_or_target_mismatch_prevents_mutation(self):
        changes = {'boot_id': 'boot-2', 'InvocationID': 'inv-2', 'MainPID': '43',
                   'ControlGroup': '/sawm.slice/sawm-charge.slice/labo-other.service',
                   'cible': 'labo-other.service'}
        for key, value in changes.items():
            with self.subTest(key=key):
                req = request(); req['expected_identity'][key] = value
                self.assertFalse(ex.appliquer(req)['applique'])
        self.action.assert_not_called()
        self.assertEqual(self.journal, [])

    def test_incomplete_identity_fails_closed_but_legacy_request_still_works(self):
        for expected in (None, {}, {'cible': UNIT}, {**identity(), 'MainPID': '0'},
                         {**identity(), 'unexpected': 'key'}):
            req = request(); req['expected_identity'] = expected
            self.assertFalse(ex.appliquer(req)['applique'])
        self.action.assert_not_called()
        req = request(); req.pop('expected_identity')
        self.assertTrue(ex.appliquer(req)['applique'])

    def test_replay_returns_original_receipt_without_checking_new_os_state(self):
        req = request()
        saved = {**req, 'demande_sha256': ex._sha(ex._canon(req)), 'etat': 'termine', 'applique': True}
        self.boot.read_text.side_effect = AssertionError('replay must not inspect or mutate OS')
        with patch.object(ex, '_precedent', return_value=saved):
            r = ex.appliquer(req)
        self.assertTrue(r['rejeu'])
        self.assertTrue(r['applique'])
        self.action.assert_not_called()

    def test_identity_checked_again_when_action_reloads_unit(self):
        def reload_target(cible, m, decision_id):
            changed = {**state(), 'InvocationID': 'new-invocation'}
            with patch.object(ex, '_etat_unite', return_value=changed):
                ex.unite_autorisee(cible, m)
            self.fail('must not execute mutation')
        with patch.dict(ex.ACTIONS, {'geler-transfert': reload_target}):
            r = ex.appliquer(request())
        self.assertFalse(r['applique'])
        self.assertEqual(r['refus']['motif'], 'identite_attendue_changee')


if __name__ == '__main__': unittest.main()
