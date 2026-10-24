"""Préparation du seul pare-feu auth ; nft simulé, aucun accès invité."""
import copy
import importlib.util
import json
import pathlib
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'invite/agent_labo'))
SPEC = importlib.util.spec_from_file_location('auth_guard_firewall_test', ROOT/'invite/agent_labo/auth_guard_firewall.py')
f = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(f)
from test_auth_guard import nft_table


def result(document=None, code=0):
    return SimpleNamespace(returncode=code, stdout=json.dumps(document or {'nftables': []}))


class FirewallTests(unittest.TestCase):
    def test_present_valid_table_and_unrelated_tables_are_never_modified(self):
        document = nft_table()
        document['nftables'].extend([
            {'table': {'family': 'inet', 'name': 'other'}},
            {'rule': {'family': 'inet', 'table': 'other', 'chain': 'input', 'expr': [{'accept': None}]}}])
        original = copy.deepcopy(document)
        runner = Mock(return_value=result(document))
        self.assertTrue(f.ensure(runner))
        runner.assert_called_once_with(['/usr/sbin/nft', '-j', 'list', 'ruleset'],
            capture_output=True, text=True, timeout=3)
        self.assertEqual(document, original)

    def test_absent_table_creates_only_fixed_scope_then_rechecks(self):
        runner = Mock(side_effect=[result({'nftables': [{'table': {'family': 'inet', 'name': 'other'}}]}),
                                  result(), result(nft_table())])
        self.assertTrue(f.ensure(runner))
        self.assertEqual(runner.call_count, 3)
        creation = runner.call_args_list[1]
        self.assertEqual(creation.args[0], ['/usr/sbin/nft', '-f', '-'])
        self.assertIs(creation.kwargs['check'], True)
        lines = creation.kwargs['input'].splitlines()
        self.assertEqual(lines[0], 'create table inet sawm_auth_guard')
        self.assertEqual(len(lines), 6)
        self.assertTrue(all('inet sawm_auth_guard' in line for line in lines))
        self.assertEqual(sum('tcp dport 8082' in line for line in lines), 2)
        self.assertNotIn('flush', creation.kwargs['input'])
        self.assertNotIn('delete', creation.kwargs['input'])

    def test_present_table_outside_scope_is_refused_without_any_write(self):
        wrong_port = nft_table()
        wrong_port['nftables'][-1]['rule']['expr'][0]['match']['right'] = 22
        extra_rule = nft_table()
        extra_rule['nftables'].append({'rule': {'family': 'inet', 'table': 'sawm_auth_guard',
                                              'chain': 'input', 'expr': [{'drop': None}]}})
        incomplete = {'nftables': [{'table': {'family': 'inet', 'name': 'sawm_auth_guard'}}]}
        for document in (wrong_port, extra_rule, incomplete):
            with self.subTest(document=document):
                runner = Mock(return_value=result(document))
                with self.assertRaisesRegex(RuntimeError, 'firewall_scope_invalid'):
                    f.ensure(runner)
                runner.assert_called_once()
                self.assertNotIn('input', runner.call_args.kwargs)

    def test_inventory_failure_or_malformed_response_does_not_create_any_table(self):
        for response in (result(code=1), SimpleNamespace(returncode=0, stdout='{bad'),
                         SimpleNamespace(returncode=0, stdout='x'*(1024*1024+1))):
            with self.subTest(response_code=response.returncode):
                runner = Mock(return_value=response)
                with self.assertRaises((RuntimeError, ValueError)):
                    f.ensure(runner)
                runner.assert_called_once()

    def test_creation_race_fails_exclusive_create_instead_of_merging_table(self):
        runner = Mock(side_effect=[result(), subprocess.CalledProcessError(1, ['nft', '-f', '-'])])
        with self.assertRaises(subprocess.CalledProcessError):
            f.ensure(runner)
        self.assertEqual(runner.call_count, 2)
        self.assertTrue(runner.call_args.kwargs['input'].startswith('create table inet sawm_auth_guard\n'))

    def test_post_creation_scope_mismatch_fails_without_repair_or_delete(self):
        runner = Mock(side_effect=[result(), result(), result()])
        with self.assertRaisesRegex(RuntimeError, 'firewall_scope_invalid'):
            f.ensure(runner)
        self.assertEqual(runner.call_count, 3)
        self.assertEqual(sum('input' in call.kwargs for call in runner.call_args_list), 1)


if __name__ == '__main__': unittest.main()
