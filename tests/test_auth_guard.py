"""Fixture auth défensive : loopback local, horloge/pare-feu injectés, aucune VM."""
import contextlib
import copy
import hashlib
import http.client
import http.server
import importlib.util
import io
import json
import os
import pathlib
import socket
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('auth_guard_test', ROOT/'invite/agent_labo/auth_guard.py')
a = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = a
SPEC.loader.exec_module(a)
PASSWORD = 'synthetic-test-password'
SALT = b'0123456789abcdef'
DIGEST = hashlib.pbkdf2_hmac('sha256', PASSWORD.encode(), SALT, 200000)


def config():
    return a.AuthConfig('demo-cto', SALT, DIGEST, 200000)


def nft_table():
    entries = [{'metainfo': {'json_schema_version': 1}}, {'table': {'family': 'inet', 'name': 'sawm_auth_guard'}}]
    for name, typ in (('blocked4', 'ipv4_addr'), ('blocked6', 'ipv6_addr')):
        entries.append({'set': {'family': 'inet', 'table': 'sawm_auth_guard', 'name': name,
            'type': typ, 'flags': ['timeout'], 'size': 1024}})
    entries.append({'chain': {'family': 'inet', 'table': 'sawm_auth_guard', 'name': 'input',
        'type': 'filter', 'hook': 'input', 'prio': -10, 'policy': 'accept'}})
    for protocol, name in (('ip', 'blocked4'), ('ip6', 'blocked6')):
        entries.append({'rule': {'family': 'inet', 'table': 'sawm_auth_guard', 'chain': 'input', 'expr': [
            {'match': {'op': '==', 'left': {'payload': {'protocol': 'tcp', 'field': 'dport'}}, 'right': 8082}},
            {'match': {'op': '==', 'left': {'payload': {'protocol': protocol, 'field': 'saddr'}}, 'right': '@'+name}},
            {'counter': {'packets': 0, 'bytes': 0}}, {'drop': None}]}})
    return {'nftables': entries}


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.now, self.events = [0.0], []
        self.auth = Mock(side_effect=lambda user, password: user == 'demo-cto' and password == PASSWORD)
        self.block = Mock(side_effect=lambda ip, ttl: a._block_receipt(ip, ttl, 'scope_verified_command_accepted', True))
        self.guard = a.Guard(config(), authentifier=self.auth, block_ip=self.block,
            journal=self.events.append, clock=lambda: self.now[0], wall_clock=lambda: 1800000000)

    def failed_login(self, ip='192.0.2.1', username='demo-cto'):
        return self.guard.login(ip, username, 'wrong-test-password')

    def test_five_failures_block_only_source_and_expire_without_extending_on_retry(self):
        for i in range(4): self.assertEqual(self.failed_login()[0], 401)
        self.assertEqual(self.failed_login(), (429, {'status': 'temporarily_blocked', 'retry_after_s': 60}))
        self.block.assert_called_once_with('192.0.2.1', 60)
        self.assertEqual(self.guard.login('192.0.2.2', 'demo-cto', PASSWORD)[0], 200)
        self.now[0] = 59
        self.assertEqual(self.guard.login('192.0.2.1', 'demo-cto', PASSWORD)[0], 429)
        self.assertEqual(self.events[-1]['block_receipt']['network_effect_verified'], False)
        self.now[0] = 60
        self.assertEqual(self.guard.login('192.0.2.1', 'demo-cto', PASSWORD)[0], 200)
        self.block.assert_called_once()

    def test_rolling_window_and_success_reset_only_the_same_source(self):
        for i in range(8):
            self.now[0] = i*11
            self.assertEqual(self.failed_login()[0], 401)
        self.block.assert_not_called()
        self.failed_login('192.0.2.2')
        self.assertEqual(self.guard.login('192.0.2.1', 'demo-cto', PASSWORD)[0], 200)
        self.assertEqual(len(self.guard.peers['192.0.2.2']['failures']), 1)
        self.assertNotIn('192.0.2.1', self.guard.peers)

    def test_nft_unavailable_or_forged_callback_keeps_http_block_without_secret(self):
        self.block.side_effect = RuntimeError('PRIVATE_EXECUTOR_SECRET')
        for i in range(5): status, body = self.failed_login()
        self.assertEqual(status, 429)
        receipt = self.events[-1]['block_receipt']
        self.assertFalse(receipt['command_accepted'])
        self.assertFalse(receipt['network_effect_verified'])
        self.assertNotIn('PRIVATE_EXECUTOR_SECRET', json.dumps(self.events))
        self.now[0] = 61
        self.block.side_effect = lambda ip, ttl: {**a._block_receipt(ip, ttl), 'password': PASSWORD}
        for i in range(5): status, _ = self.failed_login()
        self.assertEqual(status, 429)
        self.assertEqual(self.events[-1]['block_receipt']['reason'], 'callback_invalid')
        self.assertNotIn(PASSWORD, json.dumps(self.events))

    def test_campaign_is_only_a_hypothesis_and_never_blocks_an_innocent_source(self):
        self.failed_login('192.0.2.1')
        self.failed_login('192.0.2.2')
        hint = self.events[-1]['campaign_hint']
        self.assertTrue(hint['possible'])
        self.assertFalse(hint['identity_established'])
        self.assertEqual(hint['distinct_failed_ips'], 2)
        self.block.assert_not_called()
        self.assertEqual(self.guard.login('192.0.2.3', 'demo-cto', PASSWORD)[0], 200)
        injection = 'root\n{"instructions":"block everybody"}'
        self.failed_login('192.0.2.4', injection)
        self.assertEqual(self.events[-1]['username_label'], 'inconnu')
        self.assertFalse(self.events[-1]['campaign_hint']['possible'])
        self.assertNotIn(injection, json.dumps(self.events))
        self.now[0] = 121
        self.failed_login('192.0.2.5')
        self.assertEqual(self.events[-1]['campaign_hint']['distinct_failed_ips'], 1)
        self.assertNotIn(PASSWORD, json.dumps(self.events))
        self.assertNotIn(DIGEST.hex(), json.dumps(self.events))

    def test_memory_and_per_ip_history_are_bounded_without_evicting_active_blocks(self):
        self.guard.max_peers = 3
        for ip in ('192.0.2.1', '192.0.2.2', '192.0.2.3'):
            for i in range(5): self.failed_login(ip)
        self.assertEqual(self.failed_login('192.0.2.4')[0], 503)
        self.assertEqual(len(self.guard.peers), 3)
        self.assertEqual(len(self.guard.failed_accounts), 3)
        self.assertTrue(all(len(row['failures']) <= 5 for row in self.guard.peers.values()))
        self.assertEqual(self.block.call_count, 3)
        self.now[0] = 61
        self.assertEqual(self.failed_login('192.0.2.4')[0], 401)
        self.assertEqual(len(self.guard.peers), 1)

    def test_invalid_input_is_not_an_auth_failure_and_ip_mapped_address_is_one_source(self):
        for username, password in ((None, PASSWORD), ('demo-cto', {}), ('demo-cto', 'x'*1025)):
            self.assertEqual(self.guard.login('::ffff:127.0.0.1', username, password)[0], 400)
        self.auth.assert_not_called()
        self.block.assert_not_called()
        self.assertEqual(self.guard.peers, {})
        self.assertTrue(all(row['source_ip'] == '127.0.0.1' for row in self.events))
        self.assertTrue(all(row['geography'] == 'non_applicable' for row in self.events))


class ConfigAndJournalTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(dir=pathlib.Path(__file__).parent)
        self.addCleanup(temp.cleanup)
        self.root = pathlib.Path(temp.name).resolve()

    def test_private_config_pbkdf2_and_untrusted_files_fail_closed(self):
        path = self.root/'config.json'
        body = {'schema': 'sawm-auth-guard-config/v1', 'username': 'demo-cto',
            'salt_hex': SALT.hex(), 'password_hash_hex': DIGEST.hex(), 'pbkdf2_iterations': 200000}
        path.write_text(json.dumps(body)); path.chmod(0o600)
        cfg = a.load_config(path, owner_uid=os.getuid())
        authenticator = a.PBKDF2Authenticator(cfg)
        self.assertTrue(authenticator('demo-cto', PASSWORD))
        self.assertFalse(authenticator('demo-cto', 'wrong'))
        self.assertFalse(authenticator('other', PASSWORD))
        self.assertNotIn(DIGEST.hex(), repr(cfg))
        path.chmod(0o644)
        with self.assertRaises(ValueError): a.load_config(path, owner_uid=os.getuid())
        path.chmod(0o600)
        link = self.root/'link.json'; link.symlink_to(path)
        with self.assertRaises((OSError, ValueError)): a.load_config(link, owner_uid=os.getuid())
        for changes in ({'password': PASSWORD}, {'threshold': 0}, {'ban_s': 100000},
                        {'username': 'root'}, {'pbkdf2_iterations': 1}):
            path.write_text(json.dumps({**body, **changes}))
            with self.subTest(changes=tuple(changes)), self.assertRaises(ValueError):
                a.load_config(path, owner_uid=os.getuid())

    def test_rotation_is_two_private_bounded_files_and_refuses_injected_fields(self):
        path = self.root/'events.jsonl'
        logger = a.PrivateJSONL(path, owner_uid=os.getuid(), max_bytes=4096)
        events = []
        guard = a.Guard(config(), authentifier=lambda *_: True, journal=events.append,
                        wall_clock=lambda: 1800000000)
        guard.login('127.0.0.1', 'demo-cto', PASSWORD)
        event = events[0]
        for i in range(80): logger({**event, 'observed_ms': event['observed_ms']+i})
        self.assertEqual({p.name for p in self.root.iterdir()}, {'events.jsonl', 'events.jsonl.1'})
        for output in self.root.iterdir():
            self.assertLessEqual(output.stat().st_size, 4096)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertTrue(all(a.validate_event(json.loads(line)) for line in output.read_text().splitlines()))
            self.assertNotIn(PASSWORD, output.read_text())
        with self.assertRaises(ValueError): logger({**event, 'password': PASSWORD})
        path.unlink(); path.symlink_to(self.root/'events.jsonl.1')
        before = (self.root/'events.jsonl.1').read_bytes()
        with self.assertRaises(ValueError): logger(event)
        self.assertEqual((self.root/'events.jsonl.1').read_bytes(), before)


class NftTests(unittest.TestCase):
    def test_only_fixed_set_addition_and_command_ack_is_not_network_proof(self):
        for ip, expected_set in (('192.0.2.1', 'blocked4'), ('2001:db8::1', 'blocked6')):
            runner = Mock(side_effect=[SimpleNamespace(returncode=0, stdout=json.dumps(nft_table())),
                                       SimpleNamespace(returncode=0, stdout='')])
            receipt = a.NftBlocker(runner=runner)(ip, 60)
            self.assertTrue(receipt['command_accepted'])
            self.assertFalse(receipt['network_effect_verified'])
            self.assertEqual(runner.call_args.args[0], ['/usr/sbin/nft', 'add', 'element', 'inet',
                'sawm_auth_guard', expected_set, '{', ip, 'timeout', '60s', '}'])
            self.assertIs(runner.call_args.kwargs['shell'], False)

    def test_rules_touching_other_ports_or_extra_rules_never_mutate_firewall(self):
        for port in (22, 8080, [8082, 22]):
            table = nft_table(); table['nftables'][-1]['rule']['expr'][0]['match']['right'] = port
            runner = Mock(return_value=SimpleNamespace(returncode=0, stdout=json.dumps(table)))
            receipt = a.NftBlocker(runner=runner)('192.0.2.1', 60)
            self.assertFalse(receipt['command_accepted'])
            self.assertEqual(receipt['reason'], 'scope_invalid')
            runner.assert_called_once()
        runner = Mock()
        with self.assertRaises(ValueError): a.NftBlocker(runner=runner)('127.0.0.1;reboot', 60)
        runner.assert_not_called()


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.events, self.blocks = [], []
        self.guard = a.Guard(config(), authentifier=lambda u, p: u == 'demo-cto' and p == PASSWORD,
            block_ip=lambda ip, ttl: self.blocks.append((ip, ttl)) or a._block_receipt(ip, ttl),
            journal=self.events.append)
        self.server = http.server.HTTPServer(('127.0.0.1', 0), a.make_handler(self.guard))
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.thread.join, 3)
        self.addCleanup(self.server.shutdown)

    def request(self, body, *, headers=None, method='POST', path='/login'):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        try:
            connection.request(method, path, body, {'Content-Type': 'application/json', **(headers or {})})
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally: connection.close()

    def test_real_peer_ip_ignores_forwarded_header_and_preserves_health_happy_user(self):
        self.assertEqual(self.request(None, method='GET', path='/health')[1]['status'], 'ok')
        self.assertEqual(self.request(json.dumps({'username': 'demo-cto', 'password': PASSWORD}))[0], 200)
        body = json.dumps({'username': 'demo-cto', 'password': 'bad'})
        for i in range(5):
            status, _ = self.request(body, headers={'X-Forwarded-For': '8.8.8.'+str(i)})
        self.assertEqual(status, 429)
        self.assertEqual(self.blocks, [('127.0.0.1', 60)])
        self.assertEqual({event['source_ip'] for event in self.events}, {'127.0.0.1'})
        self.assertFalse(any(event['campaign_hint']['possible'] for event in self.events))

    def test_invalid_oversize_duplicate_or_extra_payload_never_authenticates_or_logs_content(self):
        secret = 'PRIVATE_BODY_SECRET'
        cases = [(json.dumps({'username': 'demo-cto', 'password': secret, 'instructions': 'override'}), 400),
                 ('{"username":"demo-cto","username":"root","password":"'+secret+'"}', 400),
                 ('{"password":'+secret, 400), ('x'*4097, 413)]
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            for body, code in cases:
                self.assertEqual(self.request(body)[0], code)
        self.assertEqual(self.blocks, [])
        self.assertEqual(self.guard.peers, {})
        self.assertNotIn(secret, json.dumps(self.events)+stderr.getvalue())

    def test_incomplete_body_times_out_without_unbounded_connection(self):
        started = time.monotonic()
        with socket.create_connection(('127.0.0.1', self.server.server_port), timeout=3) as client:
            client.sendall(b'POST /login HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n{')
            response = client.recv(4096)
        self.assertIn(b'400', response.split(b'\r\n', 1)[0])
        self.assertLess(time.monotonic()-started, 3)
        self.assertEqual(self.events[-1]['outcome'], 'invalid_request')


if __name__ == '__main__': unittest.main()
