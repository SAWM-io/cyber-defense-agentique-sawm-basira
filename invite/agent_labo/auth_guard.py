#!/usr/bin/env python3
"""Authentification fictive du laboratoire, port 8082 et exclusions temporaires.

Le compte demo-cto est un compte de cette fixture, jamais un compte Linux.
Le programme ne crée aucune règle nft : root prépare la table dédiée. Un
accusé nft n'est pas une mesure de l'effet réseau. Aucun accès SSH, fichier
utilisateur, autre port ou identité humaine n'est déduit de ces observations.
"""
from __future__ import annotations

import collections
import dataclasses
import hashlib
import hmac
import http.server
import ipaddress
import json
import math
import os
import pathlib
import re
import stat
import subprocess
import threading
import time

import os as _os
HOST, PORT = _os.environ.get('LABO_AUTH_BIND', '127.0.0.1'), 8082
CONFIG_PATH = pathlib.Path('/opt/sawm-labo/auth-guard/config.json')
LOG_PATH = pathlib.Path('/opt/sawm-labo/auth-guard/events.jsonl')
MAX_BODY, MAX_PEERS, CORRELATION_WINDOW = 4096, 1024, 120
MAX_LOG_BYTES = 1024*1024
_BLOCK_REASONS = frozenset({'scope_verified_command_accepted', 'nft_unavailable',
    'scope_invalid', 'nft_failed', 'callback_unavailable', 'callback_invalid'})
_OUTCOMES = frozenset({'authenticated', 'rejected', 'temporarily_blocked',
    'invalid_request', 'capacity_unavailable', 'auth_unavailable'})


def canonical_ip(value):
    if type(value) is not str or len(value) > 45 or '%' in value:
        raise ValueError('peer_ip_invalid')
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if address.is_multicast or address.is_unspecified:
        raise ValueError('peer_ip_invalid')
    return str(address)


def _bounded_int(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _safe_parent(path, owner_uid):
    if not path.is_absolute() or any(part in ('.', '..') for part in path.parts):
        raise ValueError('private_path_invalid')
    for parent in path.parents:
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, owner_uid)
                or info.st_mode & 0o022):
            raise ValueError('private_parent_untrusted')


def _regular_private(info, owner_uid):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise ValueError('private_file_untrusted')


@dataclasses.dataclass(frozen=True)
class AuthConfig:
    username: str
    salt: bytes = dataclasses.field(repr=False)
    password_hash: bytes = dataclasses.field(repr=False)
    pbkdf2_iterations: int = 600000
    threshold: int = 5
    window_s: int = 30
    ban_s: int = 60

    def __post_init__(self):
        if (self.username != 'demo-cto' or type(self.salt) is not bytes or not 16 <= len(self.salt) <= 32
                or type(self.password_hash) is not bytes or len(self.password_hash) != 32
                or not _bounded_int(self.pbkdf2_iterations, 200000, 1000000)
                or not _bounded_int(self.threshold, 3, 10)
                or not _bounded_int(self.window_s, 10, 120)
                or not _bounded_int(self.ban_s, 10, 300)):
            raise ValueError('auth_config_invalid')


def load_config(path=CONFIG_PATH, *, owner_uid=0):
    """Lecture root 0600, sans lien, contenu strict ; aucune exportation du hash."""
    path = pathlib.Path(path)
    _safe_parent(path, owner_uid)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _regular_private(os.fstat(fd), owner_uid)
        if os.fstat(fd).st_size > 8192:
            raise ValueError('auth_config_too_large')
        raw = os.read(fd, 8193)
        if len(raw) > 8192:
            raise ValueError('auth_config_too_large')
    finally:
        os.close(fd)
    try:
        obj = json.loads(raw, object_pairs_hook=_unique_object)
        required = {'schema', 'username', 'salt_hex', 'password_hash_hex', 'pbkdf2_iterations'}
        if (type(obj) is not dict or not required <= set(obj)
                or set(obj)-required-{'threshold', 'window_s', 'ban_s'}
                or obj['schema'] != 'sawm-auth-guard-config/v1'
                or type(obj['salt_hex']) is not str or not re.fullmatch(r'[a-f0-9]{32,64}', obj['salt_hex'])
                or len(obj['salt_hex']) % 2 or type(obj['password_hash_hex']) is not str
                or not re.fullmatch(r'[a-f0-9]{64}', obj['password_hash_hex'])):
            raise ValueError()
        return AuthConfig(obj['username'], bytes.fromhex(obj['salt_hex']),
            bytes.fromhex(obj['password_hash_hex']), obj['pbkdf2_iterations'],
            obj.get('threshold', 5), obj.get('window_s', 30), obj.get('ban_s', 60))
    except (ValueError, KeyError, TypeError, UnicodeError):
        raise ValueError('auth_config_invalid') from None


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate_json_key')
        result[key] = value
    return result


class PBKDF2Authenticator:
    def __init__(self, config):
        self.config = config

    def __call__(self, username, password):
        # Même dérivation pour un nom inconnu : le journal ne conserve que le label.
        digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'),
            self.config.salt, self.config.pbkdf2_iterations, dklen=32)
        matches = hmac.compare_digest(digest, self.config.password_hash)
        return hmac.compare_digest(username.encode('utf-8'), self.config.username.encode()) and matches


def _block_receipt(ip, ttl, reason='callback_unavailable', accepted=False):
    return {'schema': 'sawm-auth-block-receipt/v1', 'source_ip': ip, 'port': PORT,
        'set': 'blocked4' if ipaddress.ip_address(ip).version == 4 else 'blocked6',
        'ttl_s': ttl, 'command_accepted': accepted, 'network_effect_verified': False,
        'reason': reason}


def _validate_receipt(receipt, ip, ttl):
    template = _block_receipt(ip, ttl)
    if (type(receipt) is not dict or set(receipt) != set(template)
            or any(receipt[key] != template[key] for key in template
                   if key not in ('command_accepted', 'reason'))
            or type(receipt['command_accepted']) is not bool
            or not _bounded_int(receipt['ttl_s'], 10, 300) or type(receipt['port']) is not int
            or receipt['network_effect_verified'] is not False
            or receipt['reason'] not in _BLOCK_REASONS
            or receipt['command_accepted'] != (receipt['reason'] == 'scope_verified_command_accepted')):
        raise ValueError('block_receipt_invalid')
    return dict(receipt)


def nft_scope_valid(document):
    """Table fermée : deux sets, une chaîne input, deux drops limités à 8082."""
    try:
        entries = document['nftables']
        if type(entries) is not list or len(entries) > 16:
            return False
        objects = collections.defaultdict(list)
        for entry in entries:
            if type(entry) is not dict or len(entry) != 1:
                return False
            kind, value = next(iter(entry.items()))
            if kind == 'metainfo':
                continue
            if kind not in ('table', 'set', 'chain', 'rule') or type(value) is not dict:
                return False
            if value.get('family') != 'inet' or value.get('name' if kind == 'table' else 'table') != 'sawm_auth_guard':
                return False
            objects[kind].append(value)
        if [len(objects[k]) for k in ('table', 'set', 'chain', 'rule')] != [1, 2, 1, 2]:
            return False
        sets = {row['name']: row for row in objects['set']}
        if set(sets) != {'blocked4', 'blocked6'}:
            return False
        for name, address_type in (('blocked4', 'ipv4_addr'), ('blocked6', 'ipv6_addr')):
            row = sets[name]
            if row.get('type') != address_type or row.get('flags') != ['timeout'] or not _bounded_int(row.get('size'), 1, 4096):
                return False
        chain = objects['chain'][0]
        if (chain.get('name') != 'input' or chain.get('type') != 'filter'
                or chain.get('hook') != 'input' or chain.get('policy') != 'accept'):
            return False
        observed = set()
        for row in objects['rule']:
            if row.get('chain') != 'input' or type(row.get('expr')) is not list:
                return False
            expr = [item for item in row['expr'] if type(item) is not dict or set(item) != {'counter'}]
            for family, name in (('ip', 'blocked4'), ('ip6', 'blocked6')):
                expected = [
                    {'match': {'op': '==', 'left': {'payload': {'protocol': 'tcp', 'field': 'dport'}}, 'right': PORT}},
                    {'match': {'op': '==', 'left': {'payload': {'protocol': family, 'field': 'saddr'}}, 'right': '@'+name}},
                    {'drop': None}]
                if expr == expected:
                    observed.add(name)
                    break
            else:
                return False
        return observed == {'blocked4', 'blocked6'}
    except (KeyError, TypeError):
        return False


class NftBlocker:
    """Aucune création de règle ; seul add element est une mutation possible."""
    def __init__(self, *, runner=subprocess.run):
        self.runner = runner

    def __call__(self, source_ip, ttl_s):
        ip = canonical_ip(source_ip)
        if not _bounded_int(ttl_s, 10, 300):
            raise ValueError('block_ttl_invalid')
        receipt = _block_receipt(ip, ttl_s, 'nft_unavailable')
        try:
            check = self.runner(['/usr/sbin/nft', '-j', 'list', 'table', 'inet', 'sawm_auth_guard'],
                capture_output=True, text=True, timeout=2, shell=False)
            if check.returncode or len(check.stdout) > 262144:
                return receipt
            if not nft_scope_valid(json.loads(check.stdout)):
                return {**receipt, 'reason': 'scope_invalid'}
            result = self.runner(['/usr/sbin/nft', 'add', 'element', 'inet', 'sawm_auth_guard',
                receipt['set'], '{', ip, 'timeout', str(ttl_s)+'s', '}'],
                capture_output=True, text=True, timeout=2, shell=False)
            if result.returncode:
                return {**receipt, 'reason': 'nft_failed'}
            return {**receipt, 'command_accepted': True, 'reason': 'scope_verified_command_accepted'}
        except (OSError, subprocess.SubprocessError, ValueError, TypeError):
            return receipt


def validate_event(event):
    keys = {'schema', 'observed_ms', 'source_ip', 'username_label', 'endpoint', 'outcome',
            'geography', 'failures_in_window', 'block_receipt', 'campaign_hint'}
    if (type(event) is not dict or set(event) != keys or event['schema'] != 'sawm-auth-observation/v1'
            or not _bounded_int(event['observed_ms'], 1, 2**63-1)
            or event['source_ip'] != canonical_ip(event['source_ip'])
            or event['username_label'] not in ('demo-cto', 'inconnu')
            or event['endpoint'] != '/login' or event['outcome'] not in _OUTCOMES
            or event['geography'] not in ('non_applicable', 'inconnue')
            or not _bounded_int(event['failures_in_window'], 0, 10)):
        raise ValueError('auth_event_invalid')
    receipt = event['block_receipt']
    if receipt is not None:
        _validate_receipt(receipt, event['source_ip'], receipt.get('ttl_s'))
        if not _bounded_int(receipt.get('ttl_s'), 10, 300):
            raise ValueError('auth_event_invalid')
    hint = event['campaign_hint']
    if (type(hint) is not dict or set(hint) != {'possible', 'distinct_failed_ips', 'window_s', 'identity_established'}
            or type(hint['possible']) is not bool or hint['identity_established'] is not False
            or hint['window_s'] != CORRELATION_WINDOW
            or not _bounded_int(hint['distinct_failed_ips'], 0, MAX_PEERS)
            or hint['possible'] != (hint['distinct_failed_ips'] >= 2)):
        raise ValueError('auth_event_invalid')
    return json.loads(json.dumps(event, ensure_ascii=True, allow_nan=False))


class PrivateJSONL:
    """Deux fichiers au plus, chacun <=1MiB, 0600 ; champs publics fermés."""
    def __init__(self, path=LOG_PATH, *, owner_uid=0, max_bytes=MAX_LOG_BYTES):
        self.path = pathlib.Path(path)
        self.backup = self.path.with_name(self.path.name+'.1')
        self.owner_uid = owner_uid
        if not _bounded_int(max_bytes, 4096, MAX_LOG_BYTES):
            raise ValueError('journal_limit_invalid')
        self.max_bytes, self.lock = max_bytes, threading.RLock()
        _safe_parent(self.path, owner_uid)

    def __call__(self, event):
        raw = (json.dumps(validate_event(event), ensure_ascii=True, separators=(',', ':'))+'\n').encode()
        if len(raw) > self.max_bytes:
            raise ValueError('auth_event_too_large')
        with self.lock:
            _safe_parent(self.path, self.owner_uid)
            for path in (self.path, self.backup):
                try:
                    info = path.lstat()
                    _regular_private(info, self.owner_uid)
                    if info.st_size > self.max_bytes: raise ValueError('journal_existing_too_large')
                except FileNotFoundError: pass
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                info = os.fstat(fd)
                _regular_private(info, self.owner_uid)
                if info.st_size+len(raw) > self.max_bytes:
                    os.close(fd)
                    fd = None
                    os.replace(self.path, self.backup)
                    fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                offset = 0
                while offset < len(raw):
                    written = os.write(fd, raw[offset:])
                    if written <= 0: raise OSError('journal_write_failed')
                    offset += written
                os.fsync(fd)
            finally:
                if fd is not None: os.close(fd)


class Guard:
    def __init__(self, config, *, authentifier=None, block_ip=None, journal=None,
                 clock=time.monotonic, wall_clock=time.time, max_peers=MAX_PEERS):
        if not isinstance(config, AuthConfig) or not _bounded_int(max_peers, 1, MAX_PEERS):
            raise ValueError('guard_config_invalid')
        self.config = config
        self.authentifier = authentifier or PBKDF2Authenticator(config)
        self.block_ip = block_ip
        self.journal = journal
        self.clock, self.wall_clock, self.max_peers = clock, wall_clock, max_peers
        self.peers, self.failed_accounts = {}, {}
        self.lock = threading.RLock()
        self.journal_healthy = True

    def _prune(self, now):
        for ip, item in list(self.peers.items()):
            while item['failures'] and now-item['failures'][0] >= self.config.window_s:
                item['failures'].popleft()
            if item['until'] <= now and not item['failures']:
                del self.peers[ip]
        self.failed_accounts = {ip: when for ip, when in self.failed_accounts.items()
                                if now-when < CORRELATION_WINDOW}

    def _emit(self, ip, label, outcome, count, receipt=None):
        known = label == self.config.username
        count_ips = len(self.failed_accounts) if known else 0
        event = {'schema': 'sawm-auth-observation/v1', 'observed_ms': int(self.wall_clock()*1000),
            'source_ip': ip, 'username_label': label, 'endpoint': '/login', 'outcome': outcome,
            'geography': 'non_applicable' if not ipaddress.ip_address(ip).is_global else 'inconnue',
            'failures_in_window': count, 'block_receipt': receipt,
            'campaign_hint': {'possible': count_ips >= 2, 'distinct_failed_ips': count_ips,
                'window_s': CORRELATION_WINDOW, 'identity_established': False}}
        try:
            if self.journal is not None: self.journal(validate_event(event))
            self.journal_healthy = True
        except Exception:
            self.journal_healthy = False

    def invalid_request(self, peer_ip):
        ip = canonical_ip(peer_ip)
        with self.lock:
            self._prune(self.clock())
            self._emit(ip, 'inconnu', 'invalid_request', 0)
        return 400, {'status': 'invalid_request'}

    def login(self, peer_ip, username, password):
        ip = canonical_ip(peer_ip)
        if (type(username) is not str or not 1 <= len(username) <= 64
                or type(password) is not str or not 1 <= len(password) <= 1024):
            return self.invalid_request(ip)
        label = self.config.username if username == self.config.username else 'inconnu'
        with self.lock:
            now = self.clock()
            self._prune(now)
            peer = self.peers.get(ip)
            if peer is not None and peer['until'] > now:
                self._emit(ip, label, 'temporarily_blocked', len(peer['failures']), peer['receipt'])
                return 429, {'status': 'temporarily_blocked', 'retry_after_s': math.ceil(peer['until']-now)}
            if peer is None and len(self.peers) >= self.max_peers:
                self._emit(ip, label, 'capacity_unavailable', 0)
                return 503, {'status': 'temporarily_unavailable'}
            try:
                ok = self.authentifier(username, password)
                if type(ok) is not bool: raise ValueError('auth_result_invalid')
                ok = ok and username == self.config.username
            except Exception:
                self._emit(ip, label, 'auth_unavailable', 0)
                return 503, {'status': 'temporarily_unavailable'}
            if ok:
                self.peers.pop(ip, None)
                self._emit(ip, label, 'authenticated', 0)
                return (200, {'status': 'authenticated'}) if self.journal_healthy else (503, {'status': 'temporarily_unavailable'})
            if peer is None:
                peer = {'failures': collections.deque(maxlen=self.config.threshold), 'until': 0, 'receipt': None}
                self.peers[ip] = peer
            peer['failures'].append(now)
            if label == self.config.username:
                # Cette liste contient seulement des échecs réellement observés.
                # Pleine, elle n'accepte plus de nouvelle IP ; aucun autre état n'est évincé.
                if ip in self.failed_accounts or len(self.failed_accounts) < self.max_peers:
                    self.failed_accounts[ip] = now
            if len(peer['failures']) < self.config.threshold:
                self._emit(ip, label, 'rejected', len(peer['failures']))
                return 401, {'status': 'authentication_failed'}
            peer['until'] = now+self.config.ban_s
            receipt = _block_receipt(ip, self.config.ban_s)
            if self.block_ip is not None:
                try:
                    receipt = _validate_receipt(self.block_ip(ip, self.config.ban_s), ip, self.config.ban_s)
                except Exception:
                    receipt = _block_receipt(ip, self.config.ban_s, 'callback_invalid')
            peer['receipt'] = receipt
            self._emit(ip, label, 'temporarily_blocked', len(peer['failures']), receipt)
            return 429, {'status': 'temporarily_blocked', 'retry_after_s': self.config.ban_s}

    def health(self):
        return {'status': 'ok' if self.journal_healthy else 'degraded', 'service': 'labo-auth-guard', 'port': PORT}


def make_handler(guard):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.0'
        server_version = 'labo-auth-guard'
        sys_version = ''

        def setup(self):
            self.request.settimeout(2)
            super().setup()

        def log_message(self, *_args):
            pass  # Ni corps, ni URL libre, ni mot de passe dans stderr.

        def reply(self, status, value):
            raw = json.dumps(value, separators=(',', ':')).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Connection', 'close')
            if status == 429: self.send_header('Retry-After', str(value['retry_after_s']))
            self.end_headers()
            self.close_connection = True
            try: self.wfile.write(raw)
            except OSError: pass

        def send_error(self, code, message=None, explain=None):
            self.reply(code, {'status': 'invalid_request'})

        def do_GET(self):
            if self.path == '/health': self.reply(200, guard.health())
            else: self.reply(404, {'status': 'not_found'})

        def do_POST(self):
            if self.path != '/login':
                self.reply(404, {'status': 'not_found'})
                return
            peer = self.client_address[0]  # X-Forwarded-For n'est jamais consulté.
            lengths = self.headers.get_all('Content-Length', [])
            if (self.headers.get('Transfer-Encoding') is not None or len(lengths) != 1
                    or not re.fullmatch(r'[0-9]{1,5}', lengths[0])
                    or self.headers.get('Content-Type', '').split(';', 1)[0].strip().lower() != 'application/json'):
                self.reply(*guard.invalid_request(peer))
                return
            length = int(lengths[0])
            if length > MAX_BODY:
                guard.invalid_request(peer)
                self.reply(413, {'status': 'request_too_large'})
                return
            try:
                raw = self.rfile.read(length)
                if len(raw) != length: raise ValueError('incomplete_body')
                body = json.loads(raw, object_pairs_hook=_unique_object)
                if type(body) is not dict or set(body) != {'username', 'password'}:
                    raise ValueError('login_body_invalid')
            except (ValueError, UnicodeError, OSError, RecursionError):
                self.reply(*guard.invalid_request(peer))
                return
            self.reply(*guard.login(peer, body['username'], body['password']))
    return Handler


def main():
    if os.geteuid() != 0 or not pathlib.Path('/opt/sawm-labo/manifeste.json').is_file():
        raise SystemExit('root et installation du laboratoire requis')
    config = load_config()
    guard = Guard(config, block_ip=NftBlocker(), journal=PrivateJSONL())
    # Serveur séquentiel : aucun nombre de threads piloté par les clients.
    with http.server.HTTPServer((HOST, PORT), make_handler(guard)) as server:
        server.serve_forever(poll_interval=.25)


if __name__ == '__main__':
    main()
