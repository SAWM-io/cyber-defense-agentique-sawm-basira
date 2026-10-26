"""Sonde de configuration Linux en lecture seule, bornée et sans données brutes.

Ces critères sont une base technique locale, pas une certification. Les commandes
sont fixes ; aucun texte observé, nom de fichier ou conseil du modèle n'est exécuté.
Le rafraîchissement hors du fil de télémétrie évite de retarder les autres capteurs.
"""
from __future__ import annotations

import copy
import math
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import threading
import time

SCHEMA = 'sawm-posture-os/v1'
TTL_SECONDS = 60
COMMAND_TIMEOUT = 2.0
MAX_OUTPUT = 16384
SSHD = ('/usr/sbin/sshd', '-T')
AUDITD = ('/usr/bin/systemctl', 'is-active', 'auditd.service')
NTP = ('/usr/bin/timedatectl', 'show', '--property=NTPSynchronized', '--value')
COMMANDS = frozenset((SSHD, AUDITD, NTP))
SYSCTLS = (
    ('os_aslr', '/proc/sys/kernel/randomize_va_space', '2', lambda x: x == 2),
    ('os_kptr_restrict', '/proc/sys/kernel/kptr_restrict', '>= 1', lambda x: x >= 1),
    ('os_dmesg_restrict', '/proc/sys/kernel/dmesg_restrict', '1', lambda x: x == 1),
    ('os_ptrace_scope', '/proc/sys/kernel/yama/ptrace_scope', '>= 1', lambda x: x >= 1),
    ('os_protected_hardlinks', '/proc/sys/fs/protected_hardlinks', '1', lambda x: x == 1),
    ('os_protected_symlinks', '/proc/sys/fs/protected_symlinks', '1', lambda x: x == 1),
)
SSH_KEYS = (
    ('os_ssh_root_login', 'permitrootlogin', 'no'),
    ('os_ssh_password_auth', 'passwordauthentication', 'no'),
    ('os_ssh_empty_passwords', 'permitemptypasswords', 'no'),
    ('os_ssh_max_authtries', 'maxauthtries', '<= 4'),
)
SYSCTL_LIMIT = 'Valeur courante ; persistance au redémarrage et couverture du noyau non vérifiées.'
SSH_LIMIT = 'Configuration globale sshd -T ; règles Match et sessions existantes non évaluées.'
AUDIT_LIMIT = 'État systemd seulement ; règles audit, pertes et intégrité des journaux non démontrées.'
NTP_LIMIT = 'Indication timedatectl ; identité de la source de temps et précision absolue non vérifiées.'


def status_for(control_id, value):
    """Recalcul pur côté contrôleur ; un statut transmis ne fait pas autorité."""
    if type(control_id) is not str:
        return 'inconnu'
    ranges = {'os_aslr': range(3), 'os_kptr_restrict': range(3),
              'os_dmesg_restrict': range(2), 'os_ptrace_scope': range(4),
              'os_protected_hardlinks': range(2), 'os_protected_symlinks': range(2)}
    for identifier, _, _, predicate in SYSCTLS:
        if control_id == identifier:
            if type(value) is not int or value not in ranges[identifier]:
                return 'inconnu'
            return 'satisfait' if predicate(value) else 'ecart'
    if control_id == 'os_ssh_max_authtries':
        if type(value) is not int or not 0 <= value <= 9999:
            return 'inconnu'
        return 'satisfait' if value <= 4 else 'ecart'
    accepted = {
        'os_ssh_root_login': ({'yes', 'no', 'prohibit-password', 'without-password', 'forced-commands-only'}, 'no'),
        'os_ssh_password_auth': ({'yes', 'no'}, 'no'),
        'os_ssh_empty_passwords': ({'yes', 'no'}, 'no'),
        'os_auditd_active': ({'active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading'}, 'active'),
        'os_ntp_synchronized': ({'yes', 'no'}, 'yes'),
    }
    if control_id not in accepted or type(value) is not str:
        return 'inconnu'
    options, expected = accepted[control_id]
    return ('satisfait' if value == expected else 'ecart') if value in options else 'inconnu'


def _millis(wall):
    return int(wall * 1000) if type(wall) in (int, float) and math.isfinite(wall) and wall >= 0 else None


def _row(identifier, source, expected, limitation, value=None, satisfied=None):
    return {'id': identifier, 'status': 'inconnu' if satisfied is None else 'satisfait' if satisfied else 'ecart',
            'source': source, 'observed_value': value, 'expected': expected, 'limitation': limitation}


def unknown(observed_ms, reason='Observation indisponible.'):
    rows = [_row(i, p, e, reason + ' ' + SYSCTL_LIMIT) for i, p, e, _ in SYSCTLS]
    rows += [_row(i, 'sshd -T: ' + key, expected, reason + ' ' + SSH_LIMIT) for i, key, expected in SSH_KEYS]
    rows += [_row('os_auditd_active', 'systemctl is-active auditd.service', 'active', reason + ' ' + AUDIT_LIMIT),
             _row('os_ntp_synchronized', 'timedatectl NTPSynchronized', 'yes', reason + ' ' + NTP_LIMIT)]
    return {'schema': SCHEMA, 'observed_ms': observed_ms, 'controls': rows}


def _read_file(path):
    if path not in {entry[1] for entry in SYSCTLS}:
        raise ValueError('chemin de sonde interdit')
    with Path(path).open('rb') as file:
        raw = file.read(65)
    if len(raw) > 64:
        raise ValueError('valeur de configuration trop longue')
    return raw.decode('ascii')


def _run_command(command):
    """Lire au plus 16 KiB ; durée et mémoire bornées, stderr jamais exporté."""
    if type(command) is not tuple or command not in COMMANDS:
        raise ValueError('commande de sonde interdite')
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, shell=False, close_fds=True,
                               env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    selector = selectors.DefaultSelector()
    end = time.monotonic() + COMMAND_TIMEOUT
    data = bytearray()
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('sonde trop lente')
            if not selector.select(remaining):
                raise TimeoutError('sonde trop lente')
            chunk = os.read(process.stdout.fileno(), min(4096, MAX_OUTPUT + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_OUTPUT:
                raise ValueError('sortie de sonde trop longue')
        code = process.wait(timeout=max(.01, end - time.monotonic()))
        return code, bytes(data).decode('utf-8', errors='strict')
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
        process.wait(timeout=1)
        process.stdout.close()


def _integer(raw):
    if type(raw) is not str or not re.fullmatch(r'\s*[0-9]{1,4}\s*', raw):
        return None
    return int(raw.strip())


def _command(runner, command, codes):
    try:
        result = runner(command)
        if type(result) is not tuple or len(result) != 2:
            return None
        code, output = result
        if type(code) is not int or code not in codes or type(output) is not str or len(output.encode()) > MAX_OUTPUT:
            return None
        if command == AUDITD and ((code == 0) != (output.strip() == 'active')):
            return None
        return output
    except Exception:
        return None


def collect(*, read_file=None, run_command=None, platform=None, observed_ms=None):
    """Lecture complète injectable pour les tests ; aucune modification système."""
    stamp = _millis(time.time()) if observed_ms is None else observed_ms
    result = unknown(stamp)
    if (sys.platform if platform is None else platform) != 'linux':
        return unknown(stamp, 'Sonde Linux non applicable à cet hôte.')
    reader, runner = read_file or _read_file, run_command or _run_command
    rows = {row['id']: row for row in result['controls']}
    for identifier, path, expected, predicate in SYSCTLS:
        try:
            value = _integer(reader(path))
        except Exception:
            value = None
        if value is not None:
            rows[identifier].update(status=status_for(identifier, value),
                                    observed_value=value, limitation=SYSCTL_LIMIT)
    ssh = _command(runner, SSHD, {0})
    values = {}
    if ssh is not None:
        wanted = {item[1] for item in SSH_KEYS}
        for line in ssh.splitlines():
            parts = line.split(None, 1)
            if parts and parts[0] in wanted:
                key = parts[0]
                # Une clé dupliquée, même identique, ne vaut pas une mesure claire.
                values[key] = None if key in values or len(parts) != 2 else parts[1].strip()
    allowed = {'permitrootlogin': {'yes', 'no', 'prohibit-password', 'without-password', 'forced-commands-only'},
               'passwordauthentication': {'yes', 'no'}, 'permitemptypasswords': {'yes', 'no'}}
    for identifier, key, expected in SSH_KEYS:
        value = values.get(key)
        if key == 'maxauthtries':
            value = _integer(value)
        else:
            value = value if value in allowed[key] else None
        if value is not None:
            rows[identifier].update(status=status_for(identifier, value), observed_value=value, limitation=SSH_LIMIT)
    audit = _command(runner, AUDITD, {0, 3})
    audit = audit.strip() if audit is not None else None
    if audit in {'active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading'}:
        rows['os_auditd_active'].update(status=status_for('os_auditd_active', audit), observed_value=audit, limitation=AUDIT_LIMIT)
    ntp = _command(runner, NTP, {0})
    ntp = ntp.strip() if ntp is not None else None
    if ntp in {'yes', 'no'}:
        rows['os_ntp_synchronized'].update(status=status_for('os_ntp_synchronized', ntp), observed_value=ntp, limitation=NTP_LIMIT)
    return result


class PostureCache:
    """Cache 60 s ; lectures en arrière-plan, aucune attente dans la télémétrie."""
    def __init__(self, *, loader=collect, wall=time.time, monotone=time.monotonic):
        self.loader, self.wall, self.monotone = loader, wall, monotone
        self._lock = threading.Lock()
        self._cached, self._since, self._worker = None, None, None

    def _refresh(self):
        started_ms = _millis(self.wall())
        try:
            result = self.loader(observed_ms=started_ms)
        except Exception:
            result = unknown(started_ms)
        with self._lock:
            self._cached, self._since = copy.deepcopy(result), self.monotone()

    def snapshot(self):
        now_ms, mono = _millis(self.wall()), self.monotone()
        with self._lock:
            old = self._cached
            stamp = old.get('observed_ms') if type(old) is dict else None
            valid = (type(stamp) is int and type(now_ms) is int and 0 <= now_ms-stamp < TTL_SECONDS*1000
                     and self._since is not None and 0 <= mono-self._since < TTL_SECONDS)
            # Refresh before expiry without relabelling the still-valid old proof.
            # This avoids manufacturing a coverage incident on every cache cycle.
            refresh_due = not valid or now_ms-stamp >= TTL_SECONDS*800
            if refresh_due and (self._worker is None or not self._worker.is_alive()):
                self._worker = threading.Thread(target=self._refresh, daemon=True, name='sawm-posture-readonly')
                self._worker.start()
            if valid:
                return copy.deepcopy(old)
            return unknown(now_ms, 'Observation en cours ou précédente devenue périmée.')


_CACHE = PostureCache()


def snapshot():
    try:
        return _CACHE.snapshot()
    except Exception:
        return unknown(_millis(time.time()))
