"""Mandats de maintenance Ed25519 : capacité exacte, temporaire et révocable.

Le manifeste, l'horloge et l'observation OS doivent provenir du contrôleur
fiable, jamais du LLM ni du corps d'une demande utilisateur. Une signature
prouve la possession d'une clé institutionnelle enregistrée ; un UID ne prouve
pas l'identité humaine. Le module ne lance aucune commande et ne modifie pas
le manifeste. Revérifier juste avant une intervention, sous son verrou.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from pathlib import PurePosixPath

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA = 'sawm-maintenance/v1'
POLICY_SCHEMA = 'sawm-maintenance-policy/v1'
OPERATIONS = frozenset({'sqlite-exclusive-lock', 'file-read', 'file-write', 'file-replace', 'file-delete'})
RESTRICTIVE = frozenset({'arreter-service', 'geler-transfert', 'limiter-cpu', 'refuser-inode'})
TOKEN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$')
UNIT = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.@-]{0,100}\.service$')
PAYLOAD_KEYS = frozenset({'schema', 'mandate_id', 'principal', 'key_id', 'generation',
    'machine_id', 'boot_id', 'unit', 'invocation_id', 'pid', 'process_start_ticks',
    'uid', 'cgroup', 'object', 'operation', 'issued_at_ms', 'not_before_ms', 'expires_at_ms'})
OBS_KEYS = ('machine_id', 'boot_id', 'unit', 'invocation_id', 'pid', 'process_start_ticks', 'uid', 'cgroup', 'object')


class MandatInvalide(ValueError):
    pass


def canonique(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def _int(value, minimum=0):
    return type(value) is int and value >= minimum


def _token(value):
    return isinstance(value, str) and bool(TOKEN.fullmatch(value))


def _path(value):
    return (isinstance(value, str) and len(value) <= 4096 and '\x00' not in value
            and value.startswith('/') and value != '/' and '*' not in value
            and str(PurePosixPath(value)) == value and '..' not in PurePosixPath(value).parts)


def _object(value):
    return (isinstance(value, dict) and set(value) == {'path', 'device', 'inode'}
            and _path(value['path']) and _int(value['device']) and _int(value['inode'], 1))


def _validate_payload(p):
    if not isinstance(p, dict) or set(p) != PAYLOAD_KEYS or p.get('schema') != SCHEMA:
        raise MandatInvalide('contrat_invalide')
    if any(not _token(p[k]) for k in ('mandate_id', 'principal', 'generation', 'machine_id', 'boot_id', 'invocation_id')):
        raise MandatInvalide('identifiant_invalide')
    if not isinstance(p['key_id'], str) or not re.fullmatch('[0-9a-f]{64}', p['key_id']):
        raise MandatInvalide('cle_invalide')
    if not isinstance(p['unit'], str) or not UNIT.fullmatch(p['unit']):
        raise MandatInvalide('unite_invalide')
    if not _path(p['cgroup']) or PurePosixPath(p['cgroup']).name != p['unit']:
        raise MandatInvalide('cgroup_invalide')
    if any(not _int(p[k], 1) for k in ('pid', 'process_start_ticks', 'issued_at_ms', 'not_before_ms', 'expires_at_ms')) or not _int(p['uid']):
        raise MandatInvalide('nombre_invalide')
    if not p['issued_at_ms'] <= p['not_before_ms'] < p['expires_at_ms']:
        raise MandatInvalide('fenetre_invalide')
    if not isinstance(p['operation'], str) or p['operation'] not in OPERATIONS or not _object(p['object']):
        raise MandatInvalide('portee_invalide')


def public_key_record(key: Ed25519PrivateKey, principal: str, *, units, operations, objects):
    """Prépare une entrée publique ; seul l'administrateur l'ajoute au manifeste."""
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {'principal': principal, 'key_id': hashlib.sha256(raw).hexdigest(),
            'public_key': base64.b64encode(raw).decode(), 'enabled': True,
            'units': list(units), 'operations': list(operations), 'objects': list(objects)}


def signer(payload, key: Ed25519PrivateKey):
    _validate_payload(payload)
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if payload['key_id'] != hashlib.sha256(raw).hexdigest():
        raise MandatInvalide('cle_privee_differente')
    # Copie canonique : modifier le dictionnaire appelant ne modifie pas l'enveloppe.
    frozen = json.loads(canonique(payload))
    return {'payload': frozen, 'signature': base64.b64encode(key.sign(canonique(frozen))).decode()}


def _verifier(envelope, policy):
    if not isinstance(envelope, dict) or set(envelope) != {'payload', 'signature'}:
        raise MandatInvalide('enveloppe_invalide')
    p = envelope['payload']
    _validate_payload(p)
    keys = policy.get('keys')
    if not isinstance(keys, list) or len(keys) > 256:
        raise MandatInvalide('registre_cles_invalide')
    matches = [k for k in keys if isinstance(k, dict) and k.get('key_id') == p['key_id']]
    if len(matches) != 1:
        raise MandatInvalide('cle_absente_ou_ambigue')
    k = matches[0]
    if k.get('enabled') is not True or k.get('principal') != p['principal']:
        raise MandatInvalide('principal_non_autorise')
    for collection, value in (('units', p['unit']), ('operations', p['operation']), ('objects', p['object']['path'])):
        if not isinstance(k.get(collection), list) or value not in k[collection]:
            raise MandatInvalide('portee_non_deleguee')
    try:
        raw = base64.b64decode(k['public_key'], validate=True)
        if hashlib.sha256(raw).hexdigest() != p['key_id']:
            raise ValueError('empreinte')
        Ed25519PublicKey.from_public_bytes(raw).verify(base64.b64decode(envelope['signature'], validate=True), canonique(p))
    except (KeyError, ValueError, TypeError, InvalidSignature):
        raise MandatInvalide('signature_invalide') from None
    return p


def evaluate(manifest, observation, *, unit, operation, object_path, now_ms=None):
    """Autorise une opération précise ; aucun résultat négatif ne prouve un malware.

    Aucun mode compatible ne remplace une identité, une signature ou une date
    manquante. Les anciennes politiques restent la responsabilité du garde
    legacy, distinct et seulement si `maintenance` est absent du manifeste.
    """
    def denied(reason):
        return {'authorized': False, 'reason': reason}
    try:
        policy = manifest.get('maintenance')
        if not isinstance(policy, dict) or policy.get('schema') != POLICY_SCHEMA:
            return denied('politique_absente_ou_invalide')
        if operation not in OPERATIONS or not _path(object_path) or not isinstance(unit, str) or not UNIT.fullmatch(unit):
            return denied('requete_invalide')
        now = int(time.time()*1000) if now_ms is None else now_ms
        if not _int(now, 1):
            return denied('horloge_invalide')
        max_age = policy.get('max_observation_age_ms', 1500)
        max_duration = policy.get('max_duration_ms', 3600000)
        if not _int(max_age, 1) or max_age > 5000 or not _int(max_duration, 1) or max_duration > 86400000:
            return denied('bornes_invalides')
        if not isinstance(observation, dict) or observation.get('identity_stable') is not True:
            return denied('identite_os_non_verifiee')
        observed = observation.get('observed_at_ms')
        if not _int(observed, 1) or not 0 <= now - observed <= max_age:
            return denied('observation_perimee_ou_future')
        mandates = policy.get('mandates')
        revoked = policy.get('revoked_mandates')
        if not isinstance(mandates, list) or len(mandates) > 256 or not isinstance(revoked, list) or any(not _token(x) for x in revoked):
            return denied('registre_mandats_invalide')
        # Un identifiant de mandat ambigu invalide le registre, pas seulement la première occurrence.
        ids = [e.get('payload', {}).get('mandate_id') for e in mandates if isinstance(e, dict) and isinstance(e.get('payload'), dict)]
        if len(ids) != len(mandates) or len(set(ids)) != len(ids):
            return denied('registre_mandats_ambigu')
        reason = 'aucun_mandat_pour_operation'
        for envelope in mandates:
            p = envelope.get('payload', {})
            if (p.get('unit'), p.get('operation'), p.get('object', {}).get('path')) != (unit, operation, object_path):
                continue
            try:
                p = _verifier(envelope, policy)
                if p['mandate_id'] in revoked:
                    raise MandatInvalide('mandat_revoque')
                if p['generation'] != str(manifest.get('generation')) or p['machine_id'] != policy.get('machine_id'):
                    raise MandatInvalide('mandat_autre_generation_ou_machine')
                if not p['issued_at_ms'] <= now or not p['not_before_ms'] <= now < p['expires_at_ms']:
                    raise MandatInvalide('mandat_expire_ou_futur')
                if p['expires_at_ms'] - p['issued_at_ms'] > max_duration:
                    raise MandatInvalide('duree_non_deleguee')
                if any(observation.get(k) != p[k] or type(observation.get(k)) is not type(p[k]) for k in OBS_KEYS):
                    raise MandatInvalide('identite_os_ou_objet_different')
                # equality on nested dictionaries treats bool as int; reject malformed OS object explicitly.
                if not _object(observation.get('object')):
                    raise MandatInvalide('objet_os_invalide')
                return {'authorized': True, 'reason': 'mandat_signe_valide', 'mandate_id': p['mandate_id'],
                        'principal': p['principal'], 'key_id': p['key_id'], 'operation': p['operation'],
                        'expires_at_ms': p['expires_at_ms'], 'signature_verified': True}
            except MandatInvalide as exc:
                reason = str(exc)
        return denied(reason)
    except (ValueError, TypeError, KeyError, AttributeError):
        return denied('contrat_malforme')


def preservation(manifest, observation, *, unit, operation, object_path, now_ms=None):
    return evaluate(manifest, observation, unit=unit, operation=operation, object_path=object_path, now_ms=now_ms)['authorized']


def guard_proposition(manifest, observation, *, action, unit, operation, object_path, now_ms=None):
    """Veto d'une intervention sur l'opération couverte, jamais autorisation d'arrêter.

    `operation` doit être qualifiée par les capteurs/contrôleur et `observation`
    relue avant exécution. Un mandat file-write ne protège pas un verrou SQLite.
    Toute autre opération de ce processus reste soumise à sa propre politique.
    """
    decision = evaluate(manifest, observation, unit=unit, operation=operation, object_path=object_path, now_ms=now_ms)
    return {**decision, 'veto': action in RESTRICTIVE and decision['authorized'],
            'action': action, 'target': unit}


def observer_os(unit, path):
    """Observation Linux locale, deux lectures OS et aucun shell.

    L'identité humaine n'est pas déduite du compte Linux. `fd_on_object` et
    `kernel_locks` restent des observations ; l'appelant qualifie l'incident.
    Une erreur produit une exception à signaler, jamais une autorisation.
    """
    import os
    from pathlib import Path
    import stat
    import subprocess

    if not isinstance(unit, str) or not UNIT.fullmatch(unit) or not _path(path):
        raise MandatInvalide('cible_os_invalide')
    obj = Path(path)
    if obj.resolve() != obj:
        raise MandatInvalide('objet_symbolique_interdit')

    def state():
        result = subprocess.run(['/usr/bin/systemctl', 'show', '--property=Id,ActiveState,MainPID,InvocationID,ControlGroup', '--', unit],
            capture_output=True, text=True, timeout=2, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        if result.returncode or values.get('Id') != unit or values.get('ActiveState') != 'active' or not values.get('MainPID', '').isdigit() or int(values['MainPID']) <= 0:
            raise MandatInvalide('unite_os_non_active')
        return values

    def snapshot():
        state_now = state()
        pid = int(state_now['MainPID'])
        process = Path('/proc') / str(pid)
        raw = (process/'stat').read_text()
        # Field 22, after the final ')' of comm (which may itself contain ')').
        start = int(raw[raw.rfind(')')+2:].split()[19])
        status = dict(line.split(':', 1) for line in (process/'status').read_text().splitlines() if ':' in line)
        uid = int(status['Uid'].split()[1])  # effective UID; not a principal
        cgroups = (process/'cgroup').read_text().splitlines()
        if '0::'+state_now['ControlGroup'] not in cgroups:
            raise MandatInvalide('cgroup_os_divergent')
        fd = os.open(obj, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            s = os.fstat(fd)
            if not stat.S_ISREG(s.st_mode):
                raise MandatInvalide('objet_os_non_regulier')
        finally:
            os.close(fd)
        return {'machine_id': Path('/etc/machine-id').read_text().strip(),
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'unit': unit, 'invocation_id': state_now['InvocationID'], 'pid': pid,
            'process_start_ticks': start, 'uid': uid, 'cgroup': state_now['ControlGroup'],
            'object': {'path': path, 'device': s.st_dev, 'inode': s.st_ino}}

    before = snapshot()
    process = Path('/proc') / str(before['pid'])
    opened = False
    for entry in (process/'fd').iterdir():
        try:
            s = entry.stat()  # procfd links are kernel observations, deliberately followed
            if (s.st_dev, s.st_ino) == (before['object']['device'], before['object']['inode']):
                opened = True
        except FileNotFoundError:
            continue
    matching_locks = []
    for line in Path('/proc/locks').read_text().splitlines():
        fields = line.split()
        if len(fields) < 8 or fields[1] == '->' or fields[4] != str(before['pid']):
            continue
        try:
            major, minor, inode = fields[5].split(':')
            device = before['object']['device']
            if (int(major, 16), int(minor, 16), int(inode)) == (os.major(device), os.minor(device), before['object']['inode']):
                matching_locks.append(line)
        except ValueError:
            continue
    after = snapshot()
    if before != after:
        raise MandatInvalide('identite_os_changee_pendant_inspection')
    return {**after, 'identity_stable': True, 'observed_at_ms': int(time.time()*1000),
            'fd_on_object': opened, 'kernel_locks': matching_locks}


def _sqlite_busy(exc):
    """SQLITE_BUSY exact, y compris Python 3.10 sans attributs SQLite.

    Le code natif prime sur le texte. Sans code ni nom, seul le message SQLite
    canonique entier est accepté ; « table is locked » reste SQLITE_LOCKED.
    """
    import sqlite3
    if not isinstance(exc, sqlite3.OperationalError):
        return False
    code = getattr(exc, 'sqlite_errorcode', None)
    if code is not None:
        return type(code) is int and code == 5  # SQLite ABI: SQLITE_BUSY
    name = getattr(exc, 'sqlite_errorname', None)
    if name is not None:
        return name == 'SQLITE_BUSY'
    return str(exc) == 'database is locked'


def inspecter_operations(target, observation):
    """Qualifie localement intégrité et indisponibilité, sans attribuer une intention.

    Les opérations retournées peuvent coexister : le veto global exige alors
    un mandat pour chacune. Hash changé sans auteur attribué => erreur/alerte.
    Le test SQLite prend au plus 50 ms par opération (hors I/O/ordonnanceur).
    """
    import os
    import sqlite3
    import stat
    from urllib.parse import quote
    path = target.get('path')
    reference = target.get('reference_sha256')
    if not _path(path) or not isinstance(reference, str) or not re.fullmatch('[0-9a-f]{64}', reference):
        raise MandatInvalide('reference_locale_incomplete')
    maximum = target.get('max_integrity_bytes', 64*1024*1024)
    if not _int(maximum, 1) or maximum > 1024*1024*1024:
        raise MandatInvalide('budget_integrite_invalide')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    digest = hashlib.sha256()
    with os.fdopen(fd, 'rb') as f:
        first = os.fstat(f.fileno())
        if not stat.S_ISREG(first.st_mode) or first.st_size > maximum:
            raise MandatInvalide('objet_non_regulier_ou_budget_integrite_depasse')
        if (first.st_dev, first.st_ino) != (observation.get('object', {}).get('device'), observation.get('object', {}).get('inode')):
            raise MandatInvalide('objet_change_avant_inspection')
        total = 0
        while block := f.read(1024*1024):
            total += len(block)
            if total > maximum:
                raise MandatInvalide('budget_integrite_depasse')
            digest.update(block)
        last = os.fstat(f.fileno())
    if (first.st_size, first.st_mtime_ns, first.st_ctime_ns) != (last.st_size, last.st_mtime_ns, last.st_ctime_ns):
        raise MandatInvalide('objet_modifie_pendant_inspection')
    operations = []
    hash_changed = digest.hexdigest() != reference
    if hash_changed:
        if observation.get('fd_on_object') is not True:
            raise MandatInvalide('empreinte_changee_sans_processus_attribue')
        operations.append('file-write')
    busy = []
    if target.get('kind') == 'sqlite':
        for query in ('SELECT name FROM sqlite_master LIMIT 1', 'BEGIN IMMEDIATE'):
            connection = None
            try:
                connection = sqlite3.connect('file:'+quote(path, safe='/')+'?mode=rw', uri=True, timeout=.05)
                connection.execute(query).fetchall()
                connection.rollback()
                busy.append(False)
            except sqlite3.OperationalError as exc:
                if not _sqlite_busy(exc):
                    raise MandatInvalide('inspection_sqlite_non_busy') from None
                busy.append(True)
            finally:
                if connection is not None:
                    connection.close()
        if all(busy):
            exclusive = False
            for line in observation.get('kernel_locks', []):
                fields = line.split()
                try:
                    exclusive |= (len(fields) >= 8 and fields[1] == 'POSIX' and fields[3] == 'WRITE'
                        and fields[4] == str(observation.get('pid')) and int(fields[6]) <= 1073741826
                        and (fields[7] == 'EOF' or int(fields[7]) >= 1073742335))
                except (ValueError, IndexError):
                    continue
            if observation.get('fd_on_object') is not True or not exclusive:
                raise MandatInvalide('verrou_sqlite_non_attribue')
            operations.append('sqlite-exclusive-lock')
    return {'operations': operations, 'sha256': digest.hexdigest(), 'reference_matches': not hash_changed,
            'sqlite_busy': busy, 'attribution_limit': 'FD et identité OS concordants ; la causalité de chaque octet exige les événements écriture.'}
