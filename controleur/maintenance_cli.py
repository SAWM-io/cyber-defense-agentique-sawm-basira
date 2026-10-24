"""CLI locale de maintenance. Aucun appel Cloud et aucune commande de service.

keygen/sign n'accordent aucun droit. install/revoke exigent root et utilisent
le verrou de l'exécuteur. La clé doit être enregistrée au préalable, avec ses
portées, dans le manifeste root. Le principal est lié à sa clé, jamais à UID 0.
"""
from __future__ import annotations
import argparse
import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from controleur.maintenance import (MandatInvalide, POLICY_SCHEMA, _verifier,
    canonique, evaluate, signer)

MAX_FILE = 1024 * 1024


def _read(path, *, private=False, root=False):
    path = Path(path)
    if path.absolute() != path.resolve():
        raise MandatInvalide('chemin_symbolique_interdit')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as f:
        s = os.fstat(f.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1:
            raise MandatInvalide('fichier_non_regulier')
        if private and (s.st_uid != os.geteuid() or stat.S_IMODE(s.st_mode) != 0o600):
            raise MandatInvalide('cle_privee_proprietaire_ou_mode_invalide')
        if root and (s.st_uid != 0 or s.st_mode & 0o022):
            raise MandatInvalide('manifeste_non_protege')
        data = f.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise MandatInvalide('fichier_trop_grand')
    return data


def _new_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def _replace(path, data):
    fd, temporary = tempfile.mkstemp(prefix='.maintenance-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        Path(temporary).unlink(missing_ok=True)


@contextlib.contextmanager
def _locked_manifest(path):
    if os.geteuid() != 0:
        raise MandatInvalide('installation_reservee_root')
    path = Path(path).absolute()
    if path.resolve() != path:
        raise MandatInvalide('chemin_symbolique_interdit')
    # Toutes les composantes protègent le renommage, pas seulement le fichier.
    for parent in path.parents:
        s = parent.stat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise MandatInvalide('dossier_manifeste_non_protege')
    fd = os.open(path.parent / '.executeur.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_nlink != 1 or s.st_mode & 0o022:
            raise MandatInvalide('verrou_non_protege')
        fcntl.flock(fd, fcntl.LOCK_EX)
        manifest = json.loads(_read(path, root=True))
        policy = manifest.get('maintenance')
        if not isinstance(policy, dict) or policy.get('schema') != POLICY_SCHEMA:
            raise MandatInvalide('politique_absente')
        yield manifest, policy
        _replace(path, canonique(manifest) + b'\n')
    finally:
        os.close(fd)


def install(manifest_path, envelope, *, now_ms=None):
    now = int(time.time()*1000) if now_ms is None else now_ms
    with _locked_manifest(manifest_path) as (manifest, policy):
        payload = _verifier(envelope, policy)
        if payload['generation'] != str(manifest.get('generation')) or payload['machine_id'] != policy.get('machine_id'):
            raise MandatInvalide('mandat_autre_generation_ou_machine')
        if payload['issued_at_ms'] > now or payload['expires_at_ms'] <= now:
            raise MandatInvalide('mandat_expire_ou_futur')
        maximum = policy.get('max_duration_ms', 3600000)
        if type(maximum) is not int or not 1 <= maximum <= 86400000 or payload['expires_at_ms']-payload['issued_at_ms'] > maximum:
            raise MandatInvalide('duree_non_deleguee')
        mandates = policy.get('mandates')
        revoked = policy.get('revoked_mandates')
        if not isinstance(mandates, list) or len(mandates) >= 256 or not isinstance(revoked, list):
            raise MandatInvalide('registre_mandats_invalide')
        if payload['mandate_id'] in revoked or any(e.get('payload', {}).get('mandate_id') == payload['mandate_id'] for e in mandates):
            raise MandatInvalide('mandat_deja_present_ou_revoque')
        mandates.append(envelope)
    return {'installed': True, 'mandate_id': payload['mandate_id'], 'principal': payload['principal'], 'requires_fresh_os_verification': True}


def revoke(manifest_path, mandate_id, key, principal, *, now_ms=None):
    now = int(time.time()*1000) if now_ms is None else now_ms
    with _locked_manifest(manifest_path) as (manifest, policy):
        matches = [e for e in policy.get('mandates', []) if e.get('payload', {}).get('mandate_id') == mandate_id]
        if len(matches) != 1:
            raise MandatInvalide('mandat_absent_ou_ambigu')
        p = _verifier(matches[0], policy)
        raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if p['principal'] != principal or p['key_id'] != hashlib.sha256(raw).hexdigest():
            raise MandatInvalide('revocation_reservee_au_principal_signataire')
        revoked = policy.get('revoked_mandates')
        if not isinstance(revoked, list):
            raise MandatInvalide('registre_revocations_invalide')
        if mandate_id not in revoked:
            revoked.append(mandate_id)
            receipt = {'schema': 'sawm-maintenance-revocation/v1', 'mandate_id': mandate_id,
                'principal': principal, 'key_id': p['key_id'], 'generation': str(manifest['generation']),
                'machine_id': policy['machine_id'], 'revoked_at_ms': now}
            policy.setdefault('revocation_receipts', []).append({'payload': receipt,
                'signature': base64.b64encode(key.sign(canonique(receipt))).decode()})
    return {'revoked': True, 'mandate_id': mandate_id, 'principal': principal}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('keygen'); p.add_argument('--key', required=True)
    p = commands.add_parser('sign'); p.add_argument('--key', required=True); p.add_argument('--payload', required=True); p.add_argument('--out', required=True)
    p = commands.add_parser('install'); p.add_argument('--manifest', required=True); p.add_argument('--envelope', required=True)
    p = commands.add_parser('revoke'); p.add_argument('--manifest', required=True); p.add_argument('--key', required=True); p.add_argument('--principal', required=True); p.add_argument('--mandate-id', required=True)
    p = commands.add_parser('verify'); p.add_argument('--manifest', required=True); p.add_argument('--observation', required=True); p.add_argument('--unit', required=True); p.add_argument('--operation', required=True); p.add_argument('--object-path', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'keygen':
            key = Ed25519PrivateKey.generate()
            _new_file(args.key, key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
            public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            result = {'public_key': base64.b64encode(public).decode(), 'key_id': hashlib.sha256(public).hexdigest(), 'authority_registered': False}
        elif args.command == 'sign':
            key = Ed25519PrivateKey.from_private_bytes(_read(args.key, private=True))
            envelope = signer(json.loads(_read(args.payload)), key)
            _new_file(args.out, canonique(envelope) + b'\n')
            result = {'signed': True, 'mandate_id': envelope['payload']['mandate_id'], 'authority_registered': False}
        elif args.command == 'install':
            result = install(args.manifest, json.loads(_read(args.envelope)))
        elif args.command == 'revoke':
            result = revoke(args.manifest, args.mandate_id, Ed25519PrivateKey.from_private_bytes(_read(args.key, private=True)), args.principal)
        else:
            # Offline verifier: files are supplied by the operator, never an authorization service.
            result = {**evaluate(json.loads(_read(args.manifest)), json.loads(_read(args.observation)),
                unit=args.unit, operation=args.operation, object_path=args.object_path), 'offline_check_only': True}
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (MandatInvalide, OSError, ValueError, TypeError, KeyError) as exc:
        print(json.dumps({'ok': False, 'reason': str(exc)}, ensure_ascii=False))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
