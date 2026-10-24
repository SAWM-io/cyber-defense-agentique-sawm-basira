"""Preuves Ed25519 sur le contrôleur (Mac ou mode VM Linux locale explicite).

Une chaîne et un checkpoint signés détectent modification, ordre, suppression de
lignes et écriture incomplète. Le checkpoint doit être conservé avec les preuves.
Un propriétaire du contrôleur qui possède la clé peut signer de nouvelles preuves ; un
retour arrière simultané journal/checkpoint exige une ancre conservée ailleurs.
Aucune réparation, rotation de clé ou rétro-signature implicite d'anciens logs.
"""
from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
import time
import uuid

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
except ImportError as exc:
    raise RuntimeError('Audit signé indisponible : installer cryptography dans le runtime de veille') from exc

DEFAULT_KEY = Path.home()/'.sawm-labo/audit-ed25519.key'
ZERO = '0'*64
MAX_LINE = 65536
SECRET = re.compile(r'(password|passwd|secret|token|credential|authorization|api[_-]?key|private[_-]?key)', re.I)


class AuditInvalide(RuntimeError):
    """Preuve invalide : aucune nouvelle ligne ne doit être ajoutée."""


def canonique(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def _nettoyer(value, profondeur=0):
    if profondeur > 7:
        return '[profondeur limitée]'
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError('Nombre non fini interdit dans les preuves')
        return value
    if isinstance(value, str):
        return value if len(value) <= 2048 else value[:2048]+'[tronqué]'
    if isinstance(value, dict):
        result = {}
        for key, val in list(value.items())[:64]:
            if not isinstance(key, str) or len(key) > 128:
                raise ValueError('Clé de preuve invalide')
            result[key] = '[expurgé]' if SECRET.search(key) else _nettoyer(val, profondeur+1)
        if len(value) > 64:
            result['__champs_omis__'] = len(value)-64
        return result
    if isinstance(value, (tuple, list)):
        out = [_nettoyer(item, profondeur+1) for item in value[:64]]
        if len(value) > 64:
            out.append({'__elements_omis__': len(value)-64})
        return out
    raise ValueError('Seules des données JSON sont acceptées dans les preuves')


def _fichier_sur(path, *, prive=False):
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
        raise AuditInvalide('Fichier de preuve non régulier ou mauvais propriétaire')
    if st.st_nlink != 1:
        raise AuditInvalide('Lien matériel interdit pour les preuves')
    if prive and stat.S_IMODE(st.st_mode) != 0o600:
        raise AuditInvalide('La clé privée doit avoir le mode 0600')


def _fsync_dossier(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomique(path, data):
    fd, tmp = tempfile.mkstemp(prefix='.'+path.name+'.', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(tmp, path)
        _fsync_dossier(path.parent)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


@contextlib.contextmanager
def _verrou(path):
    fd = os.open(str(path)+'.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _signer(payload, key):
    raw = canonique(payload)
    return {**payload, 'sha256': hashlib.sha256(raw).hexdigest(),
            'signature': base64.b64encode(key.sign(raw)).decode('ascii')}


def _verifier_signature(obj, key):
    try:
        payload = {k: v for k, v in obj.items() if k not in ('sha256', 'signature')}
        raw = canonique(payload)
        if hashlib.sha256(raw).hexdigest() != obj['sha256']:
            raise ValueError('empreinte différente')
        key.verify(base64.b64decode(obj['signature'], validate=True), raw)
        return payload
    except (KeyError, ValueError, TypeError, InvalidSignature, AttributeError) as exc:
        raise AuditInvalide('Empreinte ou signature invalide') from exc


def _lecture_json(path):
    _fichier_sur(path)
    with path.open('rb') as file:
        data = file.read(MAX_LINE+1)
    if len(data) > MAX_LINE:
        raise AuditInvalide('Checkpoint trop grand')
    try:
        obj = json.loads(data)
    except (ValueError, UnicodeError) as exc:
        raise AuditInvalide('Checkpoint illisible') from exc
    if not isinstance(obj, dict):
        raise AuditInvalide('Checkpoint invalide')
    return obj


def _verifier(path, public_key_path, ancre=None):
    try:
        _fichier_sur(public_key_path)
        public_raw = public_key_path.read_bytes()
        key = Ed25519PublicKey.from_public_bytes(public_raw)
        key_id = hashlib.sha256(public_raw).hexdigest()
        checkpoint = _lecture_json(Path(str(path)+'.checkpoint.json'))
        cp = _verifier_signature(checkpoint, key)
        if set(cp) != {'version', 'type', 'journal_id', 'key_id', 'seq', 'dernier_sha256'} \
                or cp['version'] != 1 or cp['type'] != 'checkpoint' or cp['key_id'] != key_id \
                or type(cp['seq']) is not int or cp['seq'] < 0:
            raise AuditInvalide('Contrat du checkpoint invalide')
        _fichier_sur(path)
        seq, prev = 0, ZERO
        ancre_vue = ancre is None
        if ancre is not None:
            if not isinstance(ancre, dict) or ancre.get('journal_id') != cp['journal_id'] \
                    or ancre.get('key_id') != key_id or type(ancre.get('seq')) is not int:
                raise AuditInvalide('Ancre externe incompatible')
            ancre_vue = ancre['seq'] == 0 and ancre.get('dernier_sha256') == ZERO
        with path.open('rb') as file:
            while True:
                line = file.readline(MAX_LINE+1)
                if not line:
                    break
                if len(line) > MAX_LINE or not line.endswith(b'\n'):
                    raise AuditInvalide('Ligne incomplète ou trop grande')
                try:
                    obj = json.loads(line)
                except (ValueError, UnicodeError) as exc:
                    raise AuditInvalide('Ligne JSON illisible') from exc
                payload = _verifier_signature(obj, key)
                if set(payload) != {'version', 'type', 'journal_id', 'key_id', 'seq', 'precedent',
                                    'horodatage_mac_ns', 'evenement'} \
                        or payload['version'] != 1 or payload['type'] != 'evenement' \
                        or payload['journal_id'] != cp['journal_id'] or payload['key_id'] != key_id \
                        or type(payload['seq']) is not int or payload['seq'] != seq+1 \
                        or payload['precedent'] != prev:
                    raise AuditInvalide('Chaîne, séquence ou contrat invalide')
                seq, prev = payload['seq'], obj['sha256']
                if ancre is not None and seq == ancre['seq']:
                    ancre_vue = prev == ancre.get('dernier_sha256')
        if seq != cp['seq'] or prev != cp['dernier_sha256']:
            raise AuditInvalide('Journal et checkpoint divergent : arrêt, troncature ou écriture incomplète')
        if not ancre_vue:
            raise AuditInvalide('Ancre externe absente ou différente : retour arrière possible')
        return {'valide': True, 'algorithme': 'Ed25519', 'seq': seq, 'dernier_sha256': prev,
                'journal_id': cp['journal_id'], 'key_id': key_id,
                'ancre_externe_verifiee': ancre is not None,
                'limite': 'Retour arrière simultané non détectable sans ancre externe indépendante'}
    except AuditInvalide:
        raise
    except (OSError, ValueError, TypeError) as exc:
        raise AuditInvalide('Fichier de preuve ou clé publique indisponible/invalide') from exc


def verifier(path, *, public_key_path=None, ancre=None):
    """Lecture seule, sans clé privée. Lève AuditInvalide si une preuve manque."""
    path = Path(path)
    public_key_path = Path(public_key_path or str(DEFAULT_KEY)+'.pub')
    with _verrou(path):
        return _verifier(path, public_key_path, ancre)


class JournalSigne:
    """Écrire puis fsync, checkpoint atomique, vérification intégrale avant append.

    append ne retourne qu'après les deux écritures. Une interruption entre elles
    est détectée au prochain démarrage et exige une réparation opérateur explicite.
    """
    def __init__(self, path, *, key_path=None):
        self.path = Path(path)
        self.key_path = Path(key_path or DEFAULT_KEY)
        self.public_key_path = Path(str(self.key_path)+'.pub')
        self.checkpoint_path = Path(str(self.path)+'.checkpoint.json')
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with _verrou(self.key_path):
            if not self.key_path.exists():
                # Ne pas recréer silencieusement une identité de signature perdue.
                if self.public_key_path.exists() or self.path.exists() or self.checkpoint_path.exists():
                    raise AuditInvalide('Clé privée manquante ; création de remplacement refusée')
                key = Ed25519PrivateKey.generate()
                private_raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                serialization.NoEncryption())
                _atomique(self.key_path, private_raw)
            _fichier_sur(self.key_path, prive=True)
            self.key = Ed25519PrivateKey.from_private_bytes(self.key_path.read_bytes())
            public_raw = self.key.public_key().public_bytes(serialization.Encoding.Raw,
                                                          serialization.PublicFormat.Raw)
            if self.public_key_path.exists():
                _fichier_sur(self.public_key_path)
                if self.public_key_path.read_bytes() != public_raw:
                    raise AuditInvalide('Clés privée et publique différentes')
            else:
                _atomique(self.public_key_path, public_raw)
        self.key_id = hashlib.sha256(public_raw).hexdigest()
        with _verrou(self.path):
            if not self.path.exists() and not self.checkpoint_path.exists():
                _atomique(self.path, b'')
                self._checkpoint(uuid.uuid4().hex, 0, ZERO)
            _verifier(self.path, self.public_key_path)

    def _checkpoint(self, journal_id, seq, dernier):
        payload = {'version': 1, 'type': 'checkpoint', 'journal_id': journal_id,
                   'key_id': self.key_id, 'seq': seq, 'dernier_sha256': dernier}
        _atomique(self.checkpoint_path, canonique(_signer(payload, self.key))+b'\n')

    def append(self, evenement):
        propre = _nettoyer(evenement)
        if len(canonique(propre)) > 48000:
            raise ValueError('Événement trop volumineux pour le journal signé')
        with _verrou(self.path):
            previous = _verifier(self.path, self.public_key_path)
            payload = {'version': 1, 'type': 'evenement', 'journal_id': previous['journal_id'],
                       'key_id': self.key_id, 'seq': previous['seq']+1,
                       'precedent': previous['dernier_sha256'], 'horodatage_mac_ns': time.time_ns(),
                       'evenement': propre}
            row = _signer(payload, self.key)
            line = canonique(row)+b'\n'
            if len(line) > MAX_LINE:
                raise ValueError('Ligne de preuve trop volumineuse')
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
            with os.fdopen(fd, 'ab') as file:
                file.write(line)
                file.flush()
                os.fsync(file.fileno())
            self._checkpoint(previous['journal_id'], payload['seq'], row['sha256'])
            return {'seq': payload['seq'], 'sha256': row['sha256'], 'key_id': self.key_id,
                    'journal_id': previous['journal_id']}

    def verify(self, *, ancre=None):
        return verifier(self.path, public_key_path=self.public_key_path, ancre=ancre)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Vérifie le journal signé sans afficher son contenu')
    parser.add_argument('journal', type=Path)
    parser.add_argument('--public-key', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(verifier(args.journal, public_key_path=args.public_key), ensure_ascii=False))
    except AuditInvalide as exc:
        print(json.dumps({'valide': False, 'erreur': str(exc)}, ensure_ascii=False))
        raise SystemExit(1)
