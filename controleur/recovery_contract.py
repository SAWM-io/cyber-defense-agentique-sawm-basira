"""Contrat de reconstruction vérifié par le contrôleur, hors de l'invité.

Les identités, empreintes et preuves doivent venir de mesures du contrôleur.
``origin`` est un contrat d'appel de cet orchestrateur de confiance : une chaîne
fournie par l'invité ne constitue jamais une preuve indépendante. Ce module ne
lit pas de clé, n'exécute pas de commande et n'accorde aucun pouvoir à l'invité.
La signature protège une référence de laboratoire, pas une attestation firmware
ni une démonstration universelle que l'image de référence est saine.
"""
from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import PurePosixPath
import re
from uuid import UUID

from .audit_signe import (
    canonique, Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature, serialization,
)

MAX_MANIFEST_BYTES = 4096
STATES = ('proof', 'isolated', 'recovery_verified', 'rebuilt', 'verified', 'released')
DOMAIN = b'sawm/recovery-manifest/v1\0'
_HEX = re.compile(r'[0-9a-f]{64}\Z')
_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')


class RecoveryContractError(ValueError):
    """Contrat invalide : la reconstruction ou la libération doit s'arrêter."""


def _digest(value):
    if type(value) is not str or not _HEX.fullmatch(value):
        raise RecoveryContractError('Empreinte SHA-256 invalide')


def _identity(run_id, vm_id, target):
    if type(run_id) is not str or not _ID.fullmatch(run_id):
        raise RecoveryContractError('run_id invalide')
    try:
        if type(vm_id) is not str or str(UUID(vm_id)) != vm_id:
            raise ValueError('UUID non canonique')
    except (ValueError, AttributeError) as exc:
        raise RecoveryContractError('Identité VM UUID invalide') from exc
    if type(target) is not str or not 2 <= len(target) <= 1024 \
            or any(ord(c) < 32 or ord(c) == 127 for c in target) \
            or not target.startswith('/') or target.startswith('//') \
            or PurePosixPath(target).as_posix() != target \
            or '..' in PurePosixPath(target).parts:
        raise RecoveryContractError('Cible absolue canonique requise')
    try:
        if len(target.encode('utf-8')) > 1024:
            raise ValueError('Chemin trop grand')
    except (UnicodeError, ValueError) as exc:
        raise RecoveryContractError('Cible UTF-8 trop grande ou invalide') from exc


@dataclass(frozen=True)
class RecoveryBinding:
    run_id: str
    vm_id: str
    target: str
    clean_image_sha256: str
    institutional_key_fingerprint: str

    def __post_init__(self):
        _identity(self.run_id, self.vm_id, self.target)
        _digest(self.clean_image_sha256)
        _digest(self.institutional_key_fingerprint)


@dataclass(frozen=True)
class ControllerEvidence:
    stage: str
    run_id: str
    vm_id: str
    target: str
    sha256: str
    origin: str
    passed: bool

    def __post_init__(self):
        _identity(self.run_id, self.vm_id, self.target)
        _digest(self.sha256)
        if type(self.stage) is not str or self.stage not in STATES \
                or self.origin != 'host-controller' or self.passed is not True:
            raise RecoveryContractError('Preuve positive du contrôleur hôte requise')


def key_fingerprint(public_key):
    if not isinstance(public_key, Ed25519PublicKey):
        raise RecoveryContractError('Clé publique Ed25519 requise')
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def _evidence(binding, evidence, stage):
    if type(binding) is not RecoveryBinding or type(evidence) is not ControllerEvidence:
        raise RecoveryContractError('Liaison et preuve du contrôleur requises')
    binding.__post_init__()
    evidence.__post_init__()
    if evidence.stage != stage or any(getattr(binding, field) != getattr(evidence, field)
                                      for field in ('run_id', 'vm_id', 'target')):
        raise RecoveryContractError('Preuve hors étape, exécution ou cible')


def sign_manifest(binding, *, private_key, proof):
    """Signer uniquement une référence approuvée et une preuve mesurée sur l'hôte.

    L'appelant doit garder la clé privée et la référence d'image hors invité.
    L'empreinte institutionnelle est celle de cette clé Ed25519 préalablement
    approuvée, jamais une empreinte extraite du manifeste à vérifier.
    """
    _evidence(binding, proof, 'proof')
    if not isinstance(private_key, Ed25519PrivateKey) \
            or key_fingerprint(private_key.public_key()) != binding.institutional_key_fingerprint:
        raise RecoveryContractError('Clé de signature différente de la référence institutionnelle')
    payload = dict(version=1, purpose='lab-vm-recovery', lab_only=True,
                   **asdict(binding), proof_sha256=proof.sha256, proof_origin='host-controller')
    raw = canonique(payload)
    return {'payload': payload, 'sha256': hashlib.sha256(raw).hexdigest(),
            'signature': base64.b64encode(private_key.sign(DOMAIN + raw)).decode('ascii')}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RecoveryContractError('Champ JSON dupliqué')
        result[key] = value
    return result


def _decode(envelope):
    if type(envelope) in (bytes, str):
        if len(envelope) > MAX_MANIFEST_BYTES:
            raise RecoveryContractError('Manifeste trop grand')
        try:
            envelope = json.loads(envelope, object_pairs_hook=_unique_object)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise RecoveryContractError('Manifeste JSON invalide') from exc
    if type(envelope) is not dict or set(envelope) != {'payload', 'sha256', 'signature'}:
        raise RecoveryContractError('Champs du manifeste invalides')
    return envelope


def verify_manifest(envelope, *, public_key, expected, proof_sha256):
    """Vérifier contre des références externes de confiance, sans clé privée.

    Passer les octets du fichier pour refuser également les champs JSON dupliqués.
    L'appelant vérifie le fichier image réel et la cible avant toute mutation.
    """
    if type(expected) is not RecoveryBinding:
        raise RecoveryContractError('Référence externe de confiance requise')
    expected.__post_init__()
    _digest(proof_sha256)
    if key_fingerprint(public_key) != expected.institutional_key_fingerprint:
        raise RecoveryContractError('Clé publique non approuvée')
    envelope = _decode(envelope)
    payload = envelope['payload']
    required = set(asdict(expected)) | {'version', 'purpose', 'lab_only', 'proof_sha256', 'proof_origin'}
    if type(payload) is not dict or set(payload) != required \
            or type(payload['version']) is not int or payload['version'] != 1 \
            or payload['purpose'] != 'lab-vm-recovery' or payload['lab_only'] is not True \
            or payload['proof_origin'] != 'host-controller' or payload['proof_sha256'] != proof_sha256 \
            or any(payload[field] != value for field, value in asdict(expected).items()):
        raise RecoveryContractError('Manifeste incompatible avec la preuve, la VM ou la référence')
    _digest(envelope['sha256'])
    signature = envelope['signature']
    if type(signature) is not str or len(signature) != 88:
        raise RecoveryContractError('Signature Ed25519 invalide')
    raw = canonique(payload)
    if len(raw) + len(signature) > MAX_MANIFEST_BYTES \
            or hashlib.sha256(raw).hexdigest() != envelope['sha256']:
        raise RecoveryContractError('Empreinte du manifeste invalide')
    try:
        decoded = base64.b64decode(signature, validate=True)
        if len(decoded) != 64 or base64.b64encode(decoded).decode('ascii') != signature:
            raise ValueError('Signature non canonique')
        public_key.verify(decoded, DOMAIN + raw)
    except (InvalidSignature, ValueError) as exc:
        raise RecoveryContractError('Signature Ed25519 invalide') from exc
    return dict(payload)


class RecoveryState:
    """Barrière séquentielle du contrôleur ; ne prétend pas observer la VM.

    ``require_state('recovery_verified')`` doit précéder la reconstruction réelle.
    Chaque transition ensuite exige une mesure positive faite hors de l'invité.
    Les transitions ne remplacent ni l'observation indépendante ni son journal.
    """
    def __init__(self, binding, proof):
        _evidence(binding, proof, 'proof')
        self._binding = binding
        self._proof_sha256 = proof.sha256
        self._history = [('proof', proof.sha256)]

    @property
    def state(self):
        return self._history[-1][0]

    @property
    def history(self):
        return tuple(self._history)

    def require_state(self, state):
        if self.state != state:
            raise RecoveryContractError('Étape de reprise requise : ' + str(state))

    def advance(self, state, *, evidence=None, manifest=None, public_key=None):
        index = STATES.index(self.state)
        if index + 1 >= len(STATES) or state != STATES[index + 1]:
            raise RecoveryContractError('Saut, répétition ou retour arrière de reprise interdit')
        if state == 'recovery_verified':
            if evidence is not None:
                raise RecoveryContractError('La vérification exige le manifeste signé')
            payload = verify_manifest(manifest, public_key=public_key, expected=self._binding,
                                      proof_sha256=self._proof_sha256)
            digest = hashlib.sha256(canonique(payload)).hexdigest()
        else:
            if manifest is not None or public_key is not None:
                raise RecoveryContractError('Manifeste hors étape de vérification')
            _evidence(self._binding, evidence, state)
            digest = evidence.sha256
        self._history.append((state, digest))
        return self.state
