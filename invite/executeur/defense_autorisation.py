"""Autorisation courte du contrôleur pour un acte exact, vérifiée côté invité.

Ce reçu n'accorde aucun droit : manifeste, identité et maintenance restent vérifiés
par l'exécuteur. Seules les clés publiques enrôlées par l'administrateur comptent.
"""
from __future__ import annotations

import hashlib
import json
import math
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA = 'sawm-depth-authorization/v1'
PROFILE = 'industriel-prudent-v1'
MAX_VALIDITY_MS = 5000
BOUND_FIELDS = ('decision_id', 'action', 'cible', 'manifest_sha256')
PAYLOAD_FIELDS = frozenset(('schema', *BOUND_FIELDS, 'identity_sha256', 'issued_ms', 'expires_ms'))
HEX32 = re.compile(r'[a-f0-9]{64}')
HEX64 = re.compile(r'[a-f0-9]{128}')
IDENTIFIER = re.compile(r'[A-Za-z0-9._~:+/=-]{1,160}')


def canonical(payload):
    return json.dumps(payload, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


def _clock(value):
    if type(value) is not int or not 0 <= value < 2**63:
        raise ValueError('horodatage_autorisation_invalide')
    return value


def _bound(request):
    if type(request) is not dict:
        raise ValueError('demande_autorisation_invalide')
    decision, action, target, digest = (request.get(k) for k in BOUND_FIELDS)
    if type(decision) is not str or not IDENTIFIER.fullmatch(decision):
        raise ValueError('decision_autorisation_invalide')
    if type(action) is not str or not re.fullmatch(r'[a-z][a-z-]{0,63}', action):
        raise ValueError('action_autorisation_invalide')
    if type(target) is not str or not 1 <= len(target) <= 2048 or any(ord(c) < 32 for c in target):
        raise ValueError('cible_autorisation_invalide')
    if type(digest) is not str or not HEX32.fullmatch(digest):
        raise ValueError('empreinte_autorisation_invalide')
    return dict(zip(BOUND_FIELDS, (decision, action, target, digest)))


def identity_digest(request):
    """Lie même l'absence d'identité ; sérialisation JSON stricte de 4 KiB au plus."""
    value = request.get('expected_identity')
    visited = 0

    def json_safe(item, depth=0):
        nonlocal visited
        visited += 1
        if depth > 16 or visited > 256:
            raise ValueError('identite_autorisation_trop_complexe')
        kind = type(item)
        if item is None or kind is bool:
            return
        if kind is str and len(item) <= 4096:
            return
        if kind is int and -(2**63) <= item < 2**63:
            return
        if kind is float and math.isfinite(item):
            return
        if kind is list and len(item) <= 128:
            for child in item:
                json_safe(child, depth+1)
            return
        if kind is dict and len(item) <= 128 and all(type(key) is str and len(key) <= 4096 for key in item):
            for child in item.values():
                json_safe(child, depth+1)
            return
        raise ValueError('identite_autorisation_non_json')

    json_safe(value)
    raw = canonical(value)
    if len(raw) > 4096:
        raise ValueError('identite_autorisation_trop_longue')
    return hashlib.sha256(raw).hexdigest()


def _keys(manifest):
    if type(manifest) is not dict:
        raise ValueError('manifeste_autorisation_invalide')
    profile = manifest.get('defense_profondeur')
    if type(profile) is not dict or set(profile) not in (
            {'profil', 'controles_bloquants'}, {'profil', 'controles_bloquants', 'cles_controleur'}) \
            or profile.get('profil') != PROFILE:
        raise ValueError('profil_defense_profondeur_invalide')
    required = profile.get('controles_bloquants')
    if type(required) is not list or len(required) > 64 \
            or any(type(item) is not str or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', item) for item in required) \
            or len(set(required)) != len(required):
        raise ValueError('controles_defense_profondeur_invalides')
    values = profile.get('cles_controleur')
    if type(values) is not list or not 1 <= len(values) <= 16 \
            or any(type(value) is not str or not HEX32.fullmatch(value) for value in values) \
            or len(set(values)) != len(values):
        raise ValueError('cles_controleur_absentes_ou_invalides')
    return {hashlib.sha256(bytes.fromhex(value)).hexdigest(): bytes.fromhex(value) for value in values}


def sign_authorization(private_key, request, now_ms):
    """Signer après validation locale ; ne lit ni clé sur disque ni environnement."""
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError('cle_privee_controleur_invalide')
    issued = _clock(now_ms)
    expires = _clock(issued + MAX_VALIDITY_MS)
    payload = {'schema': SCHEMA, **_bound(request), 'identity_sha256': identity_digest(request),
               'issued_ms': issued, 'expires_ms': expires}
    public = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {'payload': payload, 'key_id': hashlib.sha256(public).hexdigest(),
            'signature': private_key.sign(canonical(payload)).hex()}


def verify_authorization(envelope, request, manifest, now_ms):
    """Refuser par défaut, sans confiance dans un booléen ou une clé de la requête."""
    now = _clock(now_ms)
    keys = _keys(manifest)
    expected = _bound(request)
    if manifest.get('_sha256') != expected['manifest_sha256']:
        raise ValueError('manifeste_autorisation_non_courant')
    if type(envelope) is not dict or set(envelope) != {'payload', 'key_id', 'signature'}:
        raise ValueError('enveloppe_autorisation_invalide')
    payload, key_id, signature = (envelope[k] for k in ('payload', 'key_id', 'signature'))
    if type(payload) is not dict or set(payload) != PAYLOAD_FIELDS or payload.get('schema') != SCHEMA:
        raise ValueError('contrat_autorisation_invalide')
    if _bound(payload) != expected:
        raise ValueError('autorisation_non_liee_a_la_demande')
    if type(payload['identity_sha256']) is not str or not HEX32.fullmatch(payload['identity_sha256']) \
            or payload['identity_sha256'] != identity_digest(request):
        raise ValueError('autorisation_non_liee_a_identite')
    issued, expires = _clock(payload['issued_ms']), _clock(payload['expires_ms'])
    if not 0 < expires-issued <= MAX_VALIDITY_MS or not issued <= now < expires:
        raise ValueError('autorisation_future_expiree_ou_duree_invalide')
    if type(key_id) is not str or not HEX32.fullmatch(key_id) or key_id not in keys:
        raise ValueError('cle_controleur_non_enrolee')
    if type(signature) is not str or not HEX64.fullmatch(signature):
        raise ValueError('signature_autorisation_invalide')
    try:
        Ed25519PublicKey.from_public_bytes(keys[key_id]).verify(bytes.fromhex(signature), canonical(payload))
    except (InvalidSignature, ValueError):
        raise ValueError('signature_autorisation_invalide') from None
    return True
