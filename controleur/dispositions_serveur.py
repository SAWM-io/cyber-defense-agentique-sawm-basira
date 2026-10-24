"""Dispositions fonctionnelles, traçables et révisables; aucune émotion vécue.

Les seuls signaux sont typés par l'appelant depuis des preuves. Aucun texte de
modèle, récit, nom de compte ou contenu métier ne détermine une disposition.
Ce module ne délivre aucune autorisation et n'exécute aucune action serveur.
"""
from __future__ import annotations

import contextlib
import copy
import fcntl
import hashlib
import json
import os
import pathlib
import re
import stat
import uuid

MAX_EVENTS = 128
MAX_MOTIFS = 12
MAX_TARGETS = 32
MAX_STATE_BYTES = 131072
SCHEMA = 'sawm-server-dispositions/v1'
_STATE_SCHEMA = 'sawm-server-dispositions-state/v1'
_ENTITY = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}')
_REFERENCE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:/@-]{0,159}')
_UNIT = re.compile(r'labo-[a-z0-9][a-z0-9_.-]{0,55}\.service')
_LABELS = {
    'observation_insuffisante': 'Preuves insuffisantes : poursuivre la vérification.',
    'anomalie_verifiee': 'Écart technique vérifié, sans qualification de malveillance.',
    'violation_confirmee': 'Violation explicitement confirmée par une preuve référencée.',
    'verification_reussie': 'Contrôle réussi ; il ne prouve pas une violation ni une innocence.',
    'fausse_alerte': 'Révision explicite : contribution de l’alerte référencée annulée.',
}
# Vigilance, confiance dans les preuves, méfiance pour la seule cible identifiée.
# Une vérification d'effet ne restaure pas artificiellement la confiance cible.
_DELTAS = {'observation_insuffisante': (5, -5, 0), 'anomalie_verifiee': (12, 4, 10),
           'violation_confirmee': (25, 8, 25), 'verification_reussie': (-4, 6, 0),
           'fausse_alerte': (0, 0, 0)}
_TRAITS = {
    'prudence': {'intensite': 80, 'objectif': 'Demander des preuves avant une conclusion risquée.'},
    'curiosite': {'intensite': 70, 'objectif': 'Réduire les inconnues par des observations autorisées.'},
    'preservation_service': {'intensite': 90, 'objectif': 'Préserver la continuité du service légitime.'},
}
_LIMITS = [
    'Dispositions fonctionnelles, sans prétention à des sentiments vécus.',
    'Scores heuristiques non calibrés et non probabilistes ; confiance dans les preuves.',
    'Méfiance contextualisée à une unité identifiée, jamais culpabilité générale ou humaine.',
    'Aucun changement de permissions, aucune autorisation ni action déduite de ces scores.',
    'Déduplication et révision limitées aux 128 événements conservés ; 12 motifs affichés.',
]


def _identifier(value, pattern=_REFERENCE):
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise ValueError('identifiant_disposition_invalide')
    return value


def _source(value):
    if type(value) is str:
        value = {'id': value}
    if type(value) is not dict or not {'id'} <= set(value) <= {'id', 'unit', 'revision_de'}:
        raise ValueError('reference_disposition_invalide')
    result = {'id': _identifier(value['id'])}
    if 'unit' in value:
        result['unit'] = _identifier(value['unit'], _UNIT)
    if 'revision_de' in value:
        result['revision_de'] = _identifier(value['revision_de'])
    return result


def _integer(value, minimum=0, maximum=2**63 - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('nombre_disposition_invalide')
    return value


def valider_snapshot(value):
    """Copie JSON stricte pour le prompt : libellés fixes, aucun texte libre."""
    required = {'schema', 'entity_id', 'revision', 'traits', 'etat', 'motifs', 'limites'}
    if type(value) is not dict or set(value) != required or value['schema'] != SCHEMA:
        raise ValueError('snapshot_dispositions_invalide')
    _identifier(value['entity_id'], _ENTITY)
    revision = _integer(value['revision'])
    if value['traits'] != _TRAITS or value['limites'] != _LIMITS:
        raise ValueError('snapshot_dispositions_texte_non_autorise')
    state = value['etat']
    if type(state) is not dict or set(state) != {'vigilance', 'confiance', 'mefiance_par_cible'}:
        raise ValueError('snapshot_dispositions_invalide')
    _integer(state['vigilance'], 0, 100); _integer(state['confiance'], 0, 100)
    targets = state['mefiance_par_cible']
    if type(targets) is not dict or len(targets) > MAX_TARGETS:
        raise ValueError('snapshot_dispositions_invalide')
    for unit, score in targets.items():
        _identifier(unit, _UNIT); _integer(score, 0, 100)
    motifs = value['motifs']
    if type(motifs) is not list or len(motifs) > min(revision, MAX_MOTIFS):
        raise ValueError('snapshot_dispositions_invalide')
    seen = set()
    for motif in motifs:
        if type(motif) is not dict or set(motif) != {
            'event_id', 'signal', 'libelle', 'source_ref', 'observed_ms', 'actif'}:
            raise ValueError('snapshot_dispositions_invalide')
        event_id = _identifier(motif['event_id'])
        signal = motif['signal']
        if type(signal) is not str or signal not in _LABELS or motif['libelle'] != _LABELS[signal]:
            raise ValueError('snapshot_dispositions_texte_non_autorise')
        if event_id in seen or type(motif['actif']) is not bool:
            raise ValueError('snapshot_dispositions_invalide')
        seen.add(event_id)
        source = _source(motif['source_ref'])
        if source != motif['source_ref'] or ('revision_de' in source) != (signal == 'fausse_alerte'):
            raise ValueError('snapshot_dispositions_revision_invalide')
        _integer(motif['observed_ms'], 1)
    encoded = json.dumps(value, ensure_ascii=False, separators=(',', ':'))
    if len(encoded.encode()) > 16384:
        raise ValueError('snapshot_dispositions_trop_grand')
    return json.loads(encoded)


class DispositionsServeur:
    def __init__(self, state_dir, entity_id):
        self.entity_id = _identifier(entity_id, _ENTITY)
        self.state_dir = pathlib.Path(state_dir).absolute()
        if '..' in self.state_dir.parts:
            raise ValueError('repertoire_dispositions_invalide')
        token = hashlib.sha256(self.entity_id.encode()).hexdigest()
        self._name = 'dispositions-' + token + '.json'
        self._lock_name = 'dispositions-' + token + '.lock'
        with self._transaction(create=True) as directory:
            try:
                self._load(directory)
            except FileNotFoundError:
                self._save(directory, self._initial())

    def _initial(self):
        return {'schema': _STATE_SCHEMA, 'entity_id': self.entity_id, 'revision': 0,
                'base': {'vigilance': 35, 'confiance': 50, 'mefiance_par_cible': {}}, 'events': []}

    @contextlib.contextmanager
    def _transaction(self, create=False):
        directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        lock = None
        try:
            for part in self.state_dir.parts[1:]:
                if create:
                    try: os.mkdir(part, 0o700, dir_fd=directory)
                    except FileExistsError: pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                os.close(directory); directory = child
            st = os.fstat(directory)
            if st.st_uid != os.geteuid() or st.st_mode & 0o022:
                raise ValueError('repertoire_dispositions_non_prive')
            lock = os.open(self._lock_name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                           0o600, dir_fd=directory)
            self._check_file(lock)
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield directory
        finally:
            if lock is not None: os.close(lock)
            os.close(directory)

    @staticmethod
    def _check_file(fd):
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.geteuid()
                or st.st_mode & 0o077 or st.st_size > MAX_STATE_BYTES):
            raise ValueError('fichier_dispositions_non_prive')

    def _load(self, directory):
        fd = os.open(self._name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            self._check_file(fd)
            with os.fdopen(fd, 'r') as stream:
                fd = None
                raw = stream.read(MAX_STATE_BYTES + 1)
            if len(raw.encode()) > MAX_STATE_BYTES:
                raise ValueError('etat_dispositions_trop_grand')
            data = json.loads(raw)
        finally:
            if fd is not None: os.close(fd)
        if (type(data) is not dict or set(data) != {'schema', 'entity_id', 'revision', 'base', 'events'}
                or data['schema'] != _STATE_SCHEMA or data['entity_id'] != self.entity_id):
            raise ValueError('etat_dispositions_invalide')
        _integer(data['revision'])
        base = data['base']
        if type(base) is not dict or set(base) != {'vigilance', 'confiance', 'mefiance_par_cible'}:
            raise ValueError('etat_dispositions_invalide')
        _integer(base['vigilance'], -1000, 1000); _integer(base['confiance'], -1000, 1000)
        if type(base['mefiance_par_cible']) is not dict or len(base['mefiance_par_cible']) > MAX_TARGETS:
            raise ValueError('etat_dispositions_invalide')
        for unit, score in base['mefiance_par_cible'].items():
            _identifier(unit, _UNIT); _integer(score, -1000, 1000)
        if type(data['events']) is not list or len(data['events']) > MAX_EVENTS:
            raise ValueError('etat_dispositions_invalide')
        ids = set()
        for event in data['events']:
            if type(event) is not dict or set(event) != {'event_id', 'signal', 'source_ref', 'observed_ms', 'revised_by'}:
                raise ValueError('etat_dispositions_invalide')
            _identifier(event['event_id']); _integer(event['observed_ms'], 1)
            if event['event_id'] in ids or type(event['signal']) is not str or event['signal'] not in _LABELS:
                raise ValueError('etat_dispositions_invalide')
            ids.add(event['event_id'])
            source = _source(event['source_ref'])
            if source != event['source_ref'] or ('revision_de' in source) != (event['signal'] == 'fausse_alerte'):
                raise ValueError('etat_dispositions_invalide')
            if event['revised_by'] is not None: _identifier(event['revised_by'])
        self._snapshot(data)
        return data

    def _save(self, directory, data):
        raw = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
        if len(raw) > MAX_STATE_BYTES:
            raise ValueError('etat_dispositions_trop_grand')
        temporary = '.' + self._name + '.' + uuid.uuid4().hex + '.tmp'
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, self._name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try: os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError: pass

    @staticmethod
    def _apply(state, event, *, fold=False):
        if event['revised_by'] is not None:
            return
        vigilance, confidence, distrust = _DELTAS[event['signal']]
        state['vigilance'] += vigilance; state['confiance'] += confidence
        unit = event['source_ref'].get('unit')
        if unit and distrust:
            state['mefiance_par_cible'][unit] = state['mefiance_par_cible'].get(unit, 0) + distrust
        if fold:
            state['vigilance'] = max(-1000, min(1000, state['vigilance']))
            state['confiance'] = max(-1000, min(1000, state['confiance']))
            state['mefiance_par_cible'] = {k: max(-1000, min(1000, v))
                                         for k, v in state['mefiance_par_cible'].items()}

    def _snapshot(self, data):
        state = copy.deepcopy(data['base'])
        for event in data['events']:
            self._apply(state, event)
        state['vigilance'] = max(0, min(100, state['vigilance']))
        state['confiance'] = max(0, min(100, state['confiance']))
        state['mefiance_par_cible'] = {k: max(0, min(100, v)) for k, v in
                                      sorted(state['mefiance_par_cible'].items()) if v > 0}
        motifs = [{'event_id': event['event_id'], 'signal': event['signal'],
                   'libelle': _LABELS[event['signal']], 'source_ref': event['source_ref'],
                   'observed_ms': event['observed_ms'], 'actif': event['revised_by'] is None}
                  for event in data['events'][-MAX_MOTIFS:]]
        return valider_snapshot({'schema': SCHEMA, 'entity_id': self.entity_id,
            'revision': data['revision'], 'traits': _TRAITS, 'etat': state,
            'motifs': motifs, 'limites': _LIMITS})

    def snapshot(self):
        with self._transaction() as directory:
            return self._snapshot(self._load(directory))

    def observer(self, event_id, signal, source_ref, observed_ms):
        _identifier(event_id); _integer(observed_ms, 1)
        if type(signal) is not str or signal not in _LABELS:
            raise ValueError('signal_disposition_non_autorise')
        source = _source(source_ref)
        if ('revision_de' in source) != (signal == 'fausse_alerte'):
            raise ValueError('revision_disposition_invalide')
        event = {'event_id': event_id, 'signal': signal, 'source_ref': source,
                 'observed_ms': observed_ms, 'revised_by': None}
        with self._transaction() as directory:
            data = self._load(directory)
            for previous in data['events']:
                if previous['event_id'] == event_id:
                    if any(previous[key] != event[key] for key in ('signal', 'source_ref', 'observed_ms')):
                        raise ValueError('identifiant_evenement_deja_utilise')
                    return self._snapshot(data)
            if signal == 'fausse_alerte':
                original = next((e for e in data['events'] if e['event_id'] == source['revision_de']), None)
                if (original is None or original['signal'] not in ('anomalie_verifiee', 'violation_confirmee')
                        or original['revised_by'] is not None
                        or original['source_ref'].get('unit') != source.get('unit')):
                    raise ValueError('revision_absente_expiree_ou_mauvaise_cible')
                original['revised_by'] = event_id
            if len(data['events']) == MAX_EVENTS:
                self._apply(data['base'], data['events'].pop(0), fold=True)
            data['events'].append(event)
            data['revision'] = _integer(data['revision'] + 1)
            result = self._snapshot(data)
            self._save(directory, data)
            return result
