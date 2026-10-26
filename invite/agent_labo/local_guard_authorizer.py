"""Autorité locale bornée, indépendante du Cloud, jamais du manifeste root.

Aucune clé n'est créée ou enrôlée ici. Une preuve fraîche est reconstruite depuis
l'OS, la maintenance est revérifiée et le même veto de posture que Veille est
appliqué. Le journal est signé avant de délivrer le reçu court à l'exécuteur.
"""
from __future__ import annotations

import http.client
from pathlib import Path
import stat
import time

from cryptography.hazmat.primitives import serialization
from controleur.audit_signe import JournalSigne
from controleur.defense_profondeur import evaluate as posture, refuse
from controleur.diagnostic_defense import diagnostiquer
from controleur.maintenance import evaluate as maintenance, observer_os
from invite.agent_labo import defense_runtime as runtime, posture_securite
from invite.executeur.defense_autorisation import local_guard_keys, sign_authorization, verify_authorization

KEY = Path('/etc/sawm-labo/garde-locale-ed25519.key')
AUDIT = Path('/var/lib/sawm-labo/garde-locale/audit.jsonl')
MANIFEST = Path('/opt/sawm-labo/manifeste.json')


def trusted_path(path, *, private=False, directory=False, owner=0, root=Path('/')):
    """Vérifier également les parents ; jamais de lien, clé recréée ou chemin LLM."""
    path, root = Path(path), Path(root)
    if not path.is_absolute() or '..' in path.parts or not path.is_relative_to(root):
        raise ValueError('garde_locale_chemin_invalide')
    current = path
    while True:
        st = current.lstat()
        is_directory = directory if current == path else True
        if st.st_uid != owner or st.st_mode & 0o022 or \
                not (stat.S_ISDIR(st.st_mode) if is_directory else stat.S_ISREG(st.st_mode)):
            raise ValueError('garde_locale_chemin_non_fiable')
        if current == path and not directory and st.st_nlink != 1:
            raise ValueError('garde_locale_lien_materiel')
        if current == path and private and stat.S_IMODE(st.st_mode) != 0o600:
            raise ValueError('garde_locale_cle_non_privee')
        if current == root:
            break
        current = current.parent


def witness():
    """Sonde fixe locale, aucun proxy ni redirection vers une destination tierce."""
    connection = http.client.HTTPConnection('127.0.0.1', 8080, timeout=0.3)
    try:
        connection.request('GET', '/sante')
        response = connection.getresponse()
        response.read(512)
        return {'disponible': response.status == 200}
    except (OSError, http.client.HTTPException):
        return {'disponible': False}
    finally:
        connection.close()


class LocalGuardAuthorizer:
    def __init__(self, *, key_path=KEY, audit_path=AUDIT, manifest_path=MANIFEST):
        self.key_path, self.audit_path, self.manifest_path = map(Path, (key_path, audit_path, manifest_path))
        self._paths()
        # JournalSigne ne voit jamais une clé absente : aucune génération automatique.
        self.journal = JournalSigne(self.audit_path, key_path=self.key_path)
        posture_securite.snapshot()  # amorçage asynchrone, sans attendre l'analyse Cloud

    def _paths(self):
        trusted_path(self.key_path, private=True)
        trusted_path(Path(str(self.key_path)+'.pub'))
        trusted_path(self.audit_path.parent, directory=True)
        trusted_path(self.manifest_path)

    def authorize(self, request, initial_item, sensor):
        self._paths()
        m = runtime.trusted_manifest(self.manifest_path)
        if m['_sha256'] != request.get('manifest_sha256') or m['generation'] != request.get('generation'):
            raise ValueError('garde_locale_manifeste_change')
        keys = local_guard_keys(m.get('defense_profondeur') or {})
        record = keys.get(self.journal.key_id)
        if record is None or request.get('cible') not in record['unites']:
            raise ValueError('garde_locale_non_enrolee')
        public = self.journal.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if Path(str(self.key_path)+'.pub').read_bytes() != public:
            raise ValueError('garde_locale_cle_changee')
        # Refuser également la rotation de la clé privée sans redémarrage explicite.
        private = self.journal.key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                serialization.NoEncryption())
        if self.key_path.read_bytes() != private:
            raise ValueError('garde_locale_cle_changee')
        matches = [t for t in runtime.targets(m) if t['unit'] == request.get('cible')
                   and t['path'] == initial_item.get('path') and t.get('automatic_containment') is True]
        if len(matches) != 1:
            raise ValueError('garde_locale_cible_non_autorisee')
        # Ni les champs diagnostiques du premier relevé ni ceux d'un appelant ne font autorité.
        item = runtime.inspect_target(m, matches[0], sensor, observer_os, maintenance, diagnostiquer)
        obs = item['identity']
        expected = {'cible':item['unit'], 'boot_id':obs.get('boot_id'), 'MainPID':str(obs.get('pid')),
                    'InvocationID':obs.get('invocation_id'), 'ControlGroup':obs.get('cgroup')}
        now = int(time.time()*1000)
        if item['diagnostic'].get('recommandation') != 'contenir_sous_mandat' \
                or expected != request.get('expected_identity') or obs.get('identity_stable') is not True \
                or any(type(x) is not int or not 0 <= now-x <= runtime.MAX_PROOF_AGE_MS
                       for x in (item.get('observed_ms'), obs.get('observed_at_ms'))):
            raise ValueError('garde_locale_preuve_ou_identite_non_etablie')
        verified = self.journal.verify()
        audit = {**verified, 'verifie_a_ms': int(time.time()*1000)}
        sample = {'mur_epoch_ms':item['observed_ms'], 'posture_securite':posture_securite.snapshot()}
        if 'service_temoin' in m['defense_profondeur'].get('controles_bloquants', []):
            sample['service_temoin'] = witness()
        # Cette collecte vient des sondes OS ci-dessus, pas d'un booléen du modèle.
        now = int(time.time()*1000)
        state = {'mode':'DIRECT', 'telemetrie_invite':{'connectee':True, 'age_ms':now-item['observed_ms']},
                 'invite':[sample]}
        veto = refuse(m, state, audit=audit, now_ms=now, authority_role='garde_locale')
        if veto:
            raise ValueError(veto)
        report = posture(m, state, audit=audit, now_ms=now, authority_role='garde_locale')
        self.journal.append({'type':'decision_garde_locale', 'origine':'garde_locale',
            'decision_id':request['decision_id'], 'action':request['action'], 'cible':request['cible'],
            'manifest_sha256':m['_sha256'], 'identite':expected,
            'preuves':item['diagnostic']['preuves'], 'raison':item['diagnostic']['raison'],
            'posture':[{k:c[k] for k in ('id','status','observed_ms')} for c in report['checks']]})
        # Le journal peut prendre du temps : aucune preuve ancienne n'est rajeunie.
        now = int(time.time()*1000)
        if any(not 0 <= now-x <= runtime.MAX_PROOF_AGE_MS
               for x in (item['observed_ms'], obs['observed_at_ms'])) \
                or runtime.trusted_manifest(self.manifest_path)['_sha256'] != m['_sha256']:
            raise ValueError('garde_locale_preuve_expiree_avant_signature')
        envelope = sign_authorization(self.journal.key, request, now)
        verify_authorization(envelope, request, m, now)  # même portée que l'exécuteur
        return envelope

    def record_result(self, request, receipt):
        self.journal.append({'type':'resultat_garde_locale', 'decision_id':request['decision_id'],
                             'cible':request['cible'], 'recu':receipt})
