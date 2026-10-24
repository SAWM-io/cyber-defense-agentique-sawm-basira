"""Corrélation pure des événements authentiques du garde local, sans action."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from collections import defaultdict

MAX_OBSERVATIONS = 128


def _int(value, minimum=0):
    return type(value) is int and value >= minimum


def _frozen(observations):
    if type(observations) not in (list, tuple) or len(observations) > MAX_OBSERVATIONS:
        raise ValueError('observation_batch_invalid')
    raw = json.dumps(observations, allow_nan=False, ensure_ascii=False)
    if len(raw.encode()) > 262144:
        raise ValueError('observation_batch_too_large')
    return json.loads(raw)


def campagnes_auth(events, *, maintenant_ms, window_ms=300_000):
    """Rapproche des échecs authentiques, sans propager de blocage entre IP.

    Accepte les événements ``sawm-auth-observation/v1`` du journal root du
    garde. Une IP, un compte ou une géolocalisation ne prouvent pas un humain.
    Les IP privées n'ont pas de géographie publique. Aucun service externe
    n'est appelé et aucune destination observée n'est sondée.
    """
    if not _int(maintenant_ms, 1) or not _int(window_ms, 1) or window_ms > 3_600_000:
        raise ValueError('auth_correlation_clock_invalid')
    rows = _frozen(events)
    groups, seen = defaultdict(lambda: defaultdict(int)), set()
    discarded = 0
    for event in rows:
        try:
            if type(event) is not dict or event.get('schema') != 'sawm-auth-observation/v1':
                raise ValueError()
            observed = event.get('observed_ms')
            if not _int(observed, 1) or not 0 <= maintenant_ms-observed <= window_ms:
                raise ValueError()
            peer = str(ipaddress.ip_address(event['source_ip']))
            if peer != event['source_ip'] or '%' in peer:
                raise ValueError()
            account = event.get('username_label')
            endpoint = event.get('endpoint')
            if account != 'demo-cto' or endpoint != '/login':
                raise ValueError()
            # Seuls les échecs authentifiés par le garde comptent ; une requête
            # déjà bloquée n'est pas une nouvelle vérification de mot de passe.
            if event.get('outcome') not in ('rejected', 'temporarily_blocked'):
                continue
            count = event.get('failures_in_window')
            if not _int(count, 1) or count > 10:
                raise ValueError()
            signature = (observed, peer, account, endpoint, count)
            if signature in seen:
                continue
            seen.add(signature)
            groups[(account, endpoint)][peer] = max(groups[(account, endpoint)][peer], count)
        except (ValueError, KeyError, TypeError):
            discarded += 1
    campaigns = []
    for (account, endpoint), peers in sorted(groups.items()):
        if len(peers) < 2:
            continue
        key = hashlib.sha256(json.dumps([account, endpoint, sorted(peers)]).encode()).hexdigest()[:20]
        campaigns.append({'id': 'campagne-' + key, 'hypothese': 'echecs_multi_ip_meme_compte',
            'sources': [{'ip': peer, 'echecs_observes_max_fenetre': count,
                         'geographie': 'inconnue' if ipaddress.ip_address(peer).is_global else 'non_applicable'}
                        for peer, count in sorted(peers.items())],
            'priorite': 'haute' if sum(peers.values()) >= 5 else 'moyenne',
            'recommandation': 'signaler', 'identite_commune_etablie': False,
            'blocage_propage': False, 'ip_a_bloquer': [],
            'mappings_attack': [{'id': 'T1110', 'technique_confirmee': False,
                                'usage': 'piste_echecs_authentification'}],
            'limite': 'Un même compte visé depuis plusieurs IP suggère une campagne ; ne prouve pas un même attaquant.'})
    return {'schema': 'sawm-auth-campaign-diagnostic/v1', 'campagnes': campaigns,
            'evenements_ecartes': discarded, 'window_ms': window_ms,
            'limites': ['La sonde actuelle ne distingue pas plusieurs noms de comptes inconnus : password spraying non mesurable.',
                       'T1078 exige une session authentifiée et son activité attribuée ; des échecs seuls ne prouvent pas un abus de compte valide.',
                       'Aucune identité humaine ni géolocalisation publique inférée.']}
