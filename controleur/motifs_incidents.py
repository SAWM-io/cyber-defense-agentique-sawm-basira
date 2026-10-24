"""Résumés factuels pour l'affichage, sans analyse LLM ni changement de décision.

Les anciens journaux restent intacts : leur projection peut recevoir ce résumé
à partir des seuls faits conservés. Aucun statut courant n'est inféré du passé.
"""
from __future__ import annotations

import json


def _faits(incident):
    values = incident.get('faits')
    for value in values[:30] if isinstance(values, list) else []:
        if isinstance(value, str) and len(value) <= 2000:
            try:
                value = json.loads(value)
            except (ValueError, RecursionError):
                continue
        if isinstance(value, dict):
            yield value


def _entier(value):
    return type(value) is int and 0 <= value <= 2**63 - 1


def motif_detection(incident):
    """Lire les mesures typées uniquement ; un texte libre n'est pas une preuve."""
    genre = incident.get('genre') or incident.get('titre')
    if genre not in ('sequence_reseau_hors_baseline', 'sequence reseau hors baseline'):
        return ''
    for fait in _faits(incident):
        identity, sequence = fait.get('identite_os'), fait.get('sequence')
        if not isinstance(identity, dict) or not isinstance(sequence, list):
            continue
        first = next((s for s in sequence[:32] if isinstance(s, dict)
                      and s.get('etape') == 'premiere_presence_reseau_hors_baseline'), {})
        last = next((s for s in sequence[:32] if isinstance(s, dict)
                     and s.get('etape') == 'presence_reseau_reobservee_meme_processus'), {})
        count, start, end = last.get('echantillons_distincts'), first.get('monotone_ns'), last.get('monotone_ns')
        if not (_entier(count) and count >= 2 and _entier(start) and _entier(end) and end >= start):
            continue
        pid = identity.get('pid')
        process = 'Le processus PID ' + str(pid) if _entier(pid) and pid > 0 else 'Le processus'
        seconds = (end-start)/1_000_000_000
        text = (f'{process} a été observé en réseau dans {count} inventaires distincts '
                f'sur {seconds:.1f} s, hors de la liste des services connus. ')
        destinations = fait.get('destinations_observees')
        if isinstance(destinations, list):
            valid = [d for d in destinations[:32] if isinstance(d, str) and 0 < len(d) <= 128]
            if valid:
                text += 'Destinations consignées : ' + ', '.join(valid[:4]) + (f' (+{len(valid)-4} autres)' if len(valid)>4 else '') + '. '
        cgroup = identity.get('cgroup')
        if isinstance(cgroup, str) and cgroup and len(cgroup) <= 4096:
            units = [part for line in cgroup.splitlines() for part in line.split(':', 2)[-1].split('/')
                     if part.endswith('.service') and '..' not in part]
            if units:
                text += 'Service identifié : ' + units[-1][:160] + '. '
            else:
                text += 'Aucune unité .service identifiée dans le cgroup conservé. '
        return ('Résumé local des faits consignés : ' + text
                + 'Cet écart demande une vérification ; il ne prouve ni malware ni exfiltration.')[:4000]
    return ('Résumé local des faits consignés : séquence réseau signalée hors de la liste des '
            'services connus. Les mesures conservées sont incomplètes ou illisibles ; '
            'aucun nombre d’observations ni durée ne peut être confirmé ici.')
