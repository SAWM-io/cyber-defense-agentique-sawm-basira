"""Invariant de disponibilité explicite, local et séparé du jugement SAWM.

Seules les mesures du contrôleur et le manifeste vérifié entrent ici.
Ce garde ne déduit ni intention malveillante, ni causalité d'un hash différent.
"""
from connecteur.contrat import Proposition
from controleur.maintenance import evaluate

def preservation_explicitement_autorisee(manifeste, unit, current, *, maintenance_observation=None, now_ms=None):
    """Une permission d'arrêt n'annule pas le mandat de maintenance d'une base.

    Protection bornée aux mesures SQLite connues. Aucune qualification fondée
    sur l'étiquette d'un scénario ni sur la justification du LLM.
    """
    db=manifeste.get('database_policy') or {}
    if 'maintenance' in manifeste:
        observation = maintenance_observation or {}
        objet = observation.get('object') or {}
        return evaluate(manifeste, observation, unit=unit, operation='sqlite-exclusive-lock',
                        object_path=objet.get('path'), now_ms=now_ms)['authorized']
    # Compatibilité : uniquement le manifeste root déjà vérifié par l'appelant.
    # Aucun fallback legacy si une politique de mandats signés est configurée.
    return (db.get('unit')==unit and db.get('exclusive_lock_authorized') is True
        and db.get('availability_required') is False and current.get('reference_matches') is True
        and current.get('reference_sha256')==db.get('reference_sha256')
        and current.get('hash_stable_during_probe') is True
        and all(v in (None,'SQLITE_BUSY') for v in current.get('errors',{}).values()))

def proposer(manifeste, baseline, current, attribution, *, maintenance_observation=None, now_ms=None):
    db=manifeste.get('database_policy') or {}
    unit=db.get('unit')
    if 'maintenance' in manifeste:
        observation = maintenance_observation or {}
        objet = observation.get('object') or {}
        maintenance = evaluate(manifeste, observation, unit=unit, operation='sqlite-exclusive-lock',
                               object_path=objet.get('path'), now_ms=now_ms)
        if maintenance['authorized'] or maintenance['reason'] in {
                'politique_absente_ou_invalide', 'requete_invalide', 'horloge_invalide',
                'bornes_invalides', 'identite_os_non_verifiee', 'observation_perimee_ou_future',
                'registre_mandats_invalide', 'registre_mandats_ambigu', 'contrat_malforme'}:
            return None
    if (db.get('availability_required') is not True
            or db.get('exclusive_lock_authorized') is not False
            or unit not in manifeste.get('unites_autorisees',[])
            or unit in manifeste.get('unites_protegees',[])
            or 'arreter-service' not in manifeste.get('veille',{}).get('actions_automatiques',[])):
        return None
    if any(baseline.get(k) is not True for k in ('read_available','write_available')):
        return None
    if (any(current.get(k) is not False for k in ('read_available','write_available'))
            or current.get('errors',{}).get('read')!='SQLITE_BUSY'
            or current.get('errors',{}).get('write')!='SQLITE_BUSY'):
        return None
    if (attribution.get('unit')!=unit or attribution.get('attribution_available') is not True
            or attribution.get('fd_on_database') is not True
            or not attribution.get('kernel_locks')
            or attribution.get('systemd',{}).get('ActiveState')!='active'):
        return None
    return Proposition('arreter-service',unit,
        'Garde local : disponibilité exigée, verrou exclusif interdit, lectures et écritures SQLITE_BUSY ; détenteur attribué par le noyau. Aucun diagnostic de virus.',1.0)
