"""Vérification indépendante, en lecture seule, après une action autorisée.

Le reçu de l'exécuteur n'est pas la preuve de l'effet futur. On relit l'unité
exacte et son cgroup, puis le document témoin. Aucun port/source_id déclaratif
n'est converti en attribution réseau. Une observation manquante reste inconnue.
"""
from __future__ import annotations

import math
import re
import time

_UNIT = re.compile(r"labo-[a-z0-9][a-z0-9_.-]{0,55}\.service")


def observer_ressource(cible, cgroup_reference=None):
    """Lecture root bornée sur l'invité connu, aucune mutation ni commande LLM."""
    if not isinstance(cible, str) or not _UNIT.fullmatch(cible):
        raise ValueError('unite_hors_laboratoire')
    if cgroup_reference is not None and (not isinstance(cgroup_reference, str)
        or not cgroup_reference.startswith('/sawm.slice/')
        or cgroup_reference.split('/')[-1] != cible
        or any(x in ('.', '..') for x in cgroup_reference.split('/'))):
        raise ValueError('cgroup_hors_unite')
    from controleur.vm_labo import json_code
    source = "cible=" + repr(cible) + ";reference=" + repr(cgroup_reference) + '\n' + r'''
import json,pathlib,subprocess,time,urllib.request
r={'cible':cible,'mur_epoch_ms':int(time.time()*1000),'monotonic_s':time.monotonic(),
   'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
fields='Id,LoadState,ActiveState,MainPID,ControlGroup,InvocationID,CPUQuotaPerSecUSec'
p=subprocess.run(['systemctl','show','--property='+fields,'--',cible],capture_output=True,text=True,timeout=5)
if p.returncode: raise RuntimeError('systemctl_indisponible')
u=dict(x.split('=',1) for x in p.stdout.splitlines() if '=' in x)
if u.get('Id') != cible or u.get('LoadState') != 'loaded':raise RuntimeError('unite_non_chargee')
r['unite']=u
cg=reference or u.get('ControlGroup')
if not cg or not cg.startswith('/sawm.slice/') or cg.split('/')[-1]!=cible or any(x in ('.','..') for x in cg.split('/')):
 raise RuntimeError('cgroup_non_specifique')
r['cgroup']=cg
path=pathlib.Path('/sys/fs/cgroup'+cg)
if path.is_symlink():raise RuntimeError('cgroup_symbolique')
r['cgroup_present']=path.exists()
if not path.exists():
 r.update(pids=[],populated=0,cpu_usage_usec=None,cpu_max=None)
else:
 r['pids']=[int(x) for x in (path/'cgroup.procs').read_text().split()]
 events=dict(x.split() for x in (path/'cgroup.events').read_text().splitlines())
 r['populated']=int(events['populated'])
 stats=dict(x.split() for x in (path/'cpu.stat').read_text().splitlines())
 r['cpu_usage_usec']=int(stats['usage_usec'])
 r['cpu_max']=(path/'cpu.max').read_text().strip()
try:
 import sys
 sys.path.insert(0,'/opt/sawm-labo/agent')
 from jetons import emettre
 requete=urllib.request.Request('http://127.0.0.1:8080/document',headers={'X-Labo-Jeton':emettre()})
 with urllib.request.urlopen(requete,timeout=2) as response:
  body=json.load(response)
  r['temoin']={'code':response.status,'lecture_document':isinstance(body,dict)}
except Exception as exc:r['temoin']={'code':None,'erreur':type(exc).__name__}
print(json.dumps(r))
'''
    return json_code(source, timeout=15)


def _nombre(x):
    return type(x) in (int, float) and math.isfinite(x)


def _quota(s):
    try:
        q, p = s['cpu_max'].split()
        return 100 * int(q) / int(p) if q != 'max' and int(p) > 0 else None
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        return None


def verifier_action(action, cible, recu, avant, *, observer=observer_ressource,
                    attendre=time.sleep, echantillons=3, intervalle=.75):
    """Compare des relectures OS fraîches avec l'état figé avant l'exécution.

    Retour structuré: statut verifie/echec/inconclusif/non_appliquee; résultats
    séparés effet/témoin/réseau. `verifie` n'affirme rien après la fenêtre finie.
    Pour CPU, la limite cgroup est lue; la consommation est une mesure distincte,
    insuffisante sans charge pour démontrer que le quota a causé une réduction.
    """
    if type(echantillons) is not int or not 2 <= echantillons <= 8 or not .1 <= intervalle <= 2:
        raise ValueError('fenetre_verification_invalide')
    result = {'schema': 'sawm-lab-verification/v1', 'action': action, 'cible': cible,
              'decision_id': recu.get('decision_id'), 'statut': 'inconclusif',
              'effet': 'inconnu', 'temoin': 'inconnu', 'reseau': 'non_attribue',
              'avant': avant, 'observations': [], 'limites': [
                  'Vérification limitée à cette unité et à la fenêtre observée.',
                  'Aucune attribution du trafic ou intention déduite des noms/source_id.']}
    if recu.get('applique') is not True:
        result.update(statut='non_appliquee', motif='recu_sans_application_confirmee')
        return result
    if recu.get('action') != action or recu.get('cible') != cible:
        result['motif'] = 'recu_non_correlle'
        return result
    if action not in {'arreter-service', 'geler-transfert', 'limiter-cpu'}:
        result['motif'] = 'action_sans_verificateur'
        return result
    cg = (avant or {}).get('cgroup')
    au = (avant or {}).get('unite') or {}
    if not avant or avant.get('cible') != cible or au.get('Id') != cible \
            or not avant.get('boot_id') or not cg or au.get('ActiveState') != 'active' \
            or not avant.get('pids') or not au.get('InvocationID'):
        result['motif'] = 'etat_avant_incomplet_ou_inactif'
        return result
    for index in range(echantillons):
        if index:
            attendre(intervalle)
        try:
            snap = observer(cible, cg)
        except Exception as exc:
            result['observations'].append({'erreur': type(exc).__name__})
            continue
        result['observations'].append(snap)
    snaps = result['observations']
    last_time = avant.get('monotonic_s')
    valid = _nombre(last_time)
    for s in snaps:
        ts, wall = s.get('monotonic_s'), s.get('mur_epoch_ms')
        u = s.get('unite') or {}
        valid = valid and s.get('cible') == cible and u.get('Id') == cible \
            and s.get('boot_id') == avant['boot_id'] and s.get('cgroup') == cg \
            and _nombre(ts) and ts > last_time and _nombre(wall) \
            and _nombre(recu.get('recu_ms')) and wall >= recu['recu_ms'] \
            and type(s.get('pids')) is list and s.get('populated') in (0, 1)
        if _nombre(ts):
            last_time = ts
    if not valid:
        result['motif'] = 'observation_absente_perimee_ou_identite_changee'
        return result
    witnesses = [(s.get('temoin') or {}).get('code') for s in snaps]
    result['temoin'] = ('disponible' if all(c == 200 for c in witnesses)
                        else 'indisponible' if any(c is not None and c != 200 for c in witnesses)
                        else 'inconnu')
    if action in {'arreter-service', 'geler-transfert'}:
        if any(s['unite'].get('ActiveState') not in ('inactive', 'failed')
               or s['unite'].get('MainPID') != '0' or s['pids'] or s['populated'] != 0 for s in snaps):
            result.update(effet='non_confirme', statut='echec', motif='activite_apres_arret')
        else:
            result.update(effet='arret_unite_verifie', statut='verifie')
    else:
        if any(s['unite'].get('InvocationID') != au['InvocationID'] for s in snaps):
            result['motif'] = 'invocation_changee_cpu'
            return result
        target = (recu.get('effet') or {}).get('quota_demande_pct')
        quotas = [_quota(s) for s in snaps]
        if not _nombre(target) or not 1 <= target <= 100 or any(q is None for q in quotas):
            result['motif'] = 'quota_non_mesurable'
            return result
        result['quotas_lus_pct'] = quotas
        if any(abs(q - target) > .1 for q in quotas):
            result.update(statut='echec', effet='quota_non_conforme', motif='limite_cgroup_différente')
        else:
            result.update(statut='verifie', effet='quota_cgroup_verifie')
        first, last = snaps[0], snaps[-1]
        dt = last['monotonic_s'] - first['monotonic_s']
        u0, u1 = first.get('cpu_usage_usec'), last.get('cpu_usage_usec')
        if _nombre(u0) and _nombre(u1) and u1 >= u0 and dt > 0:
            result['cpu_observe_pct_un_coeur'] = round((u1-u0) / (dt*1e6)*100, 3)
        result['limites'].append('Quota configuré vérifié; baisse causale sous charge non démontrée par ce seul relevé.')
    if result['temoin'] != 'disponible':
        result['statut'] = 'echec' if result['temoin'] == 'indisponible' else 'inconclusif'
        result['motif'] = 'service_temoin_non_confirme'
    result['fenetre_observee_s'] = round(snaps[-1]['monotonic_s']-snaps[0]['monotonic_s'], 3)
    return result
