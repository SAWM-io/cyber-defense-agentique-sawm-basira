#!/usr/bin/env python3
"""Telemetrie de l'invite, poussee vers le controleur une fois par seconde.

Elle ne mesure QUE ce que le noyau expose reellement. Aucune valeur n'est
estimee, interpolee ni lissee : une grandeur indisponible sort a `null`, jamais
a zero. La difference compte — un zero se lit comme « rien ne se passe », un
`null` comme « on ne sait pas », et confondre les deux est la facon la plus
simple de mentir avec un tableau de bord.

Separation des consommations par tranche systemd :
  sawm-defense.slice   capteurs, executeur, connecteur local
  sawm-charge.slice    injecteur de fautes et charges de test
  sawm-legitime.slice  service temoin et sauvegarde declaree

Chaque echantillon porte son horloge monotone ET son horodatage mural : le
controleur peut ainsi detecter un decalage d'horloge sans les melanger.
"""

from __future__ import annotations

import json
import copy
import math
import os
import re
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
import capteur_fichiers
import jetons
import auth_guard
import ssh_observation
import posture_securite
from auth_campaigns import campagnes_auth
try:
    from geoip_context import GeoIPContext
except ImportError:
    GeoIPContext = None

CONTROLEUR = (os.environ.get("LABO_CONTROLEUR", "127.0.0.1"),
              int(os.environ.get("LABO_PORT", "47900")))
PERIODE = float(os.environ.get("LABO_PERIODE", "1.0"))
CGROUP = "/sys/fs/cgroup"
TRANCHES = {
    "defense": "sawm-defense.slice",
    "charge": "sawm-charge.slice",
    "legitime": "sawm-legitime.slice",
}
# La disponibilite se mesure sur /sante, qui reste ouvert expres : sonder
# /document (authentifie depuis la rotation de jeton) rendrait 401 et ferait
# afficher « indisponible » un service parfaitement vivant.
SERVICE_SANTE = os.environ.get("LABO_TEMOIN_SANTE", "http://127.0.0.1:8080/sante")
# Sonde du travail reel, avec le jeton en vigueur : elle prouve en plus que
# l'authentification fonctionne. Distincte de la disponibilite.
SERVICE_DOCUMENT = os.environ.get("LABO_TEMOIN_DOC", "http://127.0.0.1:8080/document")
JETONS_ETAT = os.environ.get("LABO_JETONS", "/opt/sawm-labo/jetons.json")
AUTH_JOURNAL = "/opt/sawm-labo/auth-guard/events.jsonl"
DEFENSE_ETAT = "/run/sawm-labo/defense-state.json"
INTEGRITE_ARBRE_ETAT = "/run/sawm-large-tree/status.json"
GEOIP_DATABASE = "/opt/sawm-labo/geoip/dbip-country.sqlite"
GEOIP_MANIFEST = "/opt/sawm-labo/geoip/manifest.json"
_GEOIP = None
_GEOIP_INITIALIZED = False


def _geographie_locale():
    """Une vérification SHA256 au chargement, jamais à chaque échantillon."""
    global _GEOIP, _GEOIP_INITIALIZED
    if not _GEOIP_INITIALIZED:
        _GEOIP_INITIALIZED = True
        if GeoIPContext is not None:
            _GEOIP = GeoIPContext(GEOIP_DATABASE, GEOIP_MANIFEST)
    return _GEOIP


def geographie_reseau(observations):
    """Enrichissement optionnel auth/SSH ; ne modifie aucune décision existante."""
    result = copy.deepcopy(observations)
    context = _geographie_locale()
    if context is None:
        result['geoip'] = {'available': False, 'status': 'lecteur_absent', 'network_request': False}
        return result
    result['geoip'] = {**context.describe(), 'lookup_limit': 64, 'truncated': False}
    cache = {}

    def enrich(row, field):
        if type(row) is not dict:
            return
        ip = row.get(field)
        if type(ip) is not str:
            return
        if ip not in cache:
            if len(cache) >= 64:
                result['geoip']['truncated'] = True
                return
            data = context.lookup(ip)
            # La provenance complète est portée une fois dans geoip.source.
            cache[ip] = {key: data[key] for key in
                ('status','country_code','precision','reason','human_location_known','block_from_geography')}
            cache[ip]['source_ref'] = 'geoip.source'
            cache[ip]['database_sha256'] = data['source'].get('database_sha256')
        row['geolocalisation'] = dict(cache[ip])

    for key in ('events','alertes'):
        for row in result.get(key, [])[:128]:
            enrich(row, 'source_ip')
    for campaign in result.get('campagnes', [])[:64]:
        for row in campaign.get('sources', [])[:32]:
            enrich(row, 'ip')
        campaign['geographie_etablit_identite_commune'] = False
        campaign['geographie_declenche_blocage'] = False
    return result


def _json_unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate_json_key')
        result[key] = value
    return result


def _reject_constant(_):
    raise ValueError('non_finite_json')


def _lire_prive(chemin, *, maximum=65536, tail=False, owner_uid=0):
    """Lecture bornée root, sans symlink ni parent inscriptible par autrui.

    Le journal JSONL peut être plus grand : seule sa queue est lue. Un fichier
    d'état doit tenir entièrement dans la borne, sinon l'état reste inconnu.
    """
    from pathlib import Path
    path = Path(chemin)
    auth_guard._safe_parent(path, owner_uid)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner_uid
                or before.st_mode & 0o077 or before.st_nlink != 1):
            raise ValueError('private_state_untrusted')
        truncated = before.st_size > maximum
        if truncated and not tail:
            raise ValueError('private_state_too_large')
        if truncated:
            os.lseek(fd, before.st_size-maximum, os.SEEK_SET)
        data = os.read(fd, maximum+1)
        if len(data) > maximum:
            raise ValueError('private_state_grew')
        after = os.fstat(fd)
        if not tail and (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError('private_state_changed')
        if truncated:
            # Retirer la première ligne potentiellement tronquée, même si elle
            # ressemblait accidentellement à un objet JSON complet.
            data = data.partition(b'\n')[2]
        return data, truncated
    finally:
        os.close(fd)


def authentification(*, now_ms=None, chemin=AUTH_JOURNAL, owner_uid=0):
    """Expose les événements du garde et rapproche ses IP, sans nouveau droit."""
    now_ms = int(time.time()*1000) if now_ms is None else now_ms
    out = {'schema': 'sawm-auth-telemetry/v1', 'available': False,
           'status': 'journal_absent', 'events': [], 'campagnes': [],
           'age_ms': None, 'invalid_events': 0, 'truncated': False,
           'human_identity_established': False, 'block_propagation': False}
    try:
        data, out['truncated'] = _lire_prive(chemin, tail=True, owner_uid=owner_uid)
        rows = []
        lines = data.splitlines()
        if len(lines) > 128:
            out['truncated'] = True
        for line in lines[-128:]:
            try:
                event = json.loads(line, object_pairs_hook=_json_unique, parse_constant=_reject_constant)
                event = auth_guard.validate_event(event)
                if 0 <= now_ms-event['observed_ms'] <= 300_000:
                    rows.append(event)
            except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
                out['invalid_events'] += 1
        correlations = campagnes_auth(rows, maintenant_ms=now_ms)
        out.update(available=True, status='observations_recentes' if rows else 'aucun_evenement_recent',
                   events=rows[-32:], campagnes=correlations['campagnes'],
                   age_ms=now_ms-max(row['observed_ms'] for row in rows) if rows else None,
                   limits=correlations['limites'])
    except FileNotFoundError:
        pass
    except (OSError, ValueError, TypeError, RecursionError):
        out['status'] = 'journal_non_verifiable'
    return geographie_reseau(out)


def defense_fichiers(*, now_ms=None, chemin=DEFENSE_ETAT, owner_uid=0):
    """Absence du garde distincte de zéro alerte ; snapshot root jamais exécuté."""
    now_ms = int(time.time()*1000) if now_ms is None else now_ms
    out = {'available': False, 'status': 'etat_absent', 'snapshot': None, 'age_ms': None}
    try:
        data, _ = _lire_prive(chemin, owner_uid=owner_uid)
        value = json.loads(data, object_pairs_hook=_json_unique, parse_constant=_reject_constant)
        if type(value) is not dict or value.get('schema') != 'sawm-file-defense/v1':
            raise ValueError('defense_state_invalid')
        observed = value.get('observed_ms', value.get('updated_at_ms'))
        age = now_ms-observed if type(observed) is int and 0 < observed <= now_ms else None
        out.update(available=True, status='etat_recu' if age is not None and age <= 5000 else 'fraicheur_non_etablie',
                   snapshot=value, age_ms=age)
    except FileNotFoundError:
        pass
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        out['status'] = 'etat_non_verifiable'
    return out


def integrite_arbres(*, now_ms=None, chemin=INTEGRITE_ARBRE_ETAT, owner_uid=0):
    """Dernier scan staging borné ; ne prétend jamais une surveillance continue."""
    now_ms = int(time.time()*1000) if now_ms is None else now_ms
    out = {'available': False, 'status': 'scan_absent', 'snapshot': None, 'age_ms': None,
           'continuous_monitoring': False, 'recent_threshold_ms': 300000}
    kinds = {'added','deleted','rename_candidate','type_changed','content_changed',
             'object_replaced','permissions_changed','owner_changed'}
    metric_keys = {'scan_seconds','cpu_seconds','cpu_one_core_percent','process_peak_rss_bytes',
                   'bytes_read','files','entries','blocks','rate_bytes_per_second'}
    try:
        data, _ = _lire_prive(chemin, maximum=262144, owner_uid=owner_uid)
        value = json.loads(data, object_pairs_hook=_json_unique, parse_constant=_reject_constant)
        if (type(value) is not dict or value.get('schema') != 'sawm-large-tree-integrity/v1'
                or value.get('status') not in ('unchanged','changed','inconclusive')
                or value.get('attribution') != 'unknown' or value.get('action_performed') is not False
                or not isinstance(value.get('root'), str) or len(value['root']) > 4096
                or type(value.get('observed_ms')) is not int or not 0 < value['observed_ms'] <= now_ms
                or type(value.get('scan_started_ms')) is not int or not 0 < value['scan_started_ms'] <= value['observed_ms']
                or type(value.get('counts')) is not dict or set(value['counts'])-kinds
                or any(type(n) is not int or n < 0 for n in value['counts'].values())
                or type(value.get('changes')) is not list or len(value['changes']) > 2000
                or type(value.get('metrics')) is not dict):
            raise ValueError('large_tree_snapshot_invalid')
        changes=[]
        for row in value['changes'][:200]:
            if type(row) is not dict or row.get('kind') not in kinds or not isinstance(row.get('path'),str):
                raise ValueError('large_tree_change_invalid')
            changes.append({k:v for k,v in row.items() if k in
                            ('kind','path','previous_path','previous','current','changed_block_count','changed_block_indexes')})
        metrics={k:v for k,v in value['metrics'].items() if k in metric_keys}
        if any(type(v) not in (int,float) or v < 0 or v > 10**18 or not math.isfinite(v) for v in metrics.values()):
            raise ValueError('large_tree_metrics_invalid')
        clean={k:value[k] for k in ('schema','status','root','scan_started_ms','observed_ms','counts','attribution','action_performed')}
        clean.update(changes=changes, metrics=metrics,
                     changes_truncated=value.get('changes_truncated') is True or len(value['changes'])>len(changes))
        if isinstance(value.get('baseline_sha256'),str) and re.fullmatch('[a-f0-9]{64}',value['baseline_sha256']):
            clean['baseline_sha256']=value['baseline_sha256']
        if isinstance(value.get('reason'),str):clean['reason']=value['reason'][:300]
        age=now_ms-value['observed_ms']
        out.update(available=True,status='dernier_scan' if age<=300000 else 'scan_ancien',age_ms=age,snapshot=clean)
    except FileNotFoundError:
        pass
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        out['status']='scan_non_verifiable'
    return out


def lire(chemin: str) -> str | None:
    try:
        with open(chemin) as f:
            return f.read()
    except OSError:
        return None


_CHEMINS: dict[str, str | None] = {}


def chemin_tranche(tranche: str) -> str | None:
    """Resout le chemin cgroup REEL d'une tranche systemd.

    Piege : systemd lit le tiret d'un nom de tranche comme une hierarchie.
    `sawm-defense.slice` est donc un ENFANT de `sawm.slice`, et vit dans
    /sys/fs/cgroup/sawm.slice/sawm-defense.slice — pas a la racine. Chercher
    au mauvais endroit rend `null` en silence, ce qui se lit comme « pas de
    consommation » alors que c'est « pas mesure ».
    """
    if _CHEMINS.get(tranche) and os.path.isdir(_CHEMINS[tranche]):
        return _CHEMINS[tranche]
    parent = tranche.split("-")[0] + ".slice" if "-" in tranche else None
    candidats = []
    if parent:
        candidats.append(f"{CGROUP}/{parent}/{tranche}")
    candidats.append(f"{CGROUP}/{tranche}")
    trouve = next((c for c in candidats if os.path.isdir(c)), None)
    _CHEMINS[tranche] = trouve
    return trouve


def champ_cgroup(tranche: str, fichier: str, cle: str | None = None):
    """Une grandeur de cgroup v2, ou None si la tranche n'existe pas encore."""
    base = chemin_tranche(tranche)
    if base is None:
        return None
    brut = lire(f"{base}/{fichier}")
    if brut is None:
        return None
    if cle is None:
        brut = brut.strip()
        return int(brut) if brut.isdigit() else None
    for ligne in brut.splitlines():
        parts = ligne.split()
        if parts and parts[0] == cle and len(parts) > 1:
            try:
                return int(parts[1])
            except ValueError:
                return None
    return None


def cpu_global() -> dict | None:
    brut = lire("/proc/stat")
    if not brut:
        return None
    for ligne in brut.splitlines():
        if ligne.startswith("cpu "):
            v = [int(x) for x in ligne.split()[1:]]
            return {"total_jiffies": sum(v[:8]), "oisif_jiffies": v[3] + (v[4] if len(v) > 4 else 0)}
    return None


def memoire() -> dict:
    brut = lire("/proc/meminfo") or ""
    m = {}
    for ligne in brut.splitlines():
        parts = ligne.split()
        if len(parts) >= 2:
            m[parts[0].rstrip(":")] = int(parts[1]) * 1024
    return {
        "total_o": m.get("MemTotal"),
        "disponible_o": m.get("MemAvailable"),
        "utilisee_o": (m.get("MemTotal", 0) - m.get("MemAvailable", 0)) or None,
        "swap_total_o": m.get("SwapTotal"),
        "swap_utilise_o": (m.get("SwapTotal", 0) - m.get("SwapFree", 0))
        if m.get("SwapTotal") else None,
    }


def disque() -> dict:
    try:
        st = os.statvfs("/")
        libre = st.f_bavail * st.f_frsize
        total = st.f_blocks * st.f_frsize
    except OSError:
        libre = total = None
    io = {"lus_o": None, "ecrits_o": None}
    brut = lire("/proc/diskstats")
    if brut:
        lus = ecrits = 0
        for ligne in brut.splitlines():
            p = ligne.split()
            # On ne compte que les disques entiers (vda), pas leurs partitions,
            # sinon chaque octet est compte deux fois.
            if len(p) >= 10 and p[2] in ("vda", "sda", "nvme0n1"):
                lus += int(p[5]) * 512
                ecrits += int(p[9]) * 512
        io = {"lus_o": lus, "ecrits_o": ecrits}
    return {"libre_o": libre, "total_o": total, **io}


def reseau() -> dict:
    brut = lire("/proc/net/dev") or ""
    interfaces = {}
    for ligne in brut.splitlines()[2:]:
        nom, _, reste = ligne.partition(":")
        nom = nom.strip()
        p = reste.split()
        if len(p) >= 9:
            interfaces[nom] = {"recus_o": int(p[0]), "emis_o": int(p[8])}
    return interfaces


_EXEC_UNIT = 'labo-capteur-exec.service'
_EXEC_CGROUP = '/sawm.slice/sawm-defense.slice/' + _EXEC_UNIT


def _systemd_exec() -> dict:
    champs = ('Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID', 'ControlGroup', 'InvocationID')
    p = subprocess.run(['systemctl', 'show', _EXEC_UNIT, '--property=' + ','.join(champs)],
                       capture_output=True, text=True, timeout=1)
    if p.returncode or len(p.stdout) > 8192:
        raise ValueError('systemd_indisponible')
    props = dict(line.split('=', 1) for line in p.stdout.splitlines() if '=' in line)
    if set(props) != set(champs) or props['Id'] != _EXEC_UNIT or props['LoadState'] != 'loaded':
        raise ValueError('systemd_incomplet')
    return props


def _identite_exec(props):
    """Le PID seul, même vivant, n'identifie jamais le capteur attendu."""
    pid = props['MainPID']
    if (not pid.isdecimal() or not 1 < int(pid) < 2**31
            or props['ControlGroup'] != _EXEC_CGROUP
            or not re.fullmatch(r'[a-f0-9]{32}', props['InvocationID'])):
        return None
    boot = (lire('/proc/sys/kernel/random/boot_id') or '').strip()
    if not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', boot):
        return None
    ticks, group = identite_processus(int(pid))
    try:
        exe = os.readlink('/proc/' + pid + '/exe')
    except OSError:
        return None
    if ticks is None or ticks <= 0 or group != '0::' + _EXEC_CGROUP or exe != '/usr/bin/bpftrace':
        return None
    return (boot, int(pid), ticks, group, props['InvocationID'], exe)


def _etat_exec() -> dict:
    """Identité stable et attachement perf vérifié ; ni PID-file ni log historique.

    Les bpftrace anciens attachent par perf_event, sans lien visible dans
    `bpftool link show`. `perf show` relie ici le tracepoint précis au MainPID.
    Cela prouve un attachement observé, pas la réception récente ni zéro perte.
    """
    proof = {'source': 'systemd+/proc+bpftool-perf', 'unit': _EXEC_UNIT,
             'identite_stable': False, 'pid': None, 'programme_ids': [],
             'motif': 'observation_indisponible',
             'limite': 'Processus actif distinct d’un attachement noyau; réception récente et absence de pertes non établies.'}
    out = {'ebpf_exec_actif': None, 'ebpf_exec_processus_actif': None, 'ebpf_exec_preuve': proof}
    try:
        before = _systemd_exec()
        if before['ActiveState'] in ('inactive', 'failed') and before['MainPID'] == '0':
            if _systemd_exec() == before:
                out.update(ebpf_exec_actif=False, ebpf_exec_processus_actif=False)
                proof.update(identite_stable=True, motif='service_inactif')
            else:
                proof['motif'] = 'identite_changee'
            return out
        if before['ActiveState'] != 'active' or before['SubState'] != 'running':
            proof['motif'] = 'service_en_transition'
            return out
        identity = _identite_exec(before)
        if identity is None:
            proof['motif'] = 'identite_non_verifiee'
            return out
        programs = None
        try:
            perf = subprocess.run(['bpftool', '-j', 'perf', 'show'],
                                  capture_output=True, text=True, timeout=1)
            if perf.returncode or len(perf.stdout) > 1024*1024:
                raise ValueError('preuve_perf_indisponible')
            rows = json.loads(perf.stdout)
            if type(rows) is not list or len(rows) > 4096 or any(
                    type(row) is not dict or type(row.get('pid')) is not int or row['pid'] <= 0
                    for row in rows):
                raise ValueError('preuve_perf_invalide')
            programs = []
            for row in rows:
                if (type(row.get('pid')) is int and row['pid'] == identity[1]
                        and row.get('fd_type') == 'tracepoint'
                        and row.get('tracepoint') == 'sched_process_exec'):
                    if type(row.get('fd')) is not int or row['fd'] < 0 \
                            or type(row.get('prog_id')) is not int or row['prog_id'] <= 0:
                        raise ValueError('preuve_perf_invalide')
                    programs.append(row['prog_id'])
        except (OSError, subprocess.SubprocessError, ValueError, TypeError):
            programs = None
        after = _systemd_exec()
        if after != before or _identite_exec(after) != identity:
            proof['motif'] = 'identite_changee'
            return out
        out['ebpf_exec_processus_actif'] = True
        proof.update(identite_stable=True, pid=identity[1], starttime_ticks=identity[2],
                     boot_id=identity[0], invocation_id=identity[4])
        if programs is None:
            proof['motif'] = 'attachement_indisponible'
        else:
            out['ebpf_exec_actif'] = bool(programs)
            proof.update(programme_ids=sorted(set(programs))[:64],
                         motif='attachement_verifie' if programs else 'attachement_absent')
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        proof['motif'] = 'observation_indisponible'
    return out


def capteurs() -> dict:
    """Etat REEL des capteurs, y compris leurs pertes.

    Un capteur arrêté doit se voir. L'état exec exige une identité systemd
    stable et le tracepoint réellement attaché ; le processus est distinct.
    """
    etat = {"ebpf_exec_actif": None, "lsm_attache": None,
            "lignes_exec": None, "refus_ouverture": None,
            "exemptions_temoin": None, "refus_execution": None,
            "ouvertures_vues": None, "pertes_bpftrace": None}
    etat.update(_etat_exec())
    journal = lire("/var/log/capteur_exec.jsonl")
    if journal is not None:
        etat["lignes_exec"] = journal.count("\n")
    err = lire("/var/log/capteur_exec.err")
    if err is not None:
        # bpftrace annonce ses pertes de file explicitement.
        etat["pertes_bpftrace"] = err.lower().count("lost")
    etat["lsm_attache"] = os.path.exists("/sys/fs/bpf/sawm/refus_ouverture")
    compteurs = _compteurs_bpf()
    if compteurs:
        etat.update(compteurs)
    return etat


def _compteurs_bpf() -> dict | None:
    """Lit les compteurs du programme LSM par bpftool, en JSON."""
    import subprocess
    if not os.path.exists("/sys/fs/bpf/sawm/compteurs"):
        return None
    try:
        r = subprocess.run(["bpftool", "-j", "map", "dump", "pinned",
                            "/sys/fs/bpf/sawm/compteurs"],
                           capture_output=True, text=True, timeout=2)
        if r.returncode != 0:
            return None
        noms = ["refus_ouverture", "exemptions_temoin",
                "refus_execution", "ouvertures_vues"]
        out = {}
        for entree in json.loads(r.stdout):
            cle = entree.get("key")
            val = entree.get("value")
            idx = _octets_vers_int(cle)
            v = _octets_vers_int(val)
            if idx is not None and 0 <= idx < len(noms):
                out[noms[idx]] = v
        return out
    except Exception:
        return None


def _octets_vers_int(v):
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v, 0)
        except ValueError:
            return None
    if isinstance(v, list):
        try:
            return int.from_bytes(bytes(int(x, 0) if isinstance(x, str) else int(x)
                                        for x in v), "little")
        except Exception:
            return None
    return None


def _version_jeton() -> int | None:
    try:
        return jetons.version_courante()
    except (OSError, ValueError, TypeError, KeyError):
        return None


def service_temoin() -> dict:
    """Disponibilite du service legitime, et sonde authentifiee du travail reel.

    Deux mesures distinctes, jamais confondues :
      - disponible : /sante repond (le service vit). Point ouvert par dessein.
      - travail_authentifie : /document sert avec le jeton en vigueur (l'auth
        fonctionne). Un 401 ici n'est PAS une indisponibilite du service : c'est
        soit un jeton perime, soit une revocation en cours.
    """
    t0 = time.monotonic()
    out = {"disponible": False, "code": None, "latence_ms": None,
           "erreur": None, "travail_authentifie": None,
           "travail_code": None, "version_jeton": _version_jeton()}
    try:
        with urllib.request.urlopen(SERVICE_SANTE, timeout=2) as r:
            r.read(512)
            out.update(disponible=True, code=r.status,
                       latence_ms=round((time.monotonic() - t0) * 1000, 2))
    except urllib.error.HTTPError as e:
        out.update(code=e.code, erreur=f"HTTP {e.code}",
                   latence_ms=round((time.monotonic() - t0) * 1000, 2))
        return out
    except Exception as e:
        out.update(erreur=type(e).__name__,
                   latence_ms=round((time.monotonic() - t0) * 1000, 2))
        return out
    # Le service vit : on eprouve maintenant le travail reel, jeton a l'appui.
    try:
        req = urllib.request.Request(
            SERVICE_DOCUMENT, headers={"X-Labo-Jeton": jetons.emettre()})
        with urllib.request.urlopen(req, timeout=2) as r:
            r.read(512)
            out.update(travail_authentifie=True, travail_code=r.status)
    except urllib.error.HTTPError as e:
        out.update(travail_authentifie=False, travail_code=e.code)
    except Exception:
        out.update(travail_authentifie=False, travail_code=None)
    return out


def recepteur() -> dict | None:
    """Octets REELLEMENT recus par le recepteur du laboratoire."""
    brut = lire("/run/recepteur_labo.json")
    if not brut:
        return None
    try:
        return json.loads(brut)
    except json.JSONDecodeError:
        return None


def identite_processus(pid):
    """Bracket the cgroup read with Linux start ticks to reject exited/reused PIDs."""
    def debut():
        raw = lire(f"/proc/{pid}/stat")
        if not raw or ") " not in raw:
            return None
        fields = raw.rsplit(") ", 1)[1].split()
        return int(fields[19]) if len(fields) > 19 and fields[19].isdigit() else None
    avant = debut()
    cg = lire(f"/proc/{pid}/cgroup")
    apres = debut()
    if avant is None or avant != apres or not cg:
        return None, None
    return avant, cg.strip()


def connexions() -> list[dict] | None:
    """Inventaire réel, à compléter par événements pour les flux très brefs."""
    try:
        p = subprocess.run(["ss", "-H", "-t", "-u", "-a", "-n", "-p"],
                           capture_output=True, text=True, timeout=1)
        if p.returncode:
            return None
        out = []
        for line in p.stdout.splitlines()[:100]:
            cols = line.split(None, 6)
            if len(cols) < 6:
                continue
            detail = cols[6] if len(cols) > 6 else ""
            pid = re.search(r"pid=(\d+)", detail)
            starttime, cgroup = identite_processus(int(pid.group(1))) if pid else (None, None)
            out.append({"protocole": cols[0], "etat": cols[1],
                        "locale": cols[4], "distante": cols[5],
                        "pid": int(pid.group(1)) if pid else None, "starttime": starttime,
                        "processus": detail[:220], "cgroup": (cgroup or "").strip() or None})
        return out
    except (OSError, subprocess.TimeoutExpired):
        return None


def echantillon(sequence: int) -> dict:
    tranches = {}
    for nom, slice_ in TRANCHES.items():
        tranches[nom] = {
            "cpu_usage_usec": champ_cgroup(slice_, "cpu.stat", "usage_usec"),
            "memoire_o": champ_cgroup(slice_, "memory.current"),
            "pids": champ_cgroup(slice_, "pids.current"),
            "presente": chemin_tranche(slice_) is not None,
            "cgroup": chemin_tranche(slice_),
        }
    return {
        "source": "invite",
        "boot_id": (lire("/proc/sys/kernel/random/boot_id") or "").strip() or None,
        "sequence": sequence,
        "mur_epoch_ms": int(time.time() * 1000),
        "monotone_ns": time.monotonic_ns(),
        "uptime_s": float((lire("/proc/uptime") or "0").split()[0]),
        "cpu": cpu_global(),
        "cpu_coeurs": os.cpu_count(),
        "memoire": memoire(),
        "disque": disque(),
        "reseau": reseau(),
        "tranches": tranches,
        "capteurs": capteurs(),
        "posture_securite": posture_securite.snapshot(),
        "service_temoin": service_temoin(),
        "recepteur": recepteur(),
        "connexions": connexions(),
        "fichiers": capteur_fichiers.etat(),
        "authentification": authentification(),
        "ssh": geographie_reseau(ssh_observation.etat()),
        "defense_fichiers": defense_fichiers(),
        "integrite_arbres": integrite_arbres(),
        "connexions_couverture": "inventaire TCP/UDP; connexions brèves possibles entre échantillons",
        "charge_moyenne": [float(x) for x in (lire("/proc/loadavg") or "0 0 0").split()[:3]],
    }


def main() -> None:
    capteur_fichiers.demarrer()
    sequence = 0
    prochaine = time.monotonic()
    connexion: socket.socket | None = None
    while True:
        sequence += 1
        try:
            paquet = (json.dumps(echantillon(sequence), ensure_ascii=False)
                      + "\n").encode()
        except Exception as e:                       # jamais fatal
            paquet = (json.dumps({"source": "invite", "sequence": sequence,
                                  "erreur_echantillon": f"{type(e).__name__}: {e}",
                                  "mur_epoch_ms": int(time.time() * 1000)}) + "\n").encode()
        try:
            if connexion is None:
                connexion = socket.create_connection(CONTROLEUR, timeout=3)
                connexion.settimeout(3)
            connexion.sendall(paquet)
        except Exception:
            # Le controleur est parti : on ne bloque pas l'invite, on ne perd
            # pas la cadence, et le controleur VERRA le trou.
            try:
                if connexion:
                    connexion.close()
            except Exception:
                pass
            connexion = None
        prochaine += PERIODE
        delai = prochaine - time.monotonic()
        if delai < 0:                                # on a pris du retard
            prochaine = time.monotonic()
            delai = 0
        time.sleep(delai)


if __name__ == "__main__":
    sys.exit(main())
