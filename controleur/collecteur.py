#!/usr/bin/env python3
"""Collecteur du laboratoire, sur Mac ou explicitement dans la VM Linux.

Les journaux JSONL sont la source des compteurs, y compris après redémarrage.
Une absence de mesure reste null. Les API n'exécutent aucune action dans la VM.
"""
from __future__ import annotations

import copy
from collections import deque
import bisect
import json
import math
import mimetypes
import os
import pathlib
import re
import shlex
import socket
import subprocess
import statistics
import stat
import sys
import importlib.util
import ipaddress
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlsplit

ICI = pathlib.Path(__file__).resolve().parent
RACINE = ICI.parent
if str(RACINE) not in sys.path:
    sys.path.insert(0,str(RACINE))
from controleur.activite_agent import engine_for, summarize as resume_activite_agent
from controleur.motifs_incidents import motif_detection
SERIES = RACINE / "releves" / "series"
VM_UUID = os.environ.get("SAWM_LABO_VM_UUID", "00000000-0000-0000-0000-000000000000").upper()
LOCAL_VM = os.environ.get("SAWM_LABO_LOCAL_VM") == "1"


def adresse_telemetrie(environ=None):
    """Telemetry is loopback by default; an explicit private bind is allowed for a remote guest.

    Telemetry is not authenticated by this socket. Use an SSH tunnel, or a
    dedicated isolated network; never expose it to the public Internet.
    """
    environ = os.environ if environ is None else environ
    local = environ.get("SAWM_LABO_LOCAL_VM") == "1"
    adresse = environ.get("LABO_BIND", "127.0.0.1")
    try:
        parsed = ipaddress.ip_address(adresse)
    except ValueError:
        raise ValueError("LABO_BIND requires a numeric private or loopback address") from None
    if parsed.is_unspecified or parsed.is_multicast or not (parsed.is_private or parsed.is_loopback):
        raise ValueError("LABO_BIND must be private or loopback; wildcard/public binds are refused")
    if local and not parsed.is_loopback:
        raise ValueError("LABO_BIND must be loopback in local VM mode")
    # Port de télémétrie : 47900 par défaut (labo), surchargeable pour une instance parallèle.
    port = int(environ.get("LABO_PORT_TELEMETRIE", "47900"))
    if not 1024 <= port <= 65535:
        raise ValueError("LABO_PORT_TELEMETRIE hors limites (1024-65535)")
    return adresse, port


ECOUTE_TELEMETRIE = adresse_telemetrie()
ECOUTE_HTTP = ("127.0.0.1", int(os.environ.get("LABO_HTTP", "8899")))
PERIODE_ATTENDUE = 1.0
FENETRE = 1800
MAX_CORPS = 65536
MAX_LIGNE = 262144
MAX_PREUVE = 8 * 1024 * 1024
MAX_CAMPAGNE_DEFENSE = 1024 * 1024
CAMPAGNE_DEFENSE = "releves/rapports/campagne-defense-20260923.json"
MAX_ACCES_EXTERIEUR = 1024 * 1024
ACCES_EXTERIEUR = "releves/rapports/validation-acces-exterieur-20260923.json"
IDENTIFIANT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}\Z")
PREFIXES_PREUVES = ("preuve", "doctor", "noyau", "journal-", "rapport", "recette", "experience", "verification", "validation")
EXTENSIONS_PREUVES = {".txt", ".json", ".html", ".pdf", ".md"}


def maintenant_ms() -> int:
    return int(time.time() * 1000)


def _texte(v, nom: str, maximum: int = 4000) -> str:
    if not isinstance(v, str) or len(v) > maximum or "\x00" in v:
        raise ValueError(f"{nom}: texte attendu, maximum {maximum} caractères")
    return v


def _nombre(v, nom: str, minimum=0, maximum=2**53 - 1, entier=False):
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
        raise ValueError(f"{nom}: nombre fini attendu")
    if not minimum <= v <= maximum or (entier and not isinstance(v, int)):
        raise ValueError(f"{nom}: valeur hors limites")
    return v


def _id(v, nom: str) -> str:
    if not isinstance(v, str) or not IDENTIFIANT.fullmatch(v):
        raise ValueError(f"{nom}: identifiant invalide")
    return v


def preuve_autorisee(nom: str, racine: pathlib.Path = RACINE) -> pathlib.Path:
    """Allowlist de preuves publiques, jamais un chemin libre ni un lien symbolique."""
    _texte(nom, "preuve", 240)
    p = pathlib.PurePosixPath(nom)
    if p.is_absolute() or "\\" in nom or any(x in ("", ".", "..") or x.startswith(".") for x in nom.split("/")):
        raise ValueError("chemin de preuve invalide")
    if p.suffix.lower() not in EXTENSIONS_PREUVES:
        raise ValueError("extension de preuve interdite")
    if len(p.parts) == 2 and p.parts[0] == "releves":
        if not p.name.startswith(PREFIXES_PREUVES):
            raise ValueError("preuve hors liste autorisée")
    elif len(p.parts) == 3 and p.parts[:2] == ("releves", "rapports"):
        pass
    else:
        raise ValueError("preuve hors liste autorisée")
    destination = racine.joinpath(*p.parts)
    for parent in (destination, *destination.parents):
        if parent == racine:
            break
        if parent.is_symlink():
            raise ValueError("lien symbolique interdit")
    if not destination.resolve().is_relative_to(racine.resolve()):
        raise ValueError("preuve hors laboratoire")
    return destination


def valider_evenement(genre: str, objet: dict) -> dict:
    if not isinstance(objet, dict):
        raise ValueError("objet JSON attendu")
    communs = {"mur_epoch_ms", "run_id", "incident_id", "decision_id", "preuves"}
    spec = {
        "cloud": {"appel", "statut", "ms", "tentative", "detail", "code", "jetons_total", "jetons_entree", "jetons_sortie", "event_id", "schema", "correlation_id", "phase", "resultat", "terminal", "methode", "heure", "usage", "turn_id", "job_statut", "replayed"},
        "marqueur": {"phase", "texte", "origine"},
        "incident": {"id", "titre", "statut", "gravite", "faits", "raison_publique", "motif_detection", "origine"},
        "decision": {"id", "action", "statut", "raison_publique", "faits", "origine"},
    }
    if genre not in spec or set(objet) - (communs | spec[genre]):
        raise ValueError("champ inconnu ou non public")
    requis = {"cloud": {"appel"}, "marqueur": {"phase", "texte"}, "incident": {"id", "titre", "statut"}, "decision": {"id", "action", "statut", "raison_publique"}}[genre]
    if requis - set(objet):
        raise ValueError("champ obligatoire absent: " + ", ".join(sorted(requis - set(objet))))
    out = {}
    for k, v in objet.items():
        if v is None and k in {"statut", "ms", "jetons_total", "jetons_entree", "jetons_sortie", "usage", "code", "detail", "terminal"}:
            out[k] = None
        elif k in {"mur_epoch_ms", "jetons_total", "jetons_entree", "jetons_sortie"}:
            out[k] = _nombre(v, k, entier=True)
        elif k == "statut" and genre == "cloud":
            out[k] = _nombre(v, k, 100, 599, entier=True)
        elif k == "ms":
            out[k] = _nombre(v, k, maximum=86400000)
        elif k == "tentative":
            out[k] = _nombre(v, k, 1, 100000, entier=True)
        elif k in {"id", "run_id", "incident_id", "decision_id", "event_id", "correlation_id", "turn_id"}:
            out[k] = _id(v, k)
        elif k == "faits":
            if not isinstance(v, list) or len(v) > 30:
                raise ValueError("faits: liste de 30 textes maximum")
            out[k] = [_texte(x, k, 2000) for x in v]
        elif k == "preuves":
            if not isinstance(v, list) or len(v) > 20:
                raise ValueError("preuves: liste de 20 chemins maximum")
            for nom in v:
                preuve_autorisee(nom)
            out[k] = list(v)
        elif k == "replayed":
            if not isinstance(v, bool):
                raise ValueError("replayed: booléen attendu")
            out[k] = v
        elif k == "usage":
            if not isinstance(v, dict) or len(v) > 32:
                raise ValueError("usage: objet numérique borné attendu")
            out[k] = {_id(n, "usage"): _nombre(x, "usage") for n, x in v.items()}
        else:
            out[k] = _texte(v, k, 4000 if k in {"raison_publique", "motif_detection", "texte"} else 1000)
    if genre == "cloud":
        if out.get("resultat") not in {None, "ok", "http_error", "transport_error", "stream_error", "incomplete"}:
            raise ValueError("résultat Cloud inconnu")
        if out.get("phase") not in {None, "http", "sse"}:
            raise ValueError("phase Cloud inconnue")
    if genre == "cloud" and out.get("job_statut") not in {None, "pending", "processing", "completed", "dead_letter"}:
        raise ValueError("statut de job inconnu")
    out.setdefault("mur_epoch_ms", maintenant_ms())
    return out


def _valider_telemetrie(v, profondeur=0):
    if profondeur > 12:
        raise ValueError("télémétrie trop profonde")
    if isinstance(v, dict):
        if len(v) > 128:
            raise ValueError("objet télémétrie trop grand")
        for k, x in v.items():
            _texte(k, "clé", 100)
            _valider_telemetrie(x, profondeur + 1)
    elif isinstance(v, list):
        if len(v) > 1000:
            raise ValueError("liste télémétrie trop grande")
        for x in v:
            _valider_telemetrie(x, profondeur + 1)
    elif isinstance(v, str):
        _texte(v, "valeur", 4000)
    elif v is not None and not isinstance(v, bool):
        _nombre(v, "mesure", -(2**63 - 1), 2**63 - 1)


def lire_campagne_defense(racine: pathlib.Path) -> dict:
    """Rapport public fixe, borné et en lecture seule, sans commande ni chemin client."""
    base = {"schema": "sawm-defense-campaign/v1", "updated_at": None,
            "status": "not_run", "cases": [], "limits": [], "error": None}
    try:
        path = preuve_autorisee(CAMPAGNE_DEFENSE, pathlib.Path(racine))
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as file:
            info = os.fstat(file.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CAMPAGNE_DEFENSE:
                raise ValueError("rapport non régulier ou trop volumineux")
            raw = file.read(MAX_CAMPAGNE_DEFENSE + 1)
        if len(raw) > MAX_CAMPAGNE_DEFENSE:
            raise ValueError("rapport trop volumineux")
        obj = json.loads(raw)
        if not isinstance(obj, dict) or obj.get("schema") != base["schema"]:
            raise ValueError("contrat inconnu")
        _valider_telemetrie(obj)
        _texte(obj.get("status"), "status", 100)
        if obj.get("updated_at") is not None:
            _texte(obj["updated_at"], "updated_at", 100)
        cases, limits = obj.get("cases"), obj.get("limits", [])
        if not isinstance(cases, list) or len(cases) > 40:
            raise ValueError("liste de cas invalide")
        if not isinstance(limits, list) or len(limits) > 40:
            raise ValueError("liste de limites invalide")
        for limite in limits:
            _texte(limite, "limit")
        publics = {"id", "title", "status", "decision", "applied_by", "observations",
                   "checks", "metrics", "cloud", "proof", "cloud_refs", "proof_refs", "error",
                   "cleanup", "operator_restoration", "local_decision", "local_veto", "protocol", "local_guard_enabled", "investigation_steps"}
        cas_publics = []
        for cas in cases:
            if not isinstance(cas, dict):
                raise ValueError("cas invalide")
            _id(cas.get("id"), "case id")
            _texte(cas.get("title"), "title", 1000)
            _texte(cas.get("status"), "case status", 100)
            if cas.get("applied_by") not in {"sawm", "operator", "local_policy", "none"}:
                raise ValueError("auteur de l'action inconnu")
            if "protocol" in cas:
                _texte(cas["protocol"], "protocol", 200)
            if "local_veto" in cas:
                _texte(cas["local_veto"], "local veto", 200)
            if "local_guard_enabled" in cas and not isinstance(cas["local_guard_enabled"], bool):
                raise ValueError("état de garde locale invalide")
            if "investigation_steps" in cas and (not isinstance(cas["investigation_steps"], list) or len(cas["investigation_steps"]) > 8 or any(not isinstance(step,dict) for step in cas["investigation_steps"])):
                raise ValueError("étapes enquête invalides")
            for champ in ("decision", "observations", "checks", "metrics", "cloud", "proof",
                          "cleanup", "operator_restoration", "local_decision"):
                if champ in cas and not isinstance(cas[champ], dict):
                    raise ValueError("objet de cas invalide")
            cas_publics.append({k: v for k, v in cas.items() if k in publics})
        # Les champs publics du rapport ne sont jamais pris dans les paramètres HTTP.
        champs = {"schema", "updated_at", "status", "run_id", "limits", "error",
                  "summary", "cloud", "proof", "cloud_refs", "proof_refs"}
        return {**base, **{k: v for k, v in obj.items() if k in champs}, "cases": cas_publics}
    except FileNotFoundError:
        return {**base, "error": "Campagne non exécutée : rapport local absent."}
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        return {**base, "status": "invalid",
                "error": "Rapport de campagne absent, invalide ou hors limites ; aucun résultat confirmé."}


def lire_autonomie_profondeur(racine: pathlib.Path) -> dict:
    """Latest bounded real-campaign files, never silently replace a failed run with a success.

    Only this filename family is discoverable. No VM, Cloud, mutation or client
    supplied path. Unknown fields, raw traces and OS identity documents are not
    forwarded by this public summary. Original evidence remains downloadable.
    """
    racine = pathlib.Path(racine)
    base = {"schema": "sawm-autonomy-depth-dashboard/v1", "status": "not_run",
            "reports": [], "latest_ms": None, "omitted": 0, "error": None}
    directory = racine / "releves" / "rapports"
    try:
        # Reject symlinked directory components before discovery.
        preuve_autorisee("releves/rapports/validation-autonomie-profondeur-depth-probe.json", racine)
        candidates = []
        with os.scandir(directory) as entries:
            for entry in entries:
                if re.fullmatch(r"validation-autonomie-profondeur-depth-[a-f0-9]{10}\.json", entry.name):
                    info = entry.stat(follow_symlinks=False)
                    candidates.append((info.st_mtime_ns, entry.name))
                if len(candidates) > 1000:
                    raise ValueError("too many campaign files")
        selected = sorted(candidates, reverse=True)[:40]
    except FileNotFoundError:
        return base
    except (OSError, ValueError):
        return {**base, "status": "invalid", "error": "Rapports non accessibles dans le périmètre autorisé."}

    def pick(value, keys):
        return {k: value[k] for k in keys if k in value} if isinstance(value, dict) else {}

    def receipt(value):
        out = pick(value, ("action", "cible", "applique", "effet_verifie", "duree_ms", "decision_id"))
        if isinstance(value, dict):
            out["refusal"] = pick(value.get("refus"), ("motif",))
            out["maintenance"] = pick(value.get("maintenance"), ("checked", "veto"))
            out["authorization"] = pick(value.get("defense_profondeur"), ("valide",))
        return out

    reports = []
    for modified, name in selected:
        relative = "releves/rapports/" + name
        row = {"id": name.removeprefix("validation-autonomie-profondeur-").removesuffix(".json"),
               "status": "invalid", "origin": "unknown", "case": "unknown",
               "started_ms": None, "finished_ms": None, "modified_ms": modified // 1000000,
               "proof_path": relative}
        try:
            path = preuve_autorisee(relative, racine)
            with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_CAMPAGNE_DEFENSE:
                    raise ValueError("invalid report file")
                raw = stream.read(MAX_CAMPAGNE_DEFENSE + 1)
            if len(raw) > MAX_CAMPAGNE_DEFENSE:
                raise ValueError("report too large")
            obj = json.loads(raw)
            if not isinstance(obj, dict) or obj.get("schema") != "sawm-autonomy-depth-validation/v1":
                raise ValueError("unknown schema")
            _valider_telemetrie(obj)
            if (obj.get("id") != row["id"] or obj.get("origin") not in {"local_guard", "sawm_pipeline"}
                    or obj.get("case") not in {"lock", "tamper", "maintenance"}
                    or obj.get("status") not in {"running", "passed", "failed", "blocked", "error", "interrupted", "not_evaluated"}
                    or type(obj.get("cloud_requested")) is not bool
                    or (obj["origin"] == "local_guard" and obj["cloud_requested"])):
                raise ValueError("invalid report identity or origin")
            _nombre(obj.get("started_ms"), "started_ms", entier=True)
            if obj.get("finished_ms") is not None:
                _nombre(obj["finished_ms"], "finished_ms", minimum=obj["started_ms"], entier=True)
            for field in ("sawm_effect_applied", "local_guard_effect_applied", "memory_feedback_recorded"):
                if field in obj and type(obj[field]) is not bool:
                    raise ValueError("invalid effect flag")
            for field in ("local_boundaries", "receipts", "verifications", "inspection_steps", "refusals", "limits"):
                if field in obj and (not isinstance(obj[field], list) or len(obj[field]) > 100):
                    raise ValueError("invalid report list")
            row.update(pick(obj, ("id", "status", "origin", "case", "started_ms", "finished_ms", "phase",
                "cloud_requested", "cloud_rounds_reserved", "sawm_effect_applied", "local_guard_effect_applied",
                "local_guard_wait_ms", "memory_feedback_recorded", "block_reason", "error_type", "limits")))
            row["sawm_choice"] = pick(obj.get("sawm_choice"), ("action", "reason", "unknowns"))
            row["diagnostic"] = pick(obj.get("local_guard_diagnostic"), ("priorite", "recommandation", "raison", "inconnues"))
            row["local_receipt"] = receipt(obj.get("local_guard_receipt"))
            row["receipts"] = [receipt(v) for v in obj.get("receipts", [])]
            row["verifications"] = [pick(v, ("statut", "effet", "temoin", "motif")) for v in obj.get("verifications", [])]
            row["inspection_steps"] = [pick(v, ("step", "action", "unit", "status", "reason", "unknowns")) for v in obj.get("inspection_steps", [])]
            row["refusals"] = [pick(v, ("type", "reason")) for v in obj.get("refusals", [])]
            row["after_before_cleanup"] = pick(obj.get("after_before_cleanup"),
                ("read_available", "write_available", "reference_matches", "integrity_check", "observed_epoch_ms"))
            row["unit_before_cleanup"] = pick(obj.get("unit_before_cleanup"), ("ActiveState", "MainPID"))
            row["witness"] = pick(obj.get("witness"), ("http_status", "healthy"))
            row["local_boundaries"] = [{**pick(v, ("case", "status", "origin", "expected_reason")),
                "receipt": receipt(v.get("receipt")), "unit_after": pick(v.get("unit_after"), ("ActiveState",))}
                for v in obj.get("local_boundaries", []) if isinstance(v, dict)]
            audit = obj.get("local_guard_audit") or {}
            row["audit"] = pick(audit.get("audit") if isinstance(audit, dict) else None,
                ("valide", "seq", "ancre_externe_verifiee", "limite"))
            cleanup = obj.get("cleanup") or {}
            if not isinstance(cleanup, dict) or not isinstance(cleanup.get("steps", []), list):
                raise ValueError("invalid cleanup")
            row["cleanup"] = {"origin": cleanup.get("origin"), "steps": [pick(v, ("step", "status", "error_type"))
                for v in cleanup.get("steps", [])[:20]]}
        except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
            row = {k: row[k] for k in ("id", "modified_ms", "proof_path")}
            row.update(status="invalid", origin="unknown", case="unknown", started_ms=None, finished_ms=None,
                       error="Rapport invalide ou incomplet ; aucun résultat confirmé.")
        reports.append(row)
    reports.sort(key=lambda r: (r.get("started_ms") or r["modified_ms"], r["id"]), reverse=True)
    dates = [r.get("finished_ms") or r.get("started_ms") for r in reports]
    latest = max((d for d in dates if type(d) is int), default=None)
    return {**base, "status": "available" if reports else "not_run", "reports": reports,
            "latest_ms": latest, "omitted": max(0, len(candidates) - len(reports))}


def lire_acces_exterieur(racine: pathlib.Path) -> dict:
    """Résumé public d'un essai fixe ; aucune connexion, commande ou exclusion."""
    base = {"schema": "sawm-external-auth-validation/v1", "status": "not_run",
            "updated_at": None, "scope": "", "cases": [], "events": [],
            "correlations": [], "geography": [], "limits": [], "cloud": {}, "error": None}

    def liste(obj, nom, maximum):
        value = obj.get(nom, [])
        if not isinstance(value, list) or len(value) > maximum:
            raise ValueError("liste hors limites")
        return value

    def adresse(value, nullable=False):
        if nullable and value is None:
            return None
        _texte(value, "source_ip", 45)
        if "%" in value:
            raise ValueError("zone réseau non publique")
        ipaddress.ip_address(value)
        return value

    try:
        path = preuve_autorisee(ACCES_EXTERIEUR, pathlib.Path(racine))
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as file:
            info = os.fstat(file.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ACCES_EXTERIEUR:
                raise ValueError("rapport non régulier ou trop volumineux")
            raw = file.read(MAX_ACCES_EXTERIEUR + 1)
        if len(raw) > MAX_ACCES_EXTERIEUR:
            raise ValueError("rapport trop volumineux")
        obj = json.loads(raw)
        if not isinstance(obj, dict) or obj.get("schema") != base["schema"]:
            raise ValueError("contrat inconnu")
        _valider_telemetrie(obj)
        if obj.get("status") not in {"running", "passed", "failed"}:
            raise ValueError("statut inconnu")
        out = {**copy.deepcopy(base), "status": obj["status"], "scope": _texte(obj.get("scope", ""), "scope")}
        if obj.get("updated_at") is not None:
            out["updated_at"] = _texte(obj["updated_at"], "updated_at", 100)
        for case in liste(obj, "cases", 40):
            if not isinstance(case, dict):
                raise ValueError("cas invalide")
            checks, measurements = case.get("checks", {}), case.get("measurements", {})
            if not isinstance(checks, dict) or any(v is not None and type(v) is not bool for v in checks.values()) \
                    or not isinstance(measurements, dict):
                raise ValueError("mesures de cas invalides")
            out["cases"].append({"id": _id(case.get("id"), "case id"),
                "title": _texte(case.get("title"), "title", 1000),
                "status": _texte(case.get("status"), "case status", 100),
                "source_ip": adresse(case.get("source_ip"), nullable=True),
                "checks": checks, "measurements": measurements})
        for event in liste(obj, "events", 500):
            if not isinstance(event, dict) or event.get("applied_by") not in {"local_policy", "sawm", "operator", "none"}:
                raise ValueError("événement ou auteur invalide")
            until = event.get("ban_until_ms")
            username = event.get("username")
            out["events"].append({"timestamp_ms": _nombre(event.get("timestamp_ms"), "timestamp_ms", entier=True),
                "source_ip": adresse(event.get("source_ip")),
                "event": _texte(event.get("event"), "event", 100),
                "username": None if username is None else _texte(username, "username", 200),
                "reason": _texte(event.get("reason", ""), "reason", 2000),
                "ban_until_ms": None if until is None else _nombre(until, "ban_until_ms", entier=True),
                "applied_by": event["applied_by"]})
        for correlation in liste(obj, "correlations", 40):
            if not isinstance(correlation, dict) or correlation.get("same_actor_confirmed") is not False \
                    or correlation.get("confidence_label") != "hypothese_non_confirmee":
                raise ValueError("attribution d'identité non établie")
            out["correlations"].append({"source_ips": [adresse(ip) for ip in liste(correlation, "source_ips", 40)],
                "reason": _texte(correlation.get("reason"), "reason", 2000),
                "confidence_label": "hypothese_non_confirmee", "same_actor_confirmed": False})
        for geo in liste(obj, "geography", 100):
            if not isinstance(geo, dict) or geo.get("status") not in {"private_address", "unknown"} \
                    or geo.get("country") is not None or geo.get("source") is not None:
                raise ValueError("géographie non établie")
            ip = adresse(geo.get("source_ip"))
            if geo["status"] == "private_address" and not ipaddress.ip_address(ip).is_private:
                raise ValueError("adresse non privée")
            out["geography"].append({"source_ip": ip, "status": geo["status"], "country": None, "source": None})
        out["limits"] = [_texte(value, "limit") for value in liste(obj, "limits", 40)]
        cloud = obj.get("cloud", {})
        if not isinstance(cloud, dict):
            raise ValueError("résumé Cloud invalide")
        cloud_fields = {"status", "provider", "model", "decision_id", "action", "reason", "unknowns",
                        "job_ids", "recall_count", "odvl_available", "calls", "latency_ms", "error"}
        out["cloud"] = {key: value for key, value in cloud.items() if key in cloud_fields}
        return out
    except FileNotFoundError:
        return {**base, "error": "Validation non exécutée : rapport local absent."}
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        return {**base, "status": "invalid",
                "error": "Rapport d’accès invalide ou hors limites ; aucun résultat confirmé."}


class EtatSecurite:
    """Vue publique en lecture seule ; aucun accès à la clé privée.

    Vérification intégrale Ed25519 au plus une fois par dix secondes, hors du
    verrou des mesures. Une validité est celle de l'instant explicitement rendu.
    """
    def __init__(self, racine, *, public_key_path=None, horloge=time.time,
                 monotone=time.monotonic, cache_secondes=10):
        self.racine = pathlib.Path(racine)
        self.public_key_path = pathlib.Path(public_key_path or
            pathlib.Path.home()/'.sawm-labo/audit-ed25519.key.pub')
        self.horloge, self.monotone = horloge, monotone
        self.cache_secondes = cache_secondes
        self._audit_cache, self._audit_depuis = None, None
        self._verrou_audit = threading.Lock()

    def _battement(self):
        try:
            path = self.racine/'releves/veille/etat.json'
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as file:
                if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
                    raise ValueError('fichier non régulier')
                raw = file.read(16385)
            if len(raw) > 16384:
                raise ValueError('état trop volumineux')
            obj = json.loads(raw)
            if not isinstance(obj, dict) or obj.get('schema') != 'sawm-veille/v2':
                raise ValueError('contrat inconnu')
            ms = _nombre(obj.get('mur_epoch_ms'), 'horodatage', entier=True)
            age = self.horloge()*1000 - ms
            modes = {'observation', 'analyse_cloud', 'protection_autorisee',
                     'attente_manifeste', 'telemetrie_indisponible', 'arretee'}
            mode = obj.get('mode')
            if mode not in modes:
                raise ValueError('mode inconnu')
            out = {'mode': mode, 'age_ms': max(0, round(age)),
                   'battement_frais': 0 <= age < 15000,
                   'active': 0 <= age < 15000 and mode in {
                       'observation', 'analyse_cloud', 'protection_autorisee'},
                   'journal_signe_declare': obj.get('journal_signe') is True}
            for name in ('budget_analyses_par_heure', 'analyses_reservees_derniere_heure',
                         'analyses_en_attente', 'repli_cloud_secondes'):
                val = obj.get(name)
                out[name] = None if val is None else _nombre(val, name, maximum=100000, entier=True)
            out['analyse_en_cours'] = obj.get('analyse_en_cours') is True
            from controleur.defense_profondeur import project
            out['defense_profondeur'] = project(obj.get('defense_profondeur'), now_ms=self.horloge()*1000)
            out['erreur'] = None if out['active'] else 'Veille arrêtée, dégradée ou battement périmé'
            return out
        except (OSError, ValueError, TypeError, UnicodeError):
            return {'mode': 'indisponible', 'active': False, 'battement_frais': False,
                    'age_ms': None, 'erreur': 'État de veille absent ou invalide'}

    def _audit(self):
        with self._verrou_audit:
            now = self.monotone()
            if self._audit_cache is not None and now - self._audit_depuis < self.cache_secondes:
                return copy.deepcopy(self._audit_cache)
            out = {'valide': False, 'verifie_a_ms': round(self.horloge()*1000),
                   'cache_max_secondes': self.cache_secondes,
                   'copie_hors_invite': ('Aucune : journal et clé sur la VM Linux surveillée'
                                        if LOCAL_VM else 'Mac contrôleur, hors de la VM Linux'),
                   'coffre_immuable': False}
            try:
                path = self.racine/'releves/veille/audit.jsonl'
                # La vérification traite toute la chaîne, jamais un préfixe annoncé valide.
                if path.stat().st_size > 32 * 1024 * 1024:
                    raise ValueError('journal trop volumineux pour vérification interactive')
                spec = importlib.util.spec_from_file_location('sawm_dashboard_audit', ICI/'audit_signe.py')
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                result = module.verifier(path, public_key_path=self.public_key_path)
                out.update({k: result[k] for k in ('valide', 'algorithme', 'seq', 'key_id',
                    'journal_id', 'dernier_sha256', 'ancre_externe_verifiee', 'limite')})
                out['erreur'] = None
            except Exception:
                # Aucun contenu de journal, chemin de clé ni exception brute au navigateur.
                out['erreur'] = 'Preuves absentes, invalides ou vérification indisponible'
                out['limite'] = 'Aucune validité cryptographique confirmée'
            self._audit_cache, self._audit_depuis = out, self.monotone()
            return copy.deepcopy(out)

    def instantane(self):
        return {'schema': 'sawm-securite/v1', 'mur_epoch_ms': round(self.horloge()*1000),
                'veille': self._battement(), 'audit': self._audit()}


class Etat:
    def __init__(self, run_id: str, mode: str = "DIRECT", series: pathlib.Path | None = None, racine: pathlib.Path | None = None, max_stockage_telemetrie_o: int | None = None) -> None:
        self.verrou = threading.RLock()
        self.run_id = _id(run_id, "run_id")
        if mode not in {"DIRECT", "REJEU"}:
            raise ValueError("mode invalide")
        self.mode = mode
        self.racine = racine or RACINE
        self.series = series or SERIES
        self.securite = EtatSecurite(self.racine)
        self.series.mkdir(parents=True, exist_ok=True)
        limite = int(os.environ.get("LABO_MAX_SERIES_O", str(2 * 1024**3))) if max_stockage_telemetrie_o is None else max_stockage_telemetrie_o
        _nombre(limite, "limite de stockage télémétrie", maximum=1024**5, entier=True)
        self.retention = {"limite_series_o": limite, "taille_series_o": 0,
            "ecriture_telemetrie_suspendue": False, "echantillons_non_archives": 0,
            "politique": "Cap sur tous les JSONL des séries ; mesures directes conservées en mémoire. Aucune suppression. Métadonnées Cloud, incidents et décisions toujours journalisées."}
        self._stockage_scan_monotone = 0.0
        self._mesurer_stockage()
        self.demarre_ms = maintenant_ms()
        self.invite, self.hote, self.marqueurs, self.appels_cloud = [], [], [], []
        self.derniers_appels_moteurs = {}
        self.incidents, self.decisions = {}, {}
        self.index_cloud = []
        self.latences_cloud = []
        self.ids_cloud = set()
        self.dernier_invite_ms = None
        self.connexions_invite = self.deconnexions_invite = 0
        self.fichier = self.series / f"{run_id}.jsonl"
        self.reprise = {"journaux": 0, "lignes_invalides": 0, "telemetrie_ancienne_non_rechargee": 0}
        self.cumuls_cloud = {"appels": 0, "reussis": 0, "erreurs": 0, "inconnus": 0, "latences_fournies": 0, "latence_totale_ms": 0, "jetons_total": None, "jetons_entree": None, "jetons_sortie": None, "appels_avec_jetons": 0, "rejoues": 0, "premier_ms": None, "dernier_ms": None, "perimetre": "tous les journaux du laboratoire"}
        self.versions = self._versions()
        self._reprendre()

    @staticmethod
    def _versions() -> dict:
        def cmd(*a):
            try:
                r = subprocess.run(a, capture_output=True, text=True, timeout=3)
                return r.stdout.strip().splitlines()[0] if r.returncode == 0 and r.stdout.strip() else None
            except Exception:
                return None
        mac = sys.platform == "darwin" and not LOCAL_VM
        return {"collecteur": "2.0", "hote": cmd("uname", "-srm"),
                "utm": cmd("utmctl", "version") if mac else None,
                "qemu": cmd("qemu-system-aarch64", "--version") if mac else None,
                "placement_controleur": "vm-linux-locale" if LOCAL_VM else "hote-externe"}

    def _mesurer_stockage(self):
        total = 0
        for path in self.series.glob("*.jsonl"):
            st = path.lstat()
            if stat.S_ISREG(st.st_mode):
                total += st.st_size
        self.retention["taille_series_o"] = total
        self.retention["ecriture_telemetrie_suspendue"] |= total >= self.retention["limite_series_o"]
        self._stockage_scan_monotone = time.monotonic()

    def _reprendre(self):
        # Les fichiers restent intacts. Seule la dernière fenêtre brute est parsée
        # pour la télémétrie ; les métadonnées sont toutes validées et indexées.
        recentes = {genre: deque(maxlen=FENETRE) for genre in ("invite", "hote")}
        prefixes = {b'{"genre": "invite",': "invite", b'{"genre":"invite",': "invite",
                    b'{"genre": "hote",': "hote", b'{"genre":"hote",': "hote"}
        def integrer_ligne(ligne, position):
            try:
                e = json.loads(ligne)
                if not isinstance(e, dict):
                    raise ValueError("objet attendu")
                genre = e.pop("genre")
                if genre in {"cloud", "marqueur", "incident", "decision"}:
                    e = valider_evenement(genre, e)
                elif genre in {"invite", "hote"}:
                    _valider_telemetrie(e)
                else:
                    return
                self._integrer(genre, e, position)
            except (ValueError, TypeError, KeyError, UnicodeDecodeError, RecursionError):
                self.reprise["lignes_invalides"] += 1
        for fichier in sorted(self.series.glob("*.jsonl")):
            if fichier.is_symlink() or not fichier.is_file():
                continue
            self.reprise["journaux"] += 1
            with fichier.open("rb") as f:
                while True:
                    position = f.tell()
                    ligne = f.readline(MAX_LIGNE + 1)
                    if not ligne:
                        break
                    if len(ligne) > MAX_LIGNE:
                        while ligne and not ligne.endswith(b"\n"):
                            ligne = f.readline(MAX_LIGNE + 1)
                        self.reprise["lignes_invalides"] += 1
                        continue
                    genre = next((g for prefix, g in prefixes.items() if ligne.startswith(prefix)), None)
                    if genre:
                        if len(recentes[genre]) == FENETRE:
                            self.reprise["telemetrie_ancienne_non_rechargee"] += 1
                        recentes[genre].append((ligne, (fichier, position)))
                    else:
                        integrer_ligne(ligne, (fichier, position))
        for lignes in recentes.values():
            for ligne, position in lignes:
                integrer_ligne(ligne, position)

    def _integrer(self, genre, e, position=None):
        if genre in {"invite", "hote"}:
            liste = getattr(self, genre)
            liste.append(e)
            del liste[:-FENETRE]
            if genre == "invite":
                self.dernier_invite_ms = e.get("recu_ms")
        elif genre == "marqueur":
            self.marqueurs.append(e)
            del self.marqueurs[:-500]
        elif genre in {"incident", "decision"}:
            table = self.incidents if genre == "incident" else self.decisions
            table[e["id"]] = e
            while len(table) > 1000:
                del table[next(iter(table))]
        elif genre == "cloud":
            event_id = e.get("event_id")
            if event_id and event_id in self.ids_cloud:
                return
            if event_id:
                self.ids_cloud.add(event_id)
            engine=engine_for(e)
            if engine:
                previous=self.derniers_appels_moteurs.get(engine)
                if previous is None or e.get('mur_epoch_ms',0)>=previous.get('mur_epoch_ms',0):
                    self.derniers_appels_moteurs[engine]=dict(e)
            self.appels_cloud.append(e)
            del self.appels_cloud[:-100]
            self.index_cloud.append(position)
            c = self.cumuls_cloud
            c["appels"] += 1
            resultat, statut = e.get("resultat"), e.get("statut")
            if resultat == "ok" or (not resultat and statut is not None and 200 <= statut < 300):
                c["reussis"] += 1
            elif resultat or (statut is not None and statut >= 300):
                c["erreurs"] += 1
            else:
                c["inconnus"] += 1
            if e.get("ms") is not None:
                bisect.insort(self.latences_cloud, e["ms"])
                c["latences_fournies"] += 1
                c["latence_totale_ms"] += e["ms"]
            if any(e.get(k) is not None for k in ("jetons_total", "jetons_entree", "jetons_sortie")):
                c["appels_avec_jetons"] += 1
            for k in ("jetons_total", "jetons_entree", "jetons_sortie"):
                if e.get(k) is not None and not e.get("replayed"):
                    c[k] = (c[k] or 0) + e[k]
            if e.get("replayed"):
                c["rejoues"] += 1
            ms = e["mur_epoch_ms"]
            c["premier_ms"] = min(c["premier_ms"], ms) if c["premier_ms"] is not None else ms
            c["dernier_ms"] = max(c["dernier_ms"], ms) if c["dernier_ms"] is not None else ms

    def _ajouter(self, genre, e):
        with self.verrou:
            if genre == "cloud" and e.get("event_id") in self.ids_cloud:
                return
            if time.monotonic() - self._stockage_scan_monotone >= 30:
                self._mesurer_stockage()
            brut = (json.dumps({"genre": genre, **{k: v for k, v in e.items() if k != "genre"}}, ensure_ascii=False, allow_nan=False) + "\n").encode()
            if genre in {"invite", "hote"} and (
                self.retention["ecriture_telemetrie_suspendue"] or
                self.retention["taille_series_o"] + len(brut) + 1 > self.retention["limite_series_o"]):
                self.retention["ecriture_telemetrie_suspendue"] = True
                self.retention["echantillons_non_archives"] += 1
                self._integrer(genre, e)
                return
            # Une ligne incomplète après interruption ne doit pas absorber le prochain événement.
            with self.fichier.open("ab+") as f:
                f.seek(0, 2)
                supplement = 0
                if f.tell():
                    f.seek(-1, 2)
                    if f.read(1) != b"\n":
                        f.write(b"\n")
                        supplement = 1
                position = f.tell()
                f.write(brut)
                f.flush()
            self.retention["taille_series_o"] += len(brut) + supplement
            if self.retention["taille_series_o"] >= self.retention["limite_series_o"]:
                self.retention["ecriture_telemetrie_suspendue"] = True
            self._integrer(genre, e, (self.fichier, position))

    def ajouter_invite(self, e):
        if not isinstance(e, dict):
            raise ValueError("objet télémétrie attendu")
        _valider_telemetrie(e)
        self._ajouter("invite", {**e, "recu_ms": maintenant_ms()})

    def ajouter_hote(self, e):
        self._ajouter("hote", e)

    def ajouter_marqueur(self, e):
        self._ajouter("marqueur", valider_evenement("marqueur", e))

    def ajouter_appel_cloud(self, e):
        self._ajouter("cloud", valider_evenement("cloud", e))

    def ajouter_incident(self, e):
        self._ajouter("incident", valider_evenement("incident", e))

    def ajouter_decision(self, e):
        self._ajouter("decision", valider_evenement("decision", e))

    def historique_cloud(self, avant: int | None = None, limite: int = 50):
        with self.verrou:
            total = len(self.index_cloud)
            fin = total if avant is None else max(0, min(total, avant))
            debut = max(0, fin - max(1, min(100, limite)))
            references = self.index_cloud[debut:fin]
        appels = []
        for fichier, position in references:
            with fichier.open("rb") as f:
                f.seek(position)
                e = json.loads(f.readline(MAX_LIGNE))
                e.pop("genre", None)
                appels.append(e)
        return {"appels": appels, "total": total, "debut": debut, "fin": fin, "avant": debut if debut else None}

    def preuves(self):
        candidats = list((self.racine / "releves").glob("*")) + list((self.racine / "releves" / "rapports").glob("*"))
        resultat = []
        for p in sorted(candidats, key=lambda p: p.name, reverse=True):
            try:
                nom = p.relative_to(self.racine).as_posix()
                cible = preuve_autorisee(nom, self.racine)
                if not cible.is_file() or cible.stat().st_size > MAX_PREUVE:
                    continue
                resultat.append({"nom": p.name, "chemin": nom, "url": "/api/preuve?f=" + quote(nom, safe=""), "taille_o": p.stat().st_size, "modifie_ms": int(p.stat().st_mtime * 1000)})
            except (ValueError, OSError):
                continue
        return resultat[:200]

    def instantane(self, n=300):
        n = max(1, min(FENETRE, n))
        with self.verrou:
            maintenant = maintenant_ms()
            age = max(0, maintenant - self.dernier_invite_ms) if self.dernier_invite_ms is not None else None
            c = dict(self.cumuls_cloud)
            c["latence_moyenne_ms"] = c["latence_totale_ms"] / c["latences_fournies"] if c["latences_fournies"] else None
            c["latence_mediane_ms"] = statistics.median(self.latences_cloud) if self.latences_cloud else None
            resultat = {"run_id": self.run_id, "mode": self.mode, "demarre_ms": self.demarre_ms, "maintenant_ms": maintenant, "versions": self.versions, "telemetrie_invite": {"connectee": age is not None and age < PERIODE_ATTENDUE * 2500, "age_ms": age, "connexions": self.connexions_invite, "deconnexions": self.deconnexions_invite, "echantillons": len(self.invite)}, "invite": self.invite[-n:], "hote": self.hote[-n:], "marqueurs": self.marqueurs[-500:], "appels_cloud": self.appels_cloud[-50:], "cumuls_cloud": c, "incidents": list(self.incidents.values()), "decisions": list(self.decisions.values()), "reprise": self.reprise, "retention_telemetrie": self.retention, "fichier_series": str(self.fichier)}
            resultat = copy.deepcopy(resultat)
            derniers_moteurs=copy.deepcopy(self.derniers_appels_moteurs)
        # Projection de lecture : ne réécrit ni les preuves ni les dates historiques.
        for incident in resultat['incidents']:
            if not incident.get('motif_detection'):
                motif = motif_detection(incident)
                if motif:
                    incident['motif_detection'] = motif
        resultat['activite_agent']=resume_activite_agent(resultat,self.securite._battement(),
            derniers_moteurs,now_ms=maintenant)
        resultat["rapports"] = self.preuves()
        return resultat


def mesurer_hote(etat: Etat) -> dict:
    qemu = {"pid": None, "cpu_pct": None, "rss_o": None, "vm_uuid": VM_UUID}
    try:
        if LOCAL_VM or sys.platform != "darwin":
            raise RuntimeError("mesure hyperviseur non applicable")
        # Jamais « le premier QEMU » : le processus doit porter l'UUID exact du labo.
        lignes = subprocess.run(["ps", "-axo", "pid=,pcpu=,rss=,args="], capture_output=True, text=True, timeout=3).stdout.splitlines()
        candidats = []
        for ligne in lignes:
            p = ligne.strip().split(None, 3)
            if len(p) != 4 or "qemu-aarch64-softmmu" not in p[3]:
                continue
            args = shlex.split(p[3])
            if any(a == "-uuid" and i + 1 < len(args) and args[i + 1].upper() == VM_UUID for i, a in enumerate(args)):
                candidats.append({"pid": int(p[0]), "cpu_pct": float(p[1]), "rss_o": int(p[2]) * 1024, "vm_uuid": VM_UUID})
        if len(candidats) == 1:
            qemu = candidats[0]
    except Exception:
        pass
    controleur = {"cpu_pct": None, "rss_o": None}
    try:
        r = subprocess.run(["ps", "-o", "%cpu=,rss=", "-p", str(os.getpid())], capture_output=True, text=True, timeout=3).stdout.split()
        if len(r) >= 2:
            controleur = {"cpu_pct": float(r[0]), "rss_o": int(r[1]) * 1024}
    except Exception:
        pass
    disque = {"libre_o": None, "total_o": None}
    try:
        st = os.statvfs(str(RACINE))
        disque = {"libre_o": st.f_bavail * st.f_frsize, "total_o": st.f_blocks * st.f_frsize}
    except Exception:
        pass
    vm_statut = None
    try:
        if LOCAL_VM or sys.platform != "darwin":
            raise RuntimeError("UTM non applicable")
        r = subprocess.run(["utmctl", "status", VM_UUID], capture_output=True, text=True, timeout=3)
        vm_statut = r.stdout.strip() if r.returncode == 0 else None
    except Exception:
        pass
    return {"source": "hote", "mur_epoch_ms": maintenant_ms(), "monotone_ns": time.monotonic_ns(), "qemu": qemu, "controleur": controleur, "disque": disque, "vm_statut": vm_statut}


def fil_telemetrie(etat):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(ECOUTE_TELEMETRIE)
    srv.listen(4)
    # Une seule source invitée attendue ; connexion suivante après fin du flux.
    while True:
        conn, _ = srv.accept()
        with etat.verrou:
            etat.connexions_invite += 1
        _lire_flux(etat, conn)


def _lire_flux(etat, conn):
    reste = b""
    try:
        conn.settimeout(10)
        while True:
            bloc = conn.recv(65536)
            if not bloc:
                break
            reste += bloc
            while b"\n" in reste:
                ligne, _, reste = reste.partition(b"\n")
                if len(ligne) > MAX_LIGNE:
                    raise ValueError("ligne trop grande")
                if ligne.strip():
                    try:
                        etat.ajouter_invite(json.loads(ligne))
                    except (ValueError, TypeError, RecursionError):
                        pass
            if len(reste) > MAX_LIGNE:
                raise ValueError("ligne trop grande")
    except (OSError, ValueError):
        pass
    finally:
        with etat.verrou:
            etat.deconnexions_invite += 1
        conn.close()


def fil_hote(etat):
    prochaine = time.monotonic()
    while True:
        etat.ajouter_hote(mesurer_hote(etat))
        prochaine += PERIODE_ATTENDUE
        time.sleep(max(0.0, prochaine - time.monotonic()))


class Service(BaseHTTPRequestHandler):
    etat: Etat = None
    operateur = None  # Singleton injecté au démarrage, commandes bornées du labo.

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *a):
        pass

    def _envoyer(self, code, corps, type_mime):
        self.send_response(code)
        self.send_header("Content-Type", type_mime)
        self.send_header("Content-Length", str(len(corps)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" if urlsplit(self.path).path in {"/", "/index.html"} else "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:")
        self.end_headers()
        self.wfile.write(corps)

    def _json(self, code, objet):
        self._envoyer(code, json.dumps(objet, ensure_ascii=False, allow_nan=False).encode(), "application/json; charset=utf-8")

    def do_GET(self):
        url = urlsplit(self.path)
        q = parse_qs(url.query)
        try:
            if url.path == "/api/etat":
                self._json(200, self.etat.instantane(int(q.get("n", [300])[0])))
            elif url.path == "/api/securite":
                self._json(200, self.etat.securite.instantane())
            elif url.path == "/api/campagne-defense":
                if url.query:
                    raise ValueError("cette lecture n'accepte aucun paramètre")
                self._json(200, lire_campagne_defense(self.etat.racine))
            elif url.path == "/api/autonomie-profondeur":
                if url.query:
                    raise ValueError("cette lecture n’accepte aucun paramètre")
                self._json(200, lire_autonomie_profondeur(self.etat.racine))
            elif url.path == "/api/acces-exterieur":
                if url.query:
                    raise ValueError("cette lecture n'accepte aucun paramètre")
                self._json(200, lire_acces_exterieur(self.etat.racine))
            elif url.path == "/api/operateur":
                if self.operateur is None:
                    self._json(503, {"erreur": "console opérateur indisponible"})
                else:
                    self._json(200, self.operateur.etat())
            elif url.path == "/api/cloud":
                self._json(200, self.etat.historique_cloud(int(q["avant"][0]) if "avant" in q else None, int(q.get("limite", [50])[0])))
            elif url.path == "/api/preuve":
                p = preuve_autorisee(q.get("f", [""])[0], self.etat.racine)
                if not p.is_file() or p.stat().st_size > MAX_PREUVE:
                    self._json(404, {"erreur": "preuve absente ou trop grande"})
                else:
                    contenu = p.read_bytes()
                    if len(contenu) > MAX_PREUVE:
                        raise ValueError("preuve trop grande")
                    mime = mimetypes.guess_type(p.name)[0] or "text/plain"
                    self._envoyer(200, contenu, mime + ("; charset=utf-8" if mime.startswith("text/") else ""))
            elif url.path == "/api/modeles":
                from console_cto import FENETRES, MODELES
                self._json(200, {
                    "modeles": [{"cle": k, "libelle": v["libelle"]}
                                for k, v in MODELES.items()],
                    "fenetres": [{"cle": k, "libelle": v[0]}
                                 for k, v in FENETRES.items()]})
            elif url.path in {"/", "/index.html"}:
                self._envoyer(200, (ICI / "tableau.html").read_bytes(), "text/html; charset=utf-8")
            else:
                self._json(404, {"erreur": "inconnu"})
        except (ValueError, OSError):
            self._json(400, {"erreur": "paramètre invalide"})

    _pont_question = None
    _verrou_question = threading.Lock()

    def _question(self, corps):
        """Question du directeur technique, posée à la mémoire.

        Lecture seule : la réponse ne déclenche aucune action sur la VM et
        n'accorde aucun droit. Le rappel précède toujours la rédaction ; sans
        preuve sur la fenêtre, le modèle n'est même pas appelé.
        """
        import sys as _sys
        if str(RACINE) not in _sys.path:
            _sys.path.insert(0, str(RACINE))   # pour `connecteur`
        from console_cto import ConsoleErreur, MODELES, repondre
        from connecteur.pont_memoire import PontMemoire
        question = str(corps.get("question") or "").strip()[:2000]
        fenetre = str(corps.get("fenetre") or "jour")
        modele = corps.get("modele")
        consigne = ""
        if modele in MODELES:
            consigne = MODELES[modele]["consigne"]
            question = question or MODELES[modele]["question"]
        if not question:
            raise ValueError("question vide")
        with Service._verrou_question:
            if Service._pont_question is None:
                import uuid as _uuid
                Service._pont_question = PontMemoire(
                    campagne="cto" + _uuid.uuid4().hex[:9])
            pont = Service._pont_question
        try:
            return repondre(pont, question=question, fenetre=fenetre,
                            consigne=consigne)
        except ConsoleErreur as e:
            raise ValueError(str(e)) from None

    def _commander_operateur(self, corps):
        if self.operateur is None:
            raise OSError("console opérateur indisponible")
        return self.operateur.traite(corps)

    def do_POST(self):
        routes = {"/api/cloud": self.etat.ajouter_appel_cloud, "/api/marqueur": self.etat.ajouter_marqueur, "/api/incident": self.etat.ajouter_incident, "/api/decision": self.etat.ajouter_decision, "/api/operateur": self._commander_operateur, "/api/question": self._question}
        route = routes.get(self.path)
        if route is None:
            self._json(404, {"erreur": "inconnu"})
            return
        origine = self.headers.get("Origin")
        origines_locales = {f"http://127.0.0.1:{self.server.server_port}", f"http://localhost:{self.server.server_port}"}
        if (origine and origine not in origines_locales) or (self.path == "/api/operateur" and origine not in origines_locales):
            self._json(403, {"erreur": "origine interdite"})
            return
        if self.headers.get_content_type() != "application/json":
            self._json(415, {"erreur": "application/json requis"})
            return
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = -1
        if n < 1 or n > MAX_CORPS or self.headers.get("Transfer-Encoding"):
            self._json(413, {"erreur": "taille de corps invalide"})
            return
        try:
            brut = self.rfile.read(n)
            if len(brut) != n:
                raise ValueError("corps incomplet")
            resultat = route(json.loads(brut))
        except (ValueError, TypeError, UnicodeDecodeError, RecursionError) as e:
            code = getattr(e, "statut_http", 400)
            self._json(code if isinstance(code, int) and 400 <= code < 500 else 400, {"erreur": str(e)[:200]})
            return
        except OSError:
            self._json(503, {"erreur": "journal indisponible"})
            return
        self._json(200, resultat if isinstance(resultat, dict) else {"ok": True})


def main():
    if LOCAL_VM:
        if __package__:
            from .vm_labo import verifier_vm_locale
        else:
            from vm_labo import verifier_vm_locale
        verifier_vm_locale()
    if __package__:
        from .operateur import ControleOperateur
    else:
        from operateur import ControleOperateur
    run_id = os.environ.get("LABO_RUN") or time.strftime("run-%Y%m%dT%H%M%S")
    etat = Etat(run_id, os.environ.get("LABO_MODE", "DIRECT"))
    Service.etat = etat
    Service.operateur = ControleOperateur(racine=RACINE)
    threading.Thread(target=fil_telemetrie, args=(etat,), daemon=True).start()
    threading.Thread(target=fil_hote, args=(etat,), daemon=True).start()
    srv = ThreadingHTTPServer(ECOUTE_HTTP, Service)
    print(f"run_id       : {run_id}", flush=True)
    print(f"tableau      : http://{ECOUTE_HTTP[0]}:{ECOUTE_HTTP[1]}/", flush=True)
    print(f"series       : {etat.fichier}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
