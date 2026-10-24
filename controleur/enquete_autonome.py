"""Enquête SAWM bornée : observations typées, aucune action système exécutée.

Les décisions passent toutes par validation.decision_cloud (dépôt, TSST,
ODVL, même API SAWM). Seuls quatre outils de lecture sont délégués au callback.
Une décision terminale revient à l'appelant, qui doit encore appliquer son
propre contrôle de droits. Un budget épuisé produit un refus sans proposition.
"""
from __future__ import annotations

import copy
import dataclasses
import json
import math
import queue
import re
import threading
import time
import uuid

from connecteur.contrat import (ACTIONS_INSPECTION, ACTIONS_RESTRICTIVES,
                                PropositionInvalide, lire_proposition)
from connecteur.tour_sawm import Decision
from controleur import validation

MAX_STEPS = 3
MAX_TOTAL_SECONDS = 120.0
MAX_JSON_BYTES = 65536
_RESOURCE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")


class _Deadline(Exception):
    pass


def _json_copy(value, *, maximum=MAX_JSON_BYTES):
    """Valide et détache une observation JSON bornée, sans conversion en commande."""
    def check(item, depth=0):
        if depth > 12:
            raise ValueError("observation trop profonde")
        if isinstance(item, dict):
            if len(item) > 256 or any(not isinstance(k, str) or len(k) > 200 for k in item):
                raise ValueError("objet observation invalide")
            for child in item.values():
                check(child, depth + 1)
        elif isinstance(item, list):
            if len(item) > 1000:
                raise ValueError("liste observation trop grande")
            for child in item:
                check(child, depth + 1)
        elif isinstance(item, str):
            if len(item) > maximum:
                raise ValueError("texte observation trop grand")
        elif item is not None and not isinstance(item, bool):
            if not isinstance(item, (int, float)) or not math.isfinite(item):
                raise ValueError("valeur observation non JSON")
    check(value)
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False)
    if len(raw.encode("utf-8")) > maximum:
        raise ValueError("observation trop volumineuse")
    return json.loads(raw)


def _bounded_call(fn, deadline):
    """Retourne avant l'échéance ; une lecture tardive ne peut lancer la suite.

Le thread daemon ne peut pas interrompre un transport tiers déjà engagé. Sa
réponse est abandonnée à l'échéance, et aucun outil suivant n'est déclenché.
"""
    if time.monotonic() >= deadline:
        raise _Deadline()
    result = queue.Queue(maxsize=1)

    def work():
        try:
            if time.monotonic() >= deadline:
                raise _Deadline()
            result.put((True, fn()))
        except Exception as error:
            result.put((False, error))

    threading.Thread(target=work, daemon=True, name="sawm-enquete-lecture").start()
    try:
        ok, value = result.get(timeout=max(0, deadline - time.monotonic()))
    except queue.Empty:
        raise _Deadline() from None
    if time.monotonic() >= deadline:
        raise _Deadline()
    if not ok:
        raise value
    return value


def _refusal(last, reason):
    if last is not None:
        return dataclasses.replace(last, proposition=None, refus=reason, texte="")
    return Decision(
        decision_id="enquete-refus-" + uuid.uuid4().hex[:16], turn_id="", session_id="",
        proposition=None, refus=reason, texte="", ordre_evenements=(), latence_ms=0,
        rejoue=False, memoire_sawm=None, usage=None, job_memoire=None,
    )


def _public_cloud(raw):
    """Conserve les références de preuves, jamais le texte brut ou des pensées."""
    if not isinstance(raw, dict):
        return {}
    jobs = (raw.get("depot") or {}).get("jobs", [])
    odvl = raw.get("odvl") or {}
    return {
        "job_ids": [str(j["job_id"])[:160] for j in jobs[:20]
                    if isinstance(j, dict) and j.get("job_id") is not None],
        "recall_count": raw.get("preuves_utilisees"),
        "odvl_available": bool(odvl.get("ranking")),
    }


def _public_pipeline(raw):
    """Reçus publics du dernier tour, compatibles avec le rapport de campagne."""
    if not isinstance(raw, dict):
        return {"depot": {"jobs": []}, "preuves_utilisees": 0,
                "odvl": {"available": False, "ranking": []}}
    jobs = (raw.get("depot") or {}).get("jobs", [])
    odvl = raw.get("odvl") or {}
    return _json_copy({
        "depot": {"jobs": [{k: job[k] for k in ("job_id", "statut") if k in job}
                            for job in jobs[:20] if isinstance(job, dict)]},
        "preuves_utilisees": raw.get("preuves_utilisees", 0),
        "odvl": {"available": bool(odvl.get("ranking")),
                 "ranking": [{k: row[k] for k in ("candidate_id", "rank", "score") if k in row}
                             for row in odvl.get("ranking", [])[:100] if isinstance(row, dict)]},
    })


def enqueter(pont, faits, run, resources, *, politique_locale, inspecter_fn,
             max_steps=3, on_step=None, before_turn=None, dispositions=None):
    """Au plus trois inspections puis une quatrième décision, sous 120 secondes.

``inspecter_fn(action, unit, contexte={"run_id": run})`` reçoit exclusivement
une action d'inspection reconnue et une cible de ``resources``. Les résultats
reviennent au modèle dans ``OUTILS_NONFIABLES``, jamais comme politique locale.
``on_step`` reçoit une copie de chaque étape publique achevée.
``before_turn(index)`` réserve le budget Cloud avant chaque tour (zéro inclus) ;
un retour False arrête l'enquête sans nouvel appel au modèle.
``dispositions`` est un instantané interne détaché au début de l'enquête :
les observations d'outils ne peuvent ni le remplacer ni modifier le mandat.
"""
    if type(max_steps) is not int or not 0 <= max_steps <= MAX_STEPS:
        raise ValueError("max_steps doit être compris entre 0 et 3")
    if not isinstance(run, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,159}", run):
        raise ValueError("run invalide")
    if not isinstance(faits, list) or not isinstance(resources, (list, tuple, set, frozenset)):
        raise ValueError("faits et ressources doivent être des collections explicites")
    allowed = tuple(resources)
    if len(allowed) > 128 or any(not isinstance(x, str) or not _RESOURCE.fullmatch(x) for x in allowed):
        raise ValueError("ressources invalides")
    if (not callable(inspecter_fn) or (on_step is not None and not callable(on_step))
            or (before_turn is not None and not callable(before_turn))):
        raise ValueError("callback invalide")
    observed = _json_copy(faits, maximum=2 * MAX_JSON_BYTES)
    policy = _json_copy(politique_locale)
    if dispositions is not None and not isinstance(dispositions, dict):
        raise ValueError("dispositions doivent être un instantané JSON")
    internal_state = _json_copy(dispositions)
    started = time.monotonic()
    deadline = started + MAX_TOTAL_SECONDS
    trace = {"schema": "sawm-enquete/v1", "run_id": run, "status": "running",
             "max_steps": max_steps, "max_seconds": MAX_TOTAL_SECONDS, "steps": [],
             "tools_used": 0, "cloud_rounds": 0, "refusal": None}
    if internal_state is not None:
        trace["dispositions"] = copy.deepcopy(internal_state)
    trace.update(_public_pipeline(None))
    last = None
    # Un seul contexte historique, lié à cet incident. Les mesures d'outils
    # continuent d'être relues ; elles ne remplacent jamais le mandat.
    memory_context = None
    pending_step = None
    phase = "cloud"

    def finish(decision, status):
        trace.update(status=status, refusal=decision.refus,
                     elapsed_ms=round((time.monotonic() - started) * 1000, 1))
        public = copy.deepcopy(trace)
        public["enquete"] = {k: copy.deepcopy(v) for k, v in trace.items()
                             if k not in {"depot", "preuves_utilisees", "odvl"}}
        public["enquete"].update(steps_used=trace["tools_used"],
                                 budget_exhausted=status in {"budget_exhausted", "timeout"})
        return decision, public

    def publish(step):
        nonlocal pending_step
        trace["steps"].append(copy.deepcopy(step))
        pending_step = None
        if on_step is not None:
            _bounded_call(lambda: on_step(copy.deepcopy(step)), deadline)

    try:
        for index in range(max_steps + 1):
            pending_step = None
            if before_turn is not None:
                phase = "budget_cloud"
                permitted = _bounded_call(lambda: before_turn(index), deadline)
                if type(permitted) is not bool:
                    raise ValueError("réservation Cloud doit rendre un booléen")
                if not permitted:
                    step = {"step": index + 1, "decision_id": None, "action": None,
                            "unit": None, "reason": "budget_cloud_epuise", "status": "refused",
                            "cloud": {}, "tool_result": None}
                    phase = "publication"
                    publish(step)
                    return finish(_refusal(last, "enquete:budget_cloud_epuise"), "budget_exhausted")
            phase = "cloud"
            # Les copies empêchent tout callback de modifier le mandat du tour suivant.
            round_facts, round_policy = copy.deepcopy(observed), copy.deepcopy(policy)
            round_dispositions = copy.deepcopy(internal_state)
            trace["cloud_rounds"] += 1
            decision, cloud = _bounded_call(lambda: validation.decision_cloud(
                pont, round_facts, run, list(allowed), politique_locale=round_policy,
                enquete=True, enquete_budget=max_steps - index,
                dispositions=round_dispositions,
                memory_context=copy.deepcopy(memory_context)), deadline)
            if not isinstance(decision, Decision):
                raise ValueError("réponse Cloud hors contrat")
            last = decision
            if isinstance(cloud, dict) and cloud.get("memory_context") is not None:
                memory_context = copy.deepcopy(cloud["memory_context"])
            trace.update(_public_pipeline(cloud))
            prop = decision.proposition
            step = {"step": index + 1, "decision_id": decision.decision_id,
                    "action": prop.action if prop else None, "unit": prop.cible if prop else None,
                    "reason": prop.justification if prop else decision.refus,
                    "unknowns": list(prop.inconnues) if prop else [],
                    "confidence_uncalibrated": prop.confiance if prop else None,
                    "memory_reused": cloud.get("memory_reused", False),
                    "timings_ms": copy.deepcopy(cloud.get("timings_ms", {})),
                    "cloud": _public_cloud(cloud), "tool_result": None}
            pending_step = step
            if not decision.executable:
                step["status"] = "refused"
                phase = "publication"
                publish(step)
                return finish(decision, "refused")
            try:
                lire_proposition(json.dumps({"action": prop.action, "cible": prop.cible,
                    "justification": prop.justification, "confiance": prop.confiance,
                    "souvenirs_cites": prop.souvenirs_cites, "inconnues": prop.inconnues}),
                    cibles_autorisees=set(allowed))
                if prop.cible is not None and prop.cible not in allowed:
                    raise PropositionInvalide("cible_hors_manifeste")
                if policy is not None and prop.action in ACTIONS_RESTRICTIVES | {"restaurer-fixtures"}:
                    delegated = policy.get("actions_automatiques") if type(policy) is dict else None
                    if (type(delegated) is not list or any(type(action) is not str for action in delegated)
                            or prop.action not in delegated):
                        raise PropositionInvalide("action_hors_mandat")
            except PropositionInvalide as error:
                step.update(status="refused", refusal=error.motif)
                phase = "publication"
                publish(step)
                return finish(_refusal(last, "enquete:" + error.motif), "refused")
            if prop.action not in ACTIONS_INSPECTION:
                step["status"] = "terminal"
                phase = "publication"
                publish(step)
                return finish(decision, "terminal")
            if index >= max_steps:
                step.update(status="refused", refusal="budget_outils_epuise")
                phase = "publication"
                publish(step)
                return finish(_refusal(last, "enquete:budget_outils_epuise"), "budget_exhausted")
            phase = "inspection"
            result = _bounded_call(lambda: inspecter_fn(prop.action, prop.cible,
                                   contexte={"run_id": run}), deadline)
            result = _json_copy(result)
            evidence = {"schema": "sawm-inspection/v1", "run_id": run,
                        "action": prop.action, "unit": prop.cible, "result": result}
            observed.append({"OUTILS_NONFIABLES": evidence})
            trace["tools_used"] += 1
            step.update(status="inspected", tool_result=evidence)
            phase = "publication"
            publish(step)
    except _Deadline:
        if pending_step is not None:
            trace["steps"].append({**pending_step, "status": "timeout"})
        trace.update(timeout_phase=phase, late_result_ignored=True,
                     in_flight_read_may_finish_later=True)
        return finish(_refusal(last, "enquete:budget_temps_epuise"), "timeout")
    except Exception as error:
        if pending_step is not None:
            failed_step = {**pending_step, "status": "error", "error_type": type(error).__name__}
            trace["steps"].append(copy.deepcopy(failed_step))
            if on_step is not None:
                try:
                    _bounded_call(lambda: on_step(copy.deepcopy(failed_step)), deadline)
                except Exception:
                    pass
        # Pas d'exception brute : elle pourrait contenir un secret de transport.
        trace.update(error_phase=phase, error_type=type(error).__name__)
        return finish(_refusal(last, "enquete:" + phase + "_echoue:" + type(error).__name__), "error")
