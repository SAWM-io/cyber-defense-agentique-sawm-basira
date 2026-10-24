#!/usr/bin/env python3
"""Synthèse reproductible des journaux du laboratoire (bibliothèque standard).

Aucune VM, aucun appel Cloud, aucun secret : lecture des preuves locales seulement.
Exécution depuis n'importe quel dossier : python3 controleur/mesures_rapport.py
Le journal est lu jusqu'à sa taille au début de la lecture, même s'il continue
à croître. Les rapports incomplets sont signalés, pas assimilés à des résultats.
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import math
import os
import pathlib
import statistics
import tempfile

RACINE = pathlib.Path(__file__).resolve().parents[1]
VM_UUID = os.environ.get("SAWM_LABO_VM_UUID", "00000000-0000-0000-0000-000000000000").upper()
MAX_INTERVALLE_S = 5.0
MAX_LIGNE = 1024 * 1024


def nombre(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def chemin_public(p):
    try:
        return p.resolve().relative_to(RACINE).as_posix()
    except ValueError:
        return str(p.resolve())


def iso_ms(v):
    """Ne présume jamais le fuseau d'une date dépourvue d'offset."""
    if nombre(v):
        return float(v)
    if not isinstance(v, str):
        return None
    try:
        d = dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
        return d.timestamp() * 1000 if d.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def utc(v):
    if not nombre(v):
        return None
    return dt.datetime.fromtimestamp(v / 1000, dt.timezone.utc).isoformat()


def statistiques(valeurs):
    """P95 au rang supérieur ceil(0.95*n), médiane usuelle, sans interpolation."""
    v = sorted(x for x in valeurs if nombre(x))
    return {
        "n": len(v), "minimum": min(v) if v else None,
        "moyenne": statistics.fmean(v) if v else None,
        "mediane": statistics.median(v) if v else None,
        "p95": v[math.ceil(.95 * len(v)) - 1] if v else None,
        "maximum": max(v) if v else None,
    }


def lire_journal(p):
    evenements = []
    invalides = tronquees = trop_longues = 0
    compteurs = collections.Counter()
    sha = hashlib.sha256()
    with p.open("rb") as f:
        taille = os.fstat(f.fileno()).st_size
        restant = taille
        while restant:
            ligne = f.readline(min(MAX_LIGNE + 1, restant))
            if not ligne:
                break
            restant -= len(ligne)
            sha.update(ligne)
            if len(ligne) > MAX_LIGNE:
                while ligne and not ligne.endswith(b"\n") and restant:
                    ligne = f.readline(min(MAX_LIGNE + 1, restant))
                    restant -= len(ligne)
                    sha.update(ligne)
                trop_longues += 1
                continue
            if not ligne.endswith(b"\n"):
                tronquees += 1
                continue
            try:
                e = json.loads(ligne)
                if not isinstance(e, dict) or not isinstance(e.get("genre"), str):
                    raise ValueError("événement invalide")
            except (ValueError, UnicodeError, RecursionError):
                invalides += 1
                continue
            compteurs[e["genre"]] += 1
            # L'inventaire de sockets n'est pas nécessaire aux statistiques.
            if e["genre"] == "invite":
                e = {k: v for k, v in e.items() if k in {
                    "genre", "mur_epoch_ms", "recu_ms", "monotone_ns", "sequence",
                    "uptime_s", "cpu", "cpu_coeurs", "memoire", "disque", "reseau",
                    "tranches", "capteurs", "service_temoin",
                }}
            evenements.append(e)
    source = {"chemin": chemin_public(p), "octets_captures": taille - restant,
              "sha256": sha.hexdigest(), "lignes_par_genre": dict(compteurs),
              "lignes_invalides": invalides, "lignes_incompletes": tronquees,
              "lignes_trop_longues": trop_longues}
    return evenements, source


def dedupliquer_cloud(evenements):
    """L'event_id désigne une tentative réseau ; la corrélation ne déduplique pas les retries."""
    ids, resultat = {}, []
    doublons = conflits = sans_id = 0
    for e in evenements:
        if e.get("genre") != "cloud":
            continue
        eid = e.get("event_id")
        if isinstance(eid, str) and eid:
            if eid in ids:
                doublons += 1
                if e != ids[eid]:
                    conflits += 1
                continue
            ids[eid] = e
        else:
            sans_id += 1
        resultat.append(e)
    return resultat, {"doublons_event_id": doublons, "doublons_contradictoires": conflits,
                      "sans_event_id_non_dedupliques": sans_id}


def mesurer_cloud(appels, debut=None, fin=None):
    reussis = erreurs = inconnus = http = sse = transport = incomplets = 0
    tokens = {k: [] for k in ("jetons_total", "jetons_entree", "jetons_sortie")}
    statuts, types, resultats = collections.Counter(), collections.Counter(), collections.Counter()
    details = []
    hors_fenetre = sans_date = 0
    for e in appels:
        s, resultat = e.get("statut"), e.get("resultat")
        statut_http = nombre(s) and 100 <= s <= 599
        if resultat == "ok" or (not resultat and statut_http and 200 <= s < 300):
            reussis += 1
        elif resultat in {"http_error", "stream_error", "transport_error", "incomplete"} or (statut_http and s >= 300):
            erreurs += 1
        else:
            inconnus += 1
        http += int(resultat == "http_error" or (statut_http and s >= 400))
        sse += int(resultat == "stream_error")
        transport += int(resultat == "transport_error")
        incomplets += int(resultat == "incomplete")
        statuts[str(s) if statut_http else "sans_reponse_http"] += 1
        types[e.get("appel", "non_precise")] += 1
        resultats[resultat or "non_precise"] += 1
        if not e.get("replayed"):
            for k in tokens:
                if nombre(e.get(k)) and e[k] >= 0:
                    tokens[k].append(e[k])
        date = e.get("mur_epoch_ms")
        if not nombre(date):
            sans_date += 1
        elif debut is not None and fin is not None and not debut <= date <= fin:
            hors_fenetre += 1
        champs = ("event_id", "run_id", "appel", "methode", "statut", "resultat", "phase",
                  "tentative", "ms", "replayed", "terminal", "job_statut",
                  "jetons_total", "jetons_entree", "jetons_sortie")
        details.append({**{k: e[k] for k in champs if k in e}, "date_utc": utc(date)})
    return {
        "appels": len(appels), "reussis": reussis, "erreurs": erreurs, "inconnus": inconnus,
        "erreurs_http": http, "erreurs_sse": sse, "erreurs_transport": transport,
        "flux_incomplets": incomplets,
        "tentatives_numero_superieur_a_1": sum(nombre(e.get("tentative")) and e["tentative"] > 1 for e in appels),
        "recus_rejoues": sum(e.get("replayed") is True for e in appels),
        "statuts_http": dict(statuts), "par_appel": dict(types), "resultats": dict(resultats),
        "latence_ms": statistiques(e.get("ms") for e in appels),
        "usage_hors_replays": {k: {"somme_fournie": sum(v) if v else None, "appels_renseignes": len(v)} for k, v in tokens.items()},
        "appels_hors_fenetre_du_rapport": hors_fenetre,
        "appels_sans_date": sans_date,
        "tentatives": details,
    }


def dans_fenetre(e, cle, debut, fin):
    v = e.get(cle)
    return nombre(v) and (debut is None or debut <= v) and (fin is None or v <= fin)


def horloges(invite):
    differences = [e["recu_ms"] - e["mur_epoch_ms"] for e in invite
                   if nombre(e.get("recu_ms")) and nombre(e.get("mur_epoch_ms"))]
    sauts = 0
    for a, b in zip(invite, invite[1:]):
        if all(nombre(e.get(k)) for e in (a, b) for k in ("mur_epoch_ms", "monotone_ns")):
            dm = (b["monotone_ns"] - a["monotone_ns"]) / 1e6
            if 0 < dm <= MAX_INTERVALLE_S * 1000 and abs(b["mur_epoch_ms"] - a["mur_epoch_ms"] - dm) > 1000:
                sauts += 1
    return {"reception_moins_horloge_invitee_ms": statistiques(differences),
            "ecarts_absolus_superieurs_a_2500ms": sum(abs(d) > 2500 for d in differences),
            "ecarts_negatifs": sum(d < 0 for d in differences),
            "sauts_horloge_murale_superieurs_a_1s": sauts,
            "interpretation": "Écart observé incluant horloge et transport ; ce n'est pas une estimation du seul réseau. Aucune correction implicite des dates invitées."}


def intervalles(invite):
    valides, exclus = [], collections.Counter()
    for a, b in zip(invite, invite[1:]):
        if not all(nombre(e.get("monotone_ns")) for e in (a, b)):
            exclus["horloge_monotone_absente"] += 1
            continue
        duree = (b["monotone_ns"] - a["monotone_ns"]) / 1e9
        if duree <= 0 or (nombre(a.get("sequence")) and nombre(b.get("sequence")) and b["sequence"] <= a["sequence"]):
            exclus["redemarrage_ou_ordre_invalide"] += 1
        elif duree > MAX_INTERVALLE_S:
            exclus["lacune_superieure_a_5s"] += 1
        else:
            valides.append((a, b, duree))
    return valides, dict(exclus)


def derivee_compteur(paires, acces, facteur_pct=None):
    variations, taux, durees = [], [], []
    absents = resets = 0
    for a, b, duree in paires:
        va, vb = acces(a), acces(b)
        if not nombre(va) or not nombre(vb):
            absents += 1
        elif vb < va:
            resets += 1
        else:
            variations.append(vb - va)
            taux.append((vb - va) / duree)
            durees.append(duree)
    total_duree = sum(durees)
    return {"delta_cumule": sum(variations) if variations else None,
            "duree_mesuree_s": total_duree if durees else None,
            "taux_par_seconde": statistiques(taux),
            "cpu_pct_un_coeur": statistiques(t * facteur_pct for t in taux) if facteur_pct is not None else None,
            "cpu_pct_moyen_pondere": sum(variations) / total_duree * facteur_pct if facteur_pct is not None and total_duree else None,
            "intervalles_valides": len(variations), "compteurs_absents": absents,
            "reinitialisations_compteur": resets}


def sonder_service(sondes, origine):
    connues = [e for e in sondes if isinstance(e.get("disponible"), bool)]
    ok = sum(e["disponible"] for e in connues)
    return {"origine": origine, "sondes": len(sondes), "connues": len(connues),
            "disponibles": ok, "indisponibles": len(connues) - ok,
            "non_renseignees": len(sondes) - len(connues),
            "disponibilite_pct_sondes_connues": 100 * ok / len(connues) if connues else None,
            "latence_ms": statistiques(e.get("latence_ms") for e in sondes),
            "interpretation": "Proportion des sondes observées, pas une garantie de disponibilité entre les sondes."}


def mesurer_ressources(evenements, debut=None, fin=None):
    invite = sorted((e for e in evenements if e.get("genre") == "invite" and dans_fenetre(e, "recu_ms", debut, fin)), key=lambda e: e["recu_ms"])
    hote = sorted((e for e in evenements if e.get("genre") == "hote" and dans_fenetre(e, "mur_epoch_ms", debut, fin)), key=lambda e: e["mur_epoch_ms"])
    paires, exclus = intervalles(invite)
    roles = {}
    for role in ("defense", "charge", "legitime"):
        def tranche(e, cle, r=role):
            return (e.get("tranches") or {}).get(r, {}).get(cle)
        cpu = derivee_compteur(paires, lambda e: tranche(e, "cpu_usage_usec"), 1 / 10000)
        cpu["cpu_cumule_s"] = cpu["delta_cumule"] / 1e6 if cpu["delta_cumule"] is not None else None
        roles[role] = {"cpu": cpu,
                       "memoire_o": statistiques(tranche(e, "memoire_o") for e in invite),
                       "pids": statistiques(tranche(e, "pids") for e in invite)}
    occupes, poids = [], []
    for a, b, duree in paires:
        ca, cb = a.get("cpu") or {}, b.get("cpu") or {}
        if not all(nombre(c.get(k)) for c in (ca, cb) for k in ("total_jiffies", "oisif_jiffies")):
            continue
        total, idle = cb["total_jiffies"] - ca["total_jiffies"], cb["oisif_jiffies"] - ca["oisif_jiffies"]
        if total > 0 and 0 <= idle <= total:
            occupes.append(100 * (1 - idle / total))
            poids.append(duree)
    qemu = [e for e in hote if (e.get("qemu") or {}).get("vm_uuid") == VM_UUID]
    invites_sans_reception = sum(e.get("genre") == "invite" and not nombre(e.get("recu_ms")) for e in evenements)
    interfaces = sorted({i for e in invite for i in (e.get("reseau") or {})})
    return {
        "echantillons_invite": len(invite), "echantillons_hote": len(hote),
        "invite_sans_recu_ms_exclus_du_journal": invites_sans_reception,
        "premiere_reception_invite_utc": utc(invite[0]["recu_ms"]) if invite else None,
        "derniere_reception_invite_utc": utc(invite[-1]["recu_ms"]) if invite else None,
        "intervalles_invite_exclus": exclus, "horloges": horloges(invite),
        "invite": {
            "cpu_occupe_pct_machine": statistiques(occupes),
            "cpu_occupe_pct_machine_moyen_pondere": sum(x * p for x, p in zip(occupes, poids)) / sum(poids) if poids else None,
            "cpu_coeurs": statistiques(e.get("cpu_coeurs") for e in invite),
            "memoire_utilisee_o": statistiques((e.get("memoire") or {}).get("utilisee_o") for e in invite),
            "disque_libre_o": statistiques((e.get("disque") or {}).get("libre_o") for e in invite),
            "disque_lecture_o": derivee_compteur(paires, lambda e: (e.get("disque") or {}).get("lus_o")),
            "disque_ecriture_o": derivee_compteur(paires, lambda e: (e.get("disque") or {}).get("ecrits_o")),
            "reseau": {i: {k: derivee_compteur(paires, lambda e, interface=i, cle=k: (e.get("reseau") or {}).get(interface, {}).get(cle)) for k in ("emis_o", "recus_o")} for i in interfaces},
            "roles": roles,
        },
        "hote": {
            "qemu_uuid": VM_UUID, "qemu_echantillons_uuid_verifie": len(qemu),
            "qemu_echantillons_non_attribuables": len(hote) - len(qemu),
            "qemu_cpu_pct_ps": statistiques(e["qemu"].get("cpu_pct") for e in qemu),
            "qemu_rss_o": statistiques(e["qemu"].get("rss_o") for e in qemu),
            "controleur_cpu_pct_ps": statistiques((e.get("controleur") or {}).get("cpu_pct") for e in hote),
            "controleur_rss_o": statistiques((e.get("controleur") or {}).get("rss_o") for e in hote),
            "cpu_ps_interpretation": "Valeur %CPU rapportée par ps ; sa fenêtre de moyenne dépend de ps/macOS, ce n'est pas une dérivée du compteur invité.",
        },
        "service_temoin_telemetrie": sonder_service([e.get("service_temoin") or {} for e in invite], "télémétrie périodique invitée"),
    }


def mesures_experience(rapport, evenements, appels):
    debut, fin = iso_ms(rapport.get("debut")), iso_ms(rapport.get("fin"))
    valide = debut is not None and fin is not None and fin >= debut
    run = rapport.get("run_id")
    cloud = [e for e in appels if e.get("run_id") == run] if isinstance(run, str) else []
    sondes, etapes = [], []
    for etape in rapport.get("etapes", []):
        snap = etape.get("snapshot") or {}
        temoin = snap.get("temoin") or {}
        if temoin:
            code = temoin.get("code")
            sondes.append({"disponible": 200 <= code < 300 if nombre(code) else None, "latence_ms": temoin.get("ms")})
        flux = (snap.get("recepteur") or {}).get("flux") or {}
        etapes.append({"phase": etape.get("phase"), "horloge": "invitée, non convertie en horloge hôte",
                       "mur_epoch_ms_invite": snap.get("mur_epoch_ms"),
                       "flux": [{k: f.get(k) for k in ("source_id", "run_id", "annonces", "recus", "etat", "debut_ms", "dernier_ms", "fin_ms")} for f in flux.values() if f.get("run_id") == run]})
    return {
        "run_id": run, "type": rapport.get("type"), "succes_mesure_declare": rapport.get("succes_mesure"),
        "mandat_autorise": rapport.get("mandat_autorise"),
        "fenetre": {"valide": valide, "debut_utc": utc(debut), "fin_utc": utc(fin),
                    "debut_epoch_ms_hote": debut, "fin_epoch_ms_hote": fin,
                    "duree_s": (fin - debut) / 1000 if valide else None,
                    "attribution_invite": "recu_ms du collecteur, jamais mur_epoch_ms invité",
                    "attribution_hote": "mur_epoch_ms hôte",
                    "attribution_cloud": "run_id exact ; appels hors fenêtre signalés séparément"},
        "cloud": mesurer_cloud(cloud, debut, fin),
        "ressources": mesurer_ressources(evenements, debut, fin) if valide else None,
        "service_temoin_rapport": sonder_service(sondes, "sondes des étapes du rapport, comptées séparément de la télémétrie"),
        "mesures_rapport": rapport.get("mesures"),
        "volume_annonce_o": rapport.get("volume_annonce"),
        "mode_donnees": rapport.get("mode_donnees"),
        "etapes": etapes,
    }


def extraire(journal, dossier_rapports):
    evenements, source = lire_journal(journal)
    appels, dedup = dedupliquer_cloud(evenements)
    experiences, rapports_ignores = [], []
    for p in sorted(dossier_rapports.glob("experience*.json")):
        try:
            brut = p.read_bytes()
            rapport = json.loads(brut)
            if not isinstance(rapport, dict) or not isinstance(rapport.get("run_id"), str):
                raise ValueError("rapport sans run_id")
            resume = mesures_experience(rapport, evenements, appels)
            resume["source"] = {"chemin": chemin_public(p), "sha256": hashlib.sha256(brut).hexdigest()}
            experiences.append(resume)
        except (ValueError, OSError, TypeError, AttributeError):
            rapports_ignores.append({"chemin": chemin_public(p), "raison": "rapport illisible, incomplet ou structure invalide"})
    runs = {e["run_id"] for e in experiences}
    return {
        "schema": "sawm-lab-mesures/v1", "genere_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source_journal": source, "rapports_ignores": rapports_ignores,
        "methodologie": {
            "perimetre": "Journal capturé et rapports présents à l'exécution ; relancer après la campagne pour une synthèse finale.",
            "cloud": "Uniquement les événements genre=cloud du journal ; ni nombre d'analyses ni résumés SSE additionnés. Une tentative réseau = un event_id.",
            "usage": "Sommes des valeurs fournies, hors reçus replayed=true. Valeur absente = null ; aucune estimation ni assimilation automatique au coût facturé.",
            "cpu_invite": "Deltas des compteurs cgroup / deltas monotone_ns invité. 100 % = un cœur. Aucun intervalle extrapolé hors fenêtre ; trous >5 s, redémarrages et compteurs réinitialisés exclus.",
            "fenetres": "Bornes inclusives issues de debut/fin ISO avec fuseau du rapport. Télémétrie attribuée par réception hôte ; les temps muraux invités ne servent jamais à ce filtrage.",
            "latence": "Médiane usuelle ; p95 au rang ceil(0.95*n), sans interpolation. Toutes les tentatives disposant d'une latence, y compris échecs.",
            "limites": "Les taux moyens CPU portent sur les intervalles réellement mesurés. Les jauges RAM et %CPU ps sont des statistiques de sondes. Pas d'affirmation sur les périodes non observées.",
        },
        "global": {"cloud": {**mesurer_cloud(appels), **dedup},
                   "ressources": mesurer_ressources(evenements),
                   "cloud_sans_rapport_de_run": sum(e.get("run_id") not in runs for e in appels)},
        "experiences": experiences,
    }


def ecrire_atomique(sortie, objet):
    sortie.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=sortie.parent, prefix=".mesures-", suffix=".tmp", delete=False) as f:
        temporaire = pathlib.Path(f.name)
        try:
            json.dump(objet, f, ensure_ascii=False, indent=2, allow_nan=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        except Exception:
            temporaire.unlink(missing_ok=True)
            raise
    os.replace(temporaire, sortie)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal", type=pathlib.Path, default=RACINE / "releves/series/validation-20260922.jsonl")
    parser.add_argument("--rapports", type=pathlib.Path, default=RACINE / "releves/rapports")
    parser.add_argument("--sortie", type=pathlib.Path, default=RACINE / "releves/rapports/validation-mesures.json")
    args = parser.parse_args(argv)
    resultat = extraire(args.journal, args.rapports)
    ecrire_atomique(args.sortie, resultat)
    c = resultat["global"]["cloud"]
    print(json.dumps({"sortie": chemin_public(args.sortie), "experiences": len(resultat["experiences"]),
                      "appels_cloud": c["appels"], "erreurs_cloud": c["erreurs"],
                      "doublons_event_id": c["doublons_event_id"], "latence_cloud_ms": c["latence_ms"],
                      "usage_hors_replays": c["usage_hors_replays"],
                      "par_run": [{"run_id": e["run_id"], "fenetre_valide": e["fenetre"]["valide"],
                                   "duree_s": e["fenetre"]["duree_s"], "appels": e["cloud"]["appels"],
                                   "echantillons_invite": e["ressources"]["echantillons_invite"] if e["ressources"] else None} for e in resultat["experiences"]]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
