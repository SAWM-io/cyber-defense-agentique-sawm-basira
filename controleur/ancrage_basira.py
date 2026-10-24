#!/usr/bin/env python3
"""Ancrage de l'approbation de référence dans Basira — et ce qu'il prouve.

La procédure de reprise postule un adversaire qui a la main sur l'hôte. Une
approbation posée dans un fichier du contrôleur ne vaut donc rien : il la
réécrit. Un ancrage utile doit résister à CET adversaire-là.

**Ce que Basira apporte, précisément.** L'adversaire détient aussi la clé de
service : il peut ÉCRIRE dans l'espace. Basira n'est donc pas un coffre
inviolable, et il ne faut pas le vendre comme tel. Ce qu'il ne peut pas faire,
et qui est mesuré :

* `known_at_ms` est **assigné par le serveur** et ne peut pas être fourni par
  le client (vérifié contre la production le 2026-09-22, et documenté verbatim
  dans le SDK public). L'adversaire ne peut donc pas antidater son approbation ;
* un dépôt projeté ne s'efface pas depuis la surface publique de données : il
  peut ajouter, pas retrancher.

D'où la propriété réellement démontrable :

    un rappel TSST avec coupure sur le TEMPS DE TRANSACTION, fixée avant la
    fenêtre d'incident, rend l'approbation d'origine et exclut toute
    approbation postérieure.

Et le corollaire, qui est un signal et non un détail : si l'on trouve une
seconde approbation de la même référence avec une empreinte différente, la
question n'est plus « laquelle est bonne » mais « qui a déposé la seconde ».
Le module refuse alors de trancher, et le dit.

**Ce que cet ancrage ne prouve pas.** Si l'incident a commencé avant la
coupure choisie, l'adversaire a pu déposer son approbation avant elle. La
coupure doit venir d'une connaissance indépendante du moment où le système
était sain — elle n'est jamais « maintenant moins une heure » par défaut, et
ce module refuse de la deviner.

**Renforcement disponible, non encore posé.** Un principal distinct pour les
approbations, avec écriture réservée à une clé que le contrôleur ne détient
pas et lecture seule pour la clé d'exécution, retirerait à l'adversaire la
capacité d'écrire une approbation concurrente. Les grants d'entité de Basira
le permettent — mesuré : `403 scope_denied` en lecture comme en écriture sur
une entité sans grant. Tant que ce n'est pas fait, `ecriture_cloisonnee` vaut
faux dans les preuves.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any, Mapping

SCHEMA = "sawm/recovery-approval/v1"
_HEX = re.compile(r"[0-9a-f]{64}\Z")
# Le TITRE porte les empreintes en clair, et c'est délibéré : un rappel TSST
# rend un `excerpt` TRONQUÉ, jamais le document déposé. Mesuré le 2026-09-22 :
# le JSON de l'extrait est coupé en plein champ et ne se reparse pas. Le titre,
# lui, revient intact. Ce qui doit être vérifiable doit donc y figurer.
# Budget serre : le pont tronque le titre a 160 caracteres. Deux empreintes
# completes ne tiennent pas — on garde la reference entiere (c'est elle qui
# doit etre comparee) et un prefixe du document.
_TITRE = "SAWM-APPROBATION v1 ns={ns} ref={ref} doc16={doc16}"
_TITRE_RE = re.compile(
    r"SAWM-APPROBATION v1 ns=([A-Za-z0-9._-]{1,32}) "
    r"ref=([0-9a-f]{64}) doc16=([0-9a-f]{16})")
# Le domaine cloisonne les exercices : sans lui, les approbations d'un essai
# precedent se melent a celles du suivant et la verification conclut a une
# contradiction qui n'appartient a aucun des deux.
_NS_RE = re.compile(r"[A-Za-z0-9._-]{1,32}\Z")


class AncrageErreur(RuntimeError):
    """L'ancrage n'a pas pu être établi ou vérifié. On ne suppose rien."""


def _document(reference: str, sha256: str, cle_publique_pem: str,
              note: str = "") -> dict:
    if not _HEX.fullmatch(sha256):
        raise AncrageErreur("empreinte de référence malformée")
    corps = {
        "schema": SCHEMA,
        "reference": str(reference)[:1024],
        "reference_sha256": sha256,
        "cle_publique_sha256": hashlib.sha256(
            cle_publique_pem.encode("utf-8")).hexdigest(),
        "note": str(note)[:400],
    }
    # Empreinte du contenu canonique : c'est elle qu'on retrouvera au rappel.
    corps["document_sha256"] = hashlib.sha256(
        json.dumps(corps, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=False).encode("utf-8")).hexdigest()
    return corps


def deposer_approbation(pont, *, reference: str, sha256: str,
                        cle_publique_pem: str, domaine: str,
                        note: str = "") -> dict:
    """Dépose l'approbation À FROID, quand on croit la référence saine.

    Rend le reçu, dont le `job` terminé : sans projection confirmée, le rappel
    qui suivra lirait une mémoire vide et l'on conclurait à tort qu'aucune
    approbation n'existe.
    """
    if not _NS_RE.fullmatch(str(domaine or "")):
        raise AncrageErreur("domaine d'ancrage invalide")
    doc = _document(reference, sha256, cle_publique_pem, note)
    doc["domaine"] = domaine
    occurrence = "approbation-" + doc["document_sha256"][:16]
    recu = pont.deposer([{
        "id": occurrence,
        "titre": _TITRE.format(ns=domaine, ref=sha256,
                               doc16=doc["document_sha256"][:16]),
        "contenu": json.dumps(doc, ensure_ascii=False, sort_keys=True),
    }], attendre=True, budget_s=90.0)
    jobs = recu.get("jobs") or []
    if not jobs or any(j.get("statut") != "completed" for j in jobs):
        raise AncrageErreur(
            "dépôt non projeté : l'approbation ne serait pas rappelable, "
            "donc elle ne compte pas")
    return {
        "document": doc,
        "event_id": f"{pont.campagne}-{occurrence}",
        "jobs": jobs,
        "depose_epoch_ms": int(time.time() * 1000),
        "note_horloge": ("l'horodatage ci-dessus est celui du contrôleur ; "
                         "le temps de connaissance qui fait foi est assigné "
                         "par le serveur et n'est pas fourni par le client"),
    }


def _horodatage_ms(valeur: Any) -> int | None:
    """Convertit le `knowledge_time` du moteur en millisecondes.

    C'est LE champ qui compte : le temps de connaissance est assigné par le
    serveur, donc un client ne peut pas l'antidater.
    """
    if isinstance(valeur, (int, float)):
        return int(valeur if valeur > 1e11 else valeur * 1000)
    if not isinstance(valeur, str) or not valeur.strip():
        return None
    texte = valeur.strip().replace("Z", "+00:00")
    if " " in texte and "T" not in texte:
        texte = texte.replace(" ", "T", 1)
    try:
        from datetime import datetime, timezone
        d = datetime.fromisoformat(texte)
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return int(d.timestamp() * 1000)
    except ValueError:
        return None


def _approbations(preuves, domaine: str) -> list[dict]:
    """Extrait les approbations des preuves rappelées, par le TITRE.

    On ne tente pas de reparser l'extrait : il est tronqué par construction.
    Le titre porte les deux empreintes, le moteur porte le temps de
    connaissance. C'est suffisant, et c'est vérifiable.
    """
    sorties = []
    for ligne in preuves or ():
        if not isinstance(ligne, Mapping):
            continue
        titre = ligne.get("title") or ligne.get("titre") or ""
        m = _TITRE_RE.search(titre if isinstance(titre, str) else "")
        if not m or m.group(1) != domaine:
            continue
        sorties.append({
            "domaine": m.group(1),
            "reference_sha256": m.group(2),
            "document_sha256_prefixe": m.group(3),
            "evidence_id": ligne.get("evidence_id"),
            "knowledge_time": ligne.get("knowledge_time"),
            "knowledge_time_ms": _horodatage_ms(ligne.get("knowledge_time")),
            "status": ligne.get("status"),
            "integrity_verified": ligne.get("integrity_verified"),
        })
    return sorties


def verifier_approbation(pont, *, sha256_attendu: str, coupure_ms: int,
                         domaine: str, reference: str | None = None) -> dict:
    """Vérifie l'approbation par rappel TSST, coupé AVANT l'incident.

    `coupure_ms` est obligatoire et n'a pas de valeur par défaut : c'est une
    connaissance humaine — le moment où l'on sait que le système était sain.
    La deviner reviendrait à laisser l'adversaire la choisir.
    """
    if not isinstance(coupure_ms, int) or coupure_ms <= 0:
        raise AncrageErreur(
            "coupure temporelle obligatoire : indiquer le moment où le "
            "système était connu sain, en millisecondes")
    if not _HEX.fullmatch(sha256_attendu):
        raise AncrageErreur("empreinte attendue malformée")

    if not _NS_RE.fullmatch(str(domaine or "")):
        raise AncrageErreur("domaine d'ancrage invalide")
    question = (f"SAWM-APPROBATION ns={domaine} approbation de référence "
                f"de reprise {SCHEMA}")
    avant = pont.rappeler(question, limite=10, avant_ms=coupure_ms)
    apres = pont.rappeler(question, limite=10)

    toutes = _approbations(apres.preuves, domaine)
    # Deux filtres qui doivent CONCORDER : la coupure posée au moteur, et le
    # temps de connaissance que le moteur rend pour chaque preuve. S'ils
    # divergent, on préfère le plus strict et on le signale.
    coupees = _approbations(avant.preuves, domaine)
    par_horodatage = [d for d in toutes
                      if d["knowledge_time_ms"] is not None
                      and d["knowledge_time_ms"] <= coupure_ms]
    ids_coupees = {d["evidence_id"] for d in coupees}
    ids_horodatage = {d["evidence_id"] for d in par_horodatage}
    docs_avant = coupees if ids_coupees else par_horodatage
    docs_apres = toutes

    concordants = [d for d in docs_avant if d.get("reference_sha256") == sha256_attendu]
    divergents_avant = [d for d in docs_avant
                        if d.get("reference_sha256") != sha256_attendu]
    # Une approbation apparue APRÈS la coupure, portant une autre empreinte,
    # n'est pas un détail : c'est la trace d'une tentative de réapprobation.
    empreintes_avant = {d.get("document_sha256_prefixe") for d in docs_avant}
    posterieures = [d for d in docs_apres
                    if d.get("document_sha256_prefixe") not in empreintes_avant]
    concurrentes = [d for d in posterieures
                    if d.get("reference_sha256") != sha256_attendu]

    mesure = {
        "schema": SCHEMA,
        "domaine": domaine,
        "coupure_ms": coupure_ms,
        "coupure_moteur_et_horodatage_concordent": ids_coupees == ids_horodatage,
        "retenues_par_coupure_moteur": len(ids_coupees),
        "retenues_par_temps_de_connaissance": len(ids_horodatage),
        "approbations_avant_coupure": len(docs_avant),
        "approbations_concordantes": len(concordants),
        "approbations_divergentes_avant_coupure": len(divergents_avant),
        "approbations_posterieures": len(posterieures),
        "approbations_concurrentes": [
            {"reference_sha256": d.get("reference_sha256"),
             "document_sha256_prefixe": d.get("document_sha256_prefixe"),
             "knowledge_time": d.get("knowledge_time")}
            for d in concurrentes
        ],
        "moteur_rappel": avant.moteur,
        "latence_rappel_ms": avant.latence_ms,
        "provenance": avant.provenance,
        "ecriture_cloisonnee": False,
        "limite": ("Basira n'est pas un coffre immuable : un porteur de la clé "
                   "de service peut AJOUTER une approbation. Il ne peut ni "
                   "effacer l'originale, ni antidater la sienne, car le temps "
                   "de connaissance est assigné par le serveur."),
        "ancre": False,
    }

    if not concordants:
        mesure["motif"] = (
            "aucune approbation de cette référence connue avant la coupure : "
            "la référence n'est pas ancrée")
        return mesure
    if divergents_avant:
        mesure["motif"] = (
            "plusieurs approbations contradictoires connues avant la coupure : "
            "impossible de trancher, et ce désaccord est lui-même le résultat")
        return mesure
    mesure["ancre"] = True
    mesure["document"] = concordants[0]
    if concurrentes:
        mesure["alerte"] = (
            f"{len(concurrentes)} approbation(s) concurrente(s) déposée(s) "
            "après la coupure : la référence d'origine tient, mais quelqu'un a "
            "tenté d'en approuver une autre")
    return mesure
