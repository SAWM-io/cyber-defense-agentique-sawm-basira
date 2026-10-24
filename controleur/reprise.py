#!/usr/bin/env python3
"""Reprise après compromission supposée — conduite depuis le contrôleur.

Ce module exécute la procédure de reprise contre l'hyperviseur et l'hôte. Il
ne demande jamais rien à l'invité : un système potentiellement compromis ne
peut pas témoigner de son propre état. Chaque étape produit une mesure faite
DEHORS, scellée, et conservée hors de l'invité.

Les six étapes reprennent celles de ``recovery_contract.STATES`` :

  proof              conserver les preuves à l'extérieur, avant tout geste
  isolated           isoler la machine depuis le contrôleur indépendant
  recovery_verified  vérifier une référence de reprise DISTINCTE du système
  rebuilt            révoquer les accès et reconstruire depuis cette référence
  verified           vérifier la remise en état
  released           rendre les services progressivement, accès neufs

Trois choix de conception, chacun contre une conclusion fausse :

1. **La reconstruction ne s'écrit pas par-dessus la machine suspecte.** Elle
   crée une instance neuve depuis la référence, et le disque d'origine est
   CONSERVÉ comme preuve. Écraser le disque détruirait l'enquête, et rien ne
   prouverait ensuite ce qui s'était passé.
2. **L'isolement se constate depuis l'hôte, pas depuis l'invité.** On lit la
   ligne de commande réelle de QEMU et on vérifie soi-même qu'on ne joint plus
   la cible. Un invité qui répond « je suis isolé » ne prouve rien.
3. **Révoquer ne veut pas dire supprimer un compte.** On fait tourner les
   accès (clé d'hôte, clé de service, version de jeton applicatif) et on
   enregistre ce qui a été révoqué ; un compte effacé laisse vivre les
   identifiants déjà émis.

Limites à dire au client : la signature protège une référence de laboratoire.
Ce n'est pas une attestation de micrologiciel, et cette procédure ne prouve
pas qu'une image quelconque est saine — seulement qu'elle est celle qui a été
approuvée et mesurée avant l'incident.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import plistlib
import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass

from .audit_signe import canonique
from .recovery_contract import (ControllerEvidence, RecoveryBinding, RecoveryState)

ICI = pathlib.Path(__file__).resolve().parent
RACINE = ICI.parent
PREUVES = RACINE / "releves" / "reprise"
COFFRE = pathlib.Path.home() / ".sawm-labo"
DOCUMENTS_UTM = (pathlib.Path.home()
                 / "Library/Containers/com.utmapp.UTM/Data/Documents")
REFERENCE_BOX = pathlib.Path(os.environ.get("SAWM_LABO_RECOVERY_IMAGE", str(COFFRE / "recovery/reference.img"))).expanduser()
# L'empreinte APPROUVEE est deposee AVANT l'incident, hors du processus de
# reprise. La comparer a une empreinte calculee au meme instant sur le meme
# fichier serait une tautologie : elle passerait toujours, y compris si la
# reference avait ete remplacee entre-temps.
APPROBATION = RACINE / "releves" / "reprise" / "reference-approuvee.sha256"
# Clé publique du signataire, déposée AVANT l'incident elle aussi. C'est son
# empreinte qui lie le manifeste : une empreinte tirée du manifeste lui-même
# ne vaudrait rien, puisqu'un attaquant fournirait les deux.
CLE_APPROUVEE = RACINE / "releves" / "reprise" / "cle-signature.pub.pem"
# Deux formes du MÊME identifiant, et ce n'est pas un détail : le contrat de
# reprise exige la forme canonique (minuscules, RFC 4122) tandis qu'utmctl
# refuse tout sauf la forme majuscule de son registre. Les confondre fait
# échouer l'étape avec « VM non mesurable », ce qui se lit à tort comme une
# machine éteinte.
VM_UUID = os.environ.get("SAWM_LABO_VM_UUID", "00000000-0000-0000-0000-000000000000").lower()
VM_UUID_UTM = VM_UUID.upper()
VM_MAC = os.environ.get("SAWM_LABO_VM_MAC", "02:00:00:00:00:01")
UTILISATEUR_INVITE = os.environ.get("SAWM_LABO_VM_USER", "vagrant")
VM_NOM = os.environ.get("SAWM_LABO_VM_NOM", "sawm-security-lab")
# Le contrat veut une cible en CHEMIN absolu : c'est le bundle de la VM,
# c'est-a-dire l'objet reellement reconstruit, pas une etiquette.
VM_CIBLE = os.environ.get("SAWM_LABO_VM_BUNDLE", str(DOCUMENTS_UTM / f"{VM_NOM}.utm"))
IP_INVITE = os.environ.get("SAWM_LABO_VM_IP", "192.0.2.3")
DELAI = 30


class RepriseErreur(RuntimeError):
    """Une étape n'a pas pu être MESURÉE. On ne poursuit pas sur une supposition."""


# --------------------------------------------------------------------------
# Mesures de l'hôte — aucune ne passe par l'invité
# --------------------------------------------------------------------------

def _run(*args: str, delai: int = DELAI) -> tuple[int, str, str]:
    try:
        p = subprocess.run(list(args), capture_output=True, text=True, timeout=delai)
    except subprocess.TimeoutExpired:
        raise RepriseErreur(f"délai dépassé, issue INCONNUE : {' '.join(args)}") from None
    return p.returncode, p.stdout, p.stderr


def empreinte_fichier(chemin: pathlib.Path, *, bloc: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with chemin.open("rb") as f:
        while True:
            morceau = f.read(bloc)
            if not morceau:
                break
            h.update(morceau)
    return h.hexdigest()


def ligne_qemu(uuid: str = VM_UUID_UTM) -> str | None:
    """Ligne de commande du processus QEMU de CETTE VM, ou None.

    Piege mesure le 2026-09-22 : `pgrep -f qemu-aarch64-softmmu` correspond a
    TOUT processus dont l'argv contient cette chaine — y compris le shell qui
    vient de lancer la commande. Prendre le premier PID a scelle un
    `/bin/zsh -c ...` comme « ligne de commande reelle de QEMU ». On filtre
    donc sur l'UUID, et zero ou deux correspondances valent INCONNU, jamais
    une valeur plausible.
    """
    _, pids, _ = _run("pgrep", "-f", uuid)
    lignes = []
    for pid in pids.split():
        _, ligne, _ = _run("ps", "-o", "command=", "-p", pid)
        ligne = ligne.strip()
        if "qemu-aarch64-softmmu" in ligne and uuid in ligne:
            lignes.append(ligne)
    return lignes[0] if len(lignes) == 1 else None


def _forme_utmctl(uuid: str) -> str:
    """utmctl n'accepte que la forme de son registre : majuscules."""
    return VM_UUID_UTM if uuid.lower() == VM_UUID else uuid.upper()


def statut_vm(uuid: str = VM_UUID_UTM) -> str | None:
    _, out, _ = _run("utmctl", "status", _forme_utmctl(uuid))
    return out.strip() or None


def config_vm(nom: str = VM_NOM) -> dict | None:
    p = DOCUMENTS_UTM / f"{nom}.utm" / "config.plist"
    if not p.exists():
        return None
    with p.open("rb") as f:
        return plistlib.load(f)


def joignable(adresse: str, port: int = 22, delai: float = 3.0) -> bool:
    """Une connexion TCP. NE PAS s'en servir seule pour conclure a l'isolement :
    un service arrete donne le meme resultat qu'un lien coupe."""
    famille = socket.AF_INET6 if ":" in adresse else socket.AF_INET
    try:
        s6 = socket.socket(famille, socket.SOCK_STREAM)
        s6.settimeout(delai)
        s6.connect((adresse, port))
        s6.close()
        return True
    except OSError:
        return False


def repond_icmp(adresse: str, delai: int = 2) -> bool:
    outil = "ping6" if ":" in adresse else "ping"
    code, _, _ = _run(outil, "-c", "1", "-W", str(delai * 1000), adresse, delai=delai + 3)
    return code == 0


def adresses_de_la_cible() -> list[str]:
    """Decouvre les adresses de l'invite au lieu de les coder en dur.

    Une adresse non testee est un trou : l'invite porte une ULA IPv6 dont le
    sshd ecoute, et la sonder change le verdict.
    """
    trouvees = {IP_INVITE}
    _, arp, _ = _run("arp", "-an")
    _, ndp, _ = _run("ndp", "-an")
    mac = VM_MAC.lower()
    for ligne in (arp + "\n" + ndp).splitlines():
        if mac in ligne.lower():
            for morceau in re.findall(r"[0-9a-fA-F:.]{7,}", ligne):
                if morceau.count(".") == 3 or (":" in morceau and morceau.count(":") > 2
                                               and not re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}",
                                                                    morceau.lower())):
                    trouvees.add(morceau.strip("()"))
    return sorted(trouvees)


def sonder_cible(adresses: list[str]) -> dict:
    """Un sondage complet : ICMP + TCP sur chaque adresse connue."""
    out = {}
    for a in adresses:
        out[a] = {"icmp": repond_icmp(a), "tcp22": joignable(a, 22)}
    return out


def cible_silencieuse(sondage: dict) -> bool:
    return all(not v["icmp"] and not v["tcp22"] for v in sondage.values())


def _sceller(run_id: str, stage: str, mesure: dict) -> tuple[pathlib.Path, str]:
    """Écrit la mesure hors de l'invité et rend son empreinte canonique."""
    dossier = PREUVES / run_id
    dossier.mkdir(parents=True, exist_ok=True)
    octets = canonique(mesure)
    empreinte = hashlib.sha256(octets).hexdigest()
    chemin = dossier / f"{stage}.json"
    tmp = chemin.with_suffix(".tmp")
    tmp.write_bytes(octets)
    os.replace(tmp, chemin)
    (dossier / f"{stage}.sha256").write_text(empreinte + "\n")
    return chemin, empreinte


def _preuve(binding: RecoveryBinding, stage: str, mesure: dict) -> ControllerEvidence:
    _, empreinte = _sceller(binding.run_id, stage, mesure)
    return ControllerEvidence(stage=stage, run_id=binding.run_id, vm_id=binding.vm_id,
                              target=binding.target, sha256=empreinte,
                              origin="host-controller", passed=True)


# --------------------------------------------------------------------------
# Les six étapes
# --------------------------------------------------------------------------

@dataclass
class Reprise:
    binding: RecoveryBinding
    etat: RecoveryState
    mesures: dict

    def journal(self) -> list[dict]:
        return [{"etape": e, "empreinte": d} for e, d in self.etat.history]


def etape_preuve(binding: RecoveryBinding) -> dict:
    """1. Observer et CONSERVER les preuves à l'extérieur, avant tout geste.

    On fige ce que le contrôleur détient déjà : les séries de télémétrie
    reçues, la configuration de l'hyperviseur, la ligne de commande réelle de
    QEMU. Une compromission de l'invité ne peut pas les effacer : elles ne
    sont pas chez lui.
    """
    series = sorted((RACINE / "releves" / "series").glob("*.jsonl"))
    mesure = {
        "mur_epoch_ms": int(time.time() * 1000),
        "vm_statut": statut_vm(binding.vm_id),
        "qemu_cmdline": ligne_qemu(),
        "config_hyperviseur": _extrait_config(config_vm()),
        "series_conservees": [
            {"fichier": p.name, "octets": p.stat().st_size,
             "sha256": empreinte_fichier(p)} for p in series[-4:]
        ],
        "preuves_deja_detenues": sorted(
            p.name for p in (RACINE / "releves").glob("*.txt")),
        "hote_libre_o": shutil.disk_usage(str(RACINE)).free,
    }
    if mesure["vm_statut"] is None:
        raise RepriseErreur("statut de la VM non mesurable depuis l'hôte")
    return mesure


def _extrait_config(config: dict | None) -> dict | None:
    if not config:
        return None
    reseau = (config.get("Network") or [{}])[0]
    partage = config.get("Sharing") or {}
    return {
        "mode_reseau": reseau.get("Mode"),
        "isole_de_l_hote": reseau.get("IsolateFromHost"),
        "partage_dossiers": partage.get("DirectoryShareMode"),
        "presse_papiers": partage.get("ClipboardSharing"),
        "disques": [d.get("ImageName") for d in (config.get("Drive") or [])],
    }


def etape_isolement(binding: RecoveryBinding, *, appliquer: bool = True,
                    fenetre_s: int = 120, sondes: int = 4) -> dict:
    """2. Isoler la machine, et le CONSTATER — ce qui prend du temps.

    Trois corrections apportees apres qu'une verification adverse a montre que
    cette etape ne pouvait pas echouer :

    * on attend que l'invite ait FINI de demarrer avant de conclure. Sonder
      dix secondes apres un redemarrage garantit un silence qui n'a rien a
      voir avec l'isolement — le sshd de cet invite met 42 s a revenir ;
    * on sonde TOUTES les adresses decouvertes, IPv4 et IPv6, en ICMP et en
      TCP. Un service arrete n'est plus confondu avec un lien coupe ;
    * on exige la CONJONCTION : silence persistant sur la fenetre, `isolated=on`
      dans la ligne QEMU reelle, et l'intention lue dans la configuration.
      Auparavant seule la connexion TCP/22 entrait dans la garde ; les autres
      champs decoraient le dossier sans rien conditionner.
    """
    adresses = adresses_de_la_cible()
    avant = sonder_cible(adresses)
    vivante_avant = not cible_silencieuse(avant)
    applique = None
    if appliquer:
        applique = _isoler_par_hyperviseur(binding.vm_id)
        # On attend le demarrage : sans cela on mesure la fenetre de boot.
        _attendre_demarrage(adresses)
    sondages = []
    pas = max(1.0, fenetre_s / max(1, sondes))
    for i in range(sondes):
        if i:
            time.sleep(pas)
        sondages.append({"t_s": round(i * pas, 1), "resultat": sonder_cible(adresses)})
    silencieuse = all(cible_silencieuse(x["resultat"]) for x in sondages)
    ligne = ligne_qemu()
    config = _extrait_config(config_vm())
    mesure = {
        "mur_epoch_ms": int(time.time() * 1000),
        "adresses_sondees": adresses,
        "avant": avant,
        "vivante_avant": vivante_avant,
        "sondages": sondages,
        "fenetre_s": fenetre_s,
        "silencieuse_sur_toute_la_fenetre": silencieuse,
        "qemu_cmdline": ligne,
        "aucun_peripherique_reseau": bool(ligne and "-netdev" not in ligne
                                          and "vmnet-" not in ligne),
        "isolated_on_dans_qemu": bool(ligne and "isolated=on" in ligne),
        "config_demandee": config,
        "note_isolated_on": ("`isolated=on` isole les VM entre elles, pas de "
                             "leur hôte : mesuré, il ne suffit pas"),
        "action_hyperviseur": applique,
    }
    motifs = []
    if not silencieuse:
        motifs.append("la cible répond encore sur au moins une adresse")
    if ligne is None:
        motifs.append("processus QEMU de la cible non identifié : issue INCONNUE")
    elif "-netdev" in ligne or "vmnet-" in ligne:
        motifs.append("un périphérique réseau subsiste sur la ligne QEMU réelle")
    if appliquer and not vivante_avant:
        motifs.append("la cible était déjà silencieuse avant : aucun changement observé")
    mesure["motifs_echec"] = motifs
    if motifs:
        raise RepriseErreur("isolement NON constaté : " + " ; ".join(motifs))
    return mesure


def _attendre_demarrage(adresses: list[str], budget_s: int = 120) -> dict:
    """Attend que l'invite ait fini de demarrer, ou declare l'attente vaine.

    Sans cette attente, le silence mesure est celui du boot, pas celui de
    l'isolement — et l'etape reussit toujours.
    """
    fin = time.monotonic() + budget_s
    while time.monotonic() < fin:
        if statut_vm() == "started":
            # La VM tourne selon l'hyperviseur ; on laisse l'invite monter.
            time.sleep(45)
            return {"attente": "statut started + 45 s de montee"}
        time.sleep(3)
    return {"attente": "budget epuise, demarrage NON constate"}


def _attendre_utm_ferme(budget_s: int = 40) -> bool:
    """UTM doit être RÉELLEMENT sorti avant qu'on édite sa configuration.

    Mesuré le 2026-09-22 : `osascript quit` rend la main avant que le
    processus ait disparu, et UTM réécrit alors le plist depuis son état en
    mémoire — effaçant l'édition. La VM redémarre avec l'ancien réseau, et
    l'isolement n'est jamais appliqué alors que le fichier dit le contraire.
    """
    _run("osascript", "-e", 'tell application "UTM" to quit')
    fin = time.monotonic() + budget_s
    while time.monotonic() < fin:
        code, sortie, _ = _run("pgrep", "-x", "UTM")
        if code != 0 or not sortie.strip():
            time.sleep(1.5)                 # laisse le plist se poser
            return True
        time.sleep(1)
    return False


def _arreter_vm(uuid: str, budget_s: int = 60) -> str:
    _run("utmctl", "stop", uuid)
    fin = time.monotonic() + budget_s
    while time.monotonic() < fin:
        if statut_vm(uuid) == "stopped":
            return "stopped"
        time.sleep(2)
    _run("utmctl", "stop", uuid, "--force")
    fin = time.monotonic() + 20
    while time.monotonic() < fin:
        if statut_vm(uuid) == "stopped":
            return "stopped (force)"
        time.sleep(2)
    return statut_vm(uuid) or "inconnu"


def _isoler_par_hyperviseur(uuid: str, tentatives: int = 2) -> dict:
    """Retire la carte réseau de la VM. C'est cela, isoler.

    Mesuré le 2026-09-22, et cela corrige une erreur de conception :
    `IsolateFromHost` (qui produit `isolated=on` sur le backend vmnet) isole
    les machines virtuelles **entre elles**, PAS de leur hôte. Avec
    `Mode: Host` + `isolated=on` correctement appliqué, la cible répondait
    encore en ICMP et en TCP/22 sur ses deux familles d'adresses. Poser cet
    indicateur et annoncer « machine isolée » aurait été faux.

    Ce qui isole réellement, et qui est vérifiable : retirer le périphérique
    réseau de la configuration. Après redémarrage, la ligne de commande QEMU
    ne porte plus aucun `-netdev`, et la cible ne répond plus sur aucune
    adresse — tandis que l'invité CONTINUE DE TOURNER. L'investigation à
    chaud est préservée, et le contrôleur garde son canal hors bande par
    virtio-serial.

    La configuration d'origine est sauvegardée : la remise en service la
    rétablit, elle n'est pas perdue.
    """
    uuid = _forme_utmctl(uuid)
    bundle = DOCUMENTS_UTM / f"{VM_NOM}.utm"
    plist = bundle / "config.plist"
    sauvegarde = bundle / "config.plist.avant-isolement"
    journal = []
    for essai in range(1, tentatives + 1):
        arret = _arreter_vm(uuid)
        utm_ferme = _attendre_utm_ferme()
        if not sauvegarde.exists():
            shutil.copy2(plist, sauvegarde)
        # Retrait du périphérique réseau. `plutil -remove` sur une entrée
        # absente rend un code non nul : c'est idempotent, pas une erreur.
        _run("plutil", "-remove", "Network.0", str(plist))
        _, reste, _ = _run("plutil", "-extract", "Network", "json", "-o", "-",
                           str(plist))
        _run("utmctl", "start", uuid)
        sans_reseau = False
        ligne = None
        for _ in range(15):
            time.sleep(2)
            ligne = ligne_qemu(uuid)
            if ligne:
                sans_reseau = ("-netdev" not in ligne
                               and "vmnet-" not in ligne)
                break
        journal.append({"essai": essai, "arret": arret, "utm_ferme": utm_ferme,
                        "network_restant": reste.strip(),
                        "aucun_netdev_dans_qemu": sans_reseau})
        if sans_reseau:
            return {"methode": "retrait du périphérique réseau",
                    "sauvegarde_configuration": str(sauvegarde),
                    "statut": statut_vm(uuid), "journal": journal,
                    "applique_par_hyperviseur": True}
    raise RepriseErreur(
        "l'hyperviseur n'a PAS retiré le réseau : un `-netdev` subsiste sur la "
        "ligne QEMU après " + str(tentatives) + " tentatives")


def etape_reference(binding: RecoveryBinding, *, ancrage: dict | None = None) -> dict:
    """3. Vérifier un environnement de reprise DISTINCT du système suspect.

    On mesure la référence saine — l'image d'origine, jamais montée par
    l'invité — et on la compare à l'empreinte approuvée AVANT l'incident.
    """
    if not REFERENCE_BOX.exists():
        raise RepriseErreur(f"référence de reprise absente : {REFERENCE_BOX}")
    empreinte = empreinte_fichier(REFERENCE_BOX)
    mesure = {
        "mur_epoch_ms": int(time.time() * 1000),
        "reference": str(REFERENCE_BOX),
        "octets": REFERENCE_BOX.stat().st_size,
        "sha256": empreinte,
        "sha256_approuve": binding.clean_image_sha256,
        "concordance": empreinte == binding.clean_image_sha256,
        # D'où vient l'approbation ? C'est la question qui décide si cette
        # étape prouve quoi que ce soit. Un fichier posé sur le contrôleur ne
        # résiste pas à l'adversaire que la procédure postule.
        "ancrage": ancrage or {
            "source": "fichier local du contrôleur",
            "independant": False,
            "limite": ("réécrivable par un adversaire ayant la main sur "
                       "l'hôte — c'est précisément l'adversaire postulé"),
        },
        "distincte_du_systeme_suspect": True,
        "note": ("référence en lecture seule, jamais montée par l'invité ; "
                 "la signature protège une référence de laboratoire, pas un "
                 "micrologiciel"),
    }
    if not mesure["concordance"]:
        raise RepriseErreur(
            "l'empreinte de la référence ne correspond pas à celle approuvée")
    if ancrage is not None and not ancrage.get("ancre"):
        raise RepriseErreur(
            "approbation non ancrée dans la mémoire Cloud : "
            + str(ancrage.get("motif") or "raison non précisée"))
    return mesure


def etape_reconstruction(binding: RecoveryBinding, *, appliquer: bool = True) -> dict:
    """4. Révoquer les accès et reconstruire depuis la référence saine.

    Le disque suspect est CONSERVÉ comme preuve : on ne reconstruit pas par-
    dessus. Révoquer, ici, veut dire faire tourner des identifiants — pas
    supprimer un compte, ce qui laisserait vivre les jetons déjà émis.
    """
    revocations = _revoquer_acces(appliquer=appliquer)
    reconstruction = None
    if appliquer:
        reconstruction = _reconstruire_depuis_reference(binding)
    mesure = {
        "mur_epoch_ms": int(time.time() * 1000),
        "revocations": revocations,
        "reconstruction": reconstruction,
        "disque_suspect_conserve": reconstruction["disque_preuve"] if reconstruction else None,
        "note": ("un compte supprimé ne révoque pas les identifiants déjà "
                 "émis ; la rotation les invalide tous"),
    }
    prouvees = [r for r in revocations if r["revoque"]]
    if not prouvees:
        restants = "; ".join(f"{r['accès']} ({r.get('reste_a_faire') or r.get('post_condition', {}).get('motif') or 'non mesuré'})"
                             for r in revocations)
        raise RepriseErreur(
            "aucun accès n'a été révoqué DE FAÇON PROUVÉE — " + restants)
    return mesure


def _guest_bash(script: str, delai: int = 30) -> tuple[int, str]:
    """Exécute dans l'invité par le canal HORS RÉSEAU de l'agent.

    Ce canal survit à l'isolement : la révocation reste donc possible après
    avoir coupé le réseau de la cible, ce qu'un accès SSH ne permettrait pas.
    """
    code, sortie, _ = _run("utmctl", "exec", VM_UUID_UTM, "--cmd",
                           "/bin/bash", "-c", script, delai=delai)
    return code, sortie


def _jeton(verbe: str, argument: str = "") -> str:
    """Appelle le script de l'invité. On pousse un script, on n'imbrique pas.

    `utmctl exec --cmd /bin/bash -c "..."` casse silencieusement dès qu'il y a
    des guillemets imbriqués : la commande rend une sortie vide, et l'appelant
    conclut à tort que l'état est illisible.
    """
    # `utmctl exec` ne rend pas sa sortie de façon fiable : on écrit dans un
    # fichier de l'invité puis on le récupère. C'est le seul motif qui tient.
    if verbe not in {"version", "tourner", "essai"} or (argument and not argument.isdecimal()):
        raise RepriseErreur("commande de jeton hors contrat")
    commande = f"/usr/bin/python3 /opt/sawm-labo/agent/jetons.py {verbe} {argument}".strip()
    _run("utmctl", "exec", VM_UUID_UTM, "--cmd", "/bin/bash", "-c",
         f"{commande} > /opt/sawm-labo/jeton.out 2>&1", delai=25)
    _, sortie, _ = _run("utmctl", "file", "pull", VM_UUID_UTM,
                        "/opt/sawm-labo/jeton.out", delai=20)
    return sortie.strip()


def _jeton_guest_version() -> int | None:
    try:
        return int(_jeton("version"))
    except ValueError:
        return None


def _ssh(cle: pathlib.Path, adresse: str, commande: str, delai: int = 12):
    """Tentative SSH avec une clé précise. Sert à PROUVER un refus."""
    return _run("ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
                "-o", f"ConnectTimeout={delai}", "-o", "IdentitiesOnly=yes",
                "-i", str(cle), f"{UTILISATEUR_INVITE}@{adresse}", commande,
                delai=delai + 8)


def _revoquer_acces(*, appliquer: bool, adresse: str = IP_INVITE) -> list[dict]:
    """Révoque, puis PROUVE la révocation en rejouant l'ancien identifiant.

    Correction majeure après vérification adverse : le drapeau `revoque` ne
    doit jamais venir du mode d'exécution. Une version précédente le posait à
    `bool(appliquer)`, c'est-à-dire à vrai dès qu'on passait --appliquer, sans
    mesurer le moindre effet — et le dossier scellé annonçait deux révocations
    là où il n'y en avait zéro. Désormais chaque accès porte sa post-condition
    mesurée : l'ancien identifiant doit être REFUSÉ, le nouveau ACCEPTÉ.
    """
    sorties = []
    ancienne = COFFRE / "cle_labo"
    nouvelle = COFFRE / "cle_labo.neuve"
    empreinte_avant = _empreinte_cle_publique(COFFRE / "cle_labo.pub")

    detail = {"nouvelle_installee": False, "ancienne_retiree": False,
              "ancienne_rejouee": None, "nouvelle_verifiee": None,
              "motif": None}
    if appliquer and ancienne.exists():
        if not nouvelle.exists():
            code, _, err = _run("ssh-keygen", "-t", "ed25519", "-N", "", "-C",
                                "reprise-institutionnelle", "-f", str(nouvelle))
            if code != 0:
                detail["motif"] = f"génération impossible : {err[:120]}"
        if nouvelle.exists():
            pub = (COFFRE / "cle_labo.neuve.pub").read_text().strip()
            # On remplace authorized_keys : installer sans RETIRER l'ancienne
            # ne révoque rien. C'est le retrait qui révoque, pas l'ajout.
            code, _, err = _ssh(ancienne, adresse,
                                f"printf '%s\\n' {pub!r} > ~/.ssh/authorized_keys "
                                "&& chmod 600 ~/.ssh/authorized_keys && echo POSE")
            detail["nouvelle_installee"] = code == 0
            detail["ancienne_retiree"] = code == 0
            if code != 0:
                detail["motif"] = f"installation refusée : {err[:120]}"
            else:
                # POST-CONDITIONS : c'est ici, et nulle part ailleurs, que se
                # décide `revoque`.
                c_old, _, _ = _ssh(ancienne, adresse, "true")
                c_new, _, _ = _ssh(nouvelle, adresse, "true")
                detail["ancienne_rejouee"] = ("refusée" if c_old != 0
                                              else "ACCEPTÉE — non révoquée")
                detail["nouvelle_verifiee"] = c_new == 0
    elif appliquer:
        detail["motif"] = "aucune clé d'administration à faire tourner"
    else:
        detail["motif"] = "mode mesure seule : aucune rotation tentée"

    revoque_cle = bool(detail["ancienne_rejouee"] == "refusée"
                       and detail["nouvelle_verifiee"])
    if revoque_cle:
        # Promotion : la clé neuve DEVIENT la clé d'administration. Sans cela
        # la rotation casserait tout l'outillage, qui continue de pointer sur
        # l'ancien fichier — et on aurait révoqué l'accès du défenseur.
        for suffixe in ("", ".pub"):
            src = COFFRE / f"cle_labo.neuve{suffixe}"
            if src.exists():
                shutil.move(str(src), str(COFFRE / f"cle_labo{suffixe}"))
        detail["promue_en_cle_administration"] = True
    sorties.append({
        "accès": "clé d'administration de l'hôte vers l'invité",
        "mécanisme": "rotation ed25519 + RETRAIT de l'ancienne d'authorized_keys",
        "empreinte_avant": empreinte_avant,
        "empreinte_apres": _empreinte_cle_publique(
            COFFRE / ("cle_labo.pub" if revoque_cle else "cle_labo.neuve.pub")),
        "post_condition": detail,
        "revoque": revoque_cle,
    })

    # Jetons applicatifs. La révocation se fait par incrément de version dans
    # l'état que le service LIT RÉELLEMENT, côté invité — et non dans un
    # fichier du contrôleur que personne ne consulte. Le canal est celui de
    # l'agent invité : il survit à l'isolement réseau.
    jeton = {"version_avant": None, "version_apres": None,
             "ancien_jeton_rejoue": None, "nouveau_jeton_verifie": None,
             "motif": None}
    if appliquer:
        avant = _jeton_guest_version()
        if avant is None:
            jeton["motif"] = "état des jetons illisible dans l'invité"
        else:
            jeton["version_avant"] = avant
            try:
                jeton["version_apres"] = int(_jeton("tourner"))
            except ValueError:
                jeton["motif"] = "rotation de version sans effet mesurable"
            if jeton["version_apres"]:
                # POST-CONDITIONS, mesurées contre le VRAI service de l'invité.
                ancien_code = _jeton("essai", str(avant))
                neuf_code = _jeton("essai", str(jeton["version_apres"]))
                jeton["ancien_jeton_rejoue"] = (
                    f"refusé ({ancien_code})" if ancien_code != "200"
                    else "ACCEPTÉ — non révoqué")
                jeton["nouveau_jeton_verifie"] = neuf_code == "200"
    else:
        jeton["motif"] = "mode mesure seule : aucune rotation tentée"
    sorties.append({
        "accès": "jetons applicatifs du service documentaire",
        "mécanisme": ("incrément de version dans l'état lu par le service — "
                      "invalide TOUS les jetons émis, connus ou non"),
        "post_condition": jeton,
        "revoque": bool(jeton["nouveau_jeton_verifie"]
                        and jeton["ancien_jeton_rejoue"]
                        and jeton["ancien_jeton_rejoue"].startswith("refusé")),
    })

    sorties.append({
        "accès": "clé de service Basira/SAWM Cloud",
        "mécanisme": "rotation par la console cliente (/espace), hors de ce module",
        "presente": (COFFRE / "env").exists(),
        "revoque": False,
        "reste_a_faire": "rotation manuelle depuis la console du compte",
    })
    return sorties


def _empreinte_cle_publique(chemin: pathlib.Path) -> str | None:
    if not chemin.exists():
        return None
    code, out, _ = _run("ssh-keygen", "-lf", str(chemin))
    return out.split()[1] if code == 0 and len(out.split()) > 1 else None


def _reconstruire_depuis_reference(binding: RecoveryBinding) -> dict:
    """Crée une instance NEUVE depuis la référence, préserve le disque suspect."""
    horodatage = time.strftime("%Y%m%dT%H%M%S")
    preuves = COFFRE / "preuves-disques"
    preuves.mkdir(parents=True, exist_ok=True)

    disque_suspect = (DOCUMENTS_UTM / f"{VM_NOM}.utm" / "Data"
                      / "715CC9C3-4627-42D5-9DFA-4DA3D40AD21A.qcow2")
    conserve = None
    saisie = {"methode": None, "sha256": None, "figee": False}
    if disque_suspect.exists():
        # Un lien dur ne conserve RIEN : meme inode que le disque vivant, que
        # QEMU tient ouvert en ecriture. Mesure du 2026-09-22 : l'empreinte de
        # la « preuve » a change en 5 secondes pendant qu'on la calculait. On
        # FIGE donc la machine avant de saisir, puis on copie et on scelle
        # l'empreinte du contenu saisi.
        _run("utmctl", "stop", VM_UUID_UTM)
        for _ in range(20):
            if statut_vm() == "stopped":
                saisie["figee"] = True
                break
            time.sleep(1)
        conserve = str(preuves / f"disque-suspect-{horodatage}.qcow2")
        if saisie["figee"]:
            shutil.copy2(disque_suspect, conserve)
            saisie["methode"] = "copie sur machine arretee"
            saisie["sha256"] = empreinte_fichier(pathlib.Path(conserve))
        else:
            # On n'a pas pu figer : on le DIT, et on ne pretend pas avoir saisi.
            conserve = None
            saisie["methode"] = "echec : machine non arretee, saisie non fiable"

    neuf = COFFRE / "vm" / f"reprise-{horodatage}.qcow2"
    neuf.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(REFERENCE_BOX, neuf)
    return {
        "disque_preuve": conserve,
        "saisie": saisie,
        "disque_reconstruit": str(neuf),
        "sha256_reconstruit": empreinte_fichier(neuf),
        "source": str(REFERENCE_BOX),
        "octets": neuf.stat().st_size,
        # Honnêteté de nommage : à ce stade on a PRÉPARÉ un disque depuis la
        # référence. Aucune instance n'est créée ni enregistrée auprès de
        # l'hyperviseur — `utmctl list` ne montre rien de neuf.
        "instance_creee": False,
        "reconstruction_effective": False,
        "note": ("disque de reprise préparé ; la création de l'instance et son "
                 "démarrage restent à faire avant toute remise en service"),
    }


def _exiger_instance_reconstruite(mesures: dict) -> dict:
    reconstruit = ((mesures.get("rebuilt") or {}).get("reconstruction") or {})
    if (reconstruit.get("instance_creee") is not True
            or reconstruit.get("reconstruction_effective") is not True):
        raise RepriseErreur(
            "remise en état non vérifiée : aucune instance effectivement "
            "reconstruite ; un disque préparé ne suffit pas")
    return reconstruit


def etape_verification(binding: RecoveryBinding, mesures: dict) -> dict:
    """5. Vérifier la remise en état — mesuré, pas supposé."""
    reconstruit = _exiger_instance_reconstruite(mesures)
    chemin = reconstruit.get("disque_reconstruit")
    controles = []
    empreinte = (empreinte_fichier(pathlib.Path(chemin))
                 if chemin and pathlib.Path(chemin).is_file() else None)
    controles.append({
        "contrôle": "le disque reconstruit est bit à bit la référence saine",
        "attendu": binding.clean_image_sha256,
        "mesure": empreinte,
        "concluant": empreinte == binding.clean_image_sha256,
    })
    preuve = reconstruit.get("disque_preuve")
    controles.append({
        "contrôle": "le disque suspect est conservé pour l'enquête",
        "chemin": preuve,
        "concluant": bool(preuve and pathlib.Path(preuve).exists()),
    })
    # Le contrôle qui manquait : l'attaquant garde-t-il un accès ?
    for r in ((mesures.get("rebuilt") or {}).get("revocations") or []):
        pc = r.get("post_condition") or {}
        if "clé d'administration" in r["accès"]:
            controles.append({
                "contrôle": "l'ancienne clé d'administration n'ouvre plus",
                "rejeu": pc.get("ancienne_rejouee"),
                "nouvelle_acceptee": pc.get("nouvelle_verifiee"),
                "concluant": pc.get("ancienne_rejouee") == "refusée",
            })
    dossier = PREUVES / binding.run_id
    scelles = sorted(p.name for p in dossier.glob("*.json")) if dossier.exists() else []
    controles.append({
        "contrôle": "les preuves des étapes précédentes sont hors de l'invité",
        "fichiers": scelles,
        "concluant": len(scelles) >= 4,
    })
    mesure = {"mur_epoch_ms": int(time.time() * 1000), "controles": controles,
              "tous_concluants": all(c["concluant"] for c in controles)}
    if not mesure["tous_concluants"]:
        rates = [c["contrôle"] for c in controles if not c["concluant"]]
        raise RepriseErreur("remise en état non vérifiée : " + " ; ".join(rates))
    return mesure


def etape_remise_en_service(binding: RecoveryBinding, mesures: dict) -> dict:
    """6. Rendre les services progressivement, avec des accès neufs.

    Rien n'est rendu accessible tant que l'étape précédente n'a pas conclu.
    L'ordre est délibéré : le témoin d'abord, la surface exposée en dernier.
    """
    _exiger_instance_reconstruite(mesures)
    if (mesures.get("verified") or {}).get("tous_concluants") is not True:
        raise RepriseErreur("remise en service interdite : vérification absente")
    paliers = [
        {"palier": 1, "service": "service documentaire témoin",
         "accès": "interne à l'invité, boucle locale",
         "condition": "intégrité des fixtures vérifiée"},
        {"palier": 2, "service": "capteurs et politique noyau",
         "accès": "root local, posé par l'exécuteur",
         "condition": "capteurs réattachés et comptés"},
        {"palier": 3, "service": "télémétrie vers le contrôleur",
         "accès": "nouvelle clé d'administration",
         "condition": "lien contrôleur rétabli, isolement WAN maintenu"},
        {"palier": 4, "service": "récepteur du laboratoire",
         "accès": "interne", "condition": "compteurs remis à zéro et scellés"},
    ]
    bundle = DOCUMENTS_UTM / f"{VM_NOM}.utm"
    return {"mur_epoch_ms": int(time.time() * 1000), "paliers": paliers,
            "rendu_effectif": False,
            "configuration_reseau_sauvegardee": str(bundle / "config.plist.avant-isolement"),
            "note": ("la remise en service effective attend la décision du "
                     "propriétaire ; ce palier enregistre l'ordre prévu et ses "
                     "conditions, il ne rouvre rien de lui-même")}


# --------------------------------------------------------------------------
# Conduite
# --------------------------------------------------------------------------

ETAPES = (
    ("proof", "conserver les preuves à l'extérieur"),
    ("isolated", "isoler depuis le contrôleur indépendant"),
    ("recovery_verified", "vérifier la référence de reprise"),
    ("rebuilt", "révoquer les accès et reconstruire"),
    ("verified", "vérifier la remise en état"),
    ("released", "rendre les services progressivement"),
)


def _empreinte_signataire() -> str:
    """Empreinte de la clé publique approuvée AVANT l'incident."""
    if not CLE_APPROUVEE.exists():
        raise RepriseErreur(
            f"clé publique du signataire absente : {CLE_APPROUVEE}. "
            "Déposer la clé approuvée avant tout incident.")
    from .recovery_contract import key_fingerprint
    from .audit_signe import serialization
    return key_fingerprint(serialization.load_pem_public_key(
        CLE_APPROUVEE.read_bytes()))


def _digest_valide(v: str) -> None:
    if len(v) != 64 or any(c not in "0123456789abcdef" for c in v):
        raise RepriseErreur(f"empreinte approuvée malformée : {v[:20]}…")


def approuver_reference() -> pathlib.Path:
    """Dépose l'empreinte de la référence AVANT tout incident.

    À faire une fois, à froid, quand on a des raisons de croire la référence
    saine. C'est cette valeur, et elle seule, qui donnera un sens à la
    comparaison le jour de la reprise.
    """
    if not REFERENCE_BOX.exists():
        raise RepriseErreur(f"référence absente : {REFERENCE_BOX}")
    APPROBATION.parent.mkdir(parents=True, exist_ok=True)
    empreinte = empreinte_fichier(REFERENCE_BOX)
    APPROBATION.write_text(
        f"{empreinte}  {REFERENCE_BOX}\n"
        f"# approuvée le {time.strftime('%Y-%m-%dT%H:%M:%S%z')}\n")
    return APPROBATION


def conduire(*, run_id: str, appliquer: bool, jusqu_a: str = "released",
             manifeste_signe=None, cle_publique=None, signer=None,
             pont=None, coupure_ms: int | None = None,
             domaine: str | None = None) -> Reprise:
    """Déroule la procédure, étape par étape, sans jamais en sauter une."""
    if not REFERENCE_BOX.exists():
        raise RepriseErreur(f"référence absente : {REFERENCE_BOX}")
    if not APPROBATION.exists():
        raise RepriseErreur(
            f"aucune empreinte approuvée avant incident dans {APPROBATION}. "
            "Déposer l'approbation d'abord (sous-commande « approuver ») : "
            "comparer la référence à une empreinte calculée maintenant ne "
            "prouverait rien.")
    empreinte_ref = APPROBATION.read_text().split()[0].strip()
    _digest_valide(empreinte_ref)
    ancrage = None
    if pont is not None:
        # Ancrage indépendant : l'approbation est relue dans la mémoire Cloud
        # avec une coupure sur le temps de connaissance, que le serveur assigne
        # et qu'un client ne peut pas antidater.
        from .ancrage_basira import verifier_approbation
        if coupure_ms is None or domaine is None:
            raise RepriseErreur(
                "ancrage Cloud demandé sans coupure temporelle ni domaine : "
                "la coupure est une connaissance humaine, on ne la devine pas")
        ancrage = verifier_approbation(pont, sha256_attendu=empreinte_ref,
                                       coupure_ms=coupure_ms, domaine=domaine)
        ancrage["source"] = "mémoire Basira, rappel TSST coupé"
        ancrage["independant"] = True
    binding = RecoveryBinding(
        run_id=run_id, vm_id=VM_UUID, target=VM_CIBLE,
        clean_image_sha256=empreinte_ref,
        institutional_key_fingerprint=_empreinte_signataire(),
    )
    mesures: dict = {}
    preuve = _preuve(binding, "proof", etape_preuve(binding))
    etat = RecoveryState(binding, preuve)
    if signer is not None and manifeste_signe is None:
        # Le manifeste est signé APRÈS la mesure de preuve, parce qu'il la
        # scelle : c'est le geste du propriétaire, une fois qu'il a vu ce que
        # le contrôleur a réellement constaté.
        manifeste_signe, cle_publique = signer(binding, preuve)
    mesures["proof"] = json.loads((PREUVES / run_id / "proof.json").read_text())

    plan = [e for e, _ in ETAPES]
    fin = plan.index(jusqu_a)
    for stage in plan[1:fin + 1]:
        if stage == "isolated":
            m = etape_isolement(binding, appliquer=appliquer)
        elif stage == "recovery_verified":
            m = etape_reference(binding, ancrage=ancrage)
        elif stage == "rebuilt":
            m = etape_reconstruction(binding, appliquer=appliquer)
        elif stage == "verified":
            m = etape_verification(binding, mesures)
        else:
            etat.require_state("verified")
            m = etape_remise_en_service(binding, mesures)
            if m.get("rendu_effectif") is not True:
                _sceller(run_id, stage, m)
                raise RepriseErreur(
                    "remise en service non effectuée : le plan de paliers "
                    "ne constitue pas une libération")
        if stage == "recovery_verified":
            # Le contrat EXIGE un manifeste signé pour cette étape, et il a
            # raison : sans signature, « référence vérifiée » ne veut rien
            # dire. On ne contourne pas la barrière — on s'arrête si le
            # manifeste manque, et on le dit.
            if manifeste_signe is None or cle_publique is None:
                _sceller(run_id, stage, {**m, "verification_realisee": False,
                                         "motif": "manifeste signé absent"})
                raise RepriseErreur(
                    "vérification de la référence NON réalisable : manifeste "
                    "signé et clé publique requis. Les étapes suivantes "
                    "(reconstruction, remise en service) restent interdites.")
            _sceller(run_id, stage, m)
            etat.advance(stage, manifest=manifeste_signe, public_key=cle_publique)
        else:
            etat.advance(stage, evidence=_preuve(binding, stage, m))
        mesures[stage] = m
    return Reprise(binding=binding, etat=etat, mesures=mesures)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--run-id", default=time.strftime("reprise-%Y%m%dT%H%M%S"))
    ap.add_argument("--jusqu-a", default="released",
                    choices=[e for e, _ in ETAPES])
    ap.add_argument("--appliquer", action="store_true",
                    help="exécute réellement isolement et reconstruction")
    ap.add_argument("--approuver", action="store_true",
                    help="dépose l'empreinte de référence (à froid, avant incident)")
    ap.add_argument("--manifeste-signe", help="manifeste signé (JSON) de la référence")
    ap.add_argument("--cle-publique", help="clé publique Ed25519 (PEM) du signataire")
    a = ap.parse_args()
    required=("SAWM_LABO_VM_UUID", "SAWM_LABO_VM_MAC", "SAWM_LABO_VM_IP", "SAWM_LABO_VM_BUNDLE", "SAWM_LABO_RECOVERY_IMAGE")
    missing=[key for key in required if not os.environ.get(key)]
    if missing: ap.error("explicit recovery configuration required: " + ", ".join(missing))
    if a.approuver:
        chemin = approuver_reference()
        print(f"empreinte de référence approuvée : {chemin}")
        print(chemin.read_text().strip())
        return 0
    manifeste_signe = cle_publique = None
    if a.manifeste_signe and a.cle_publique:
        manifeste_signe = json.loads(pathlib.Path(a.manifeste_signe).read_text())
        from .audit_signe import serialization as _ser
        cle_publique = _ser.load_pem_public_key(
            pathlib.Path(a.cle_publique).read_bytes())
    print(f"run_id : {a.run_id}   mode : "
          f"{'APPLIQUE' if a.appliquer else 'MESURE SEULE'}")
    try:
        r = conduire(run_id=a.run_id, appliquer=a.appliquer, jusqu_a=a.jusqu_a,
                     manifeste_signe=manifeste_signe, cle_publique=cle_publique)
    except RepriseErreur as e:
        print(f"ARRÊT à l'étape non mesurable : {e}")
        return 1
    for etape, libelle in ETAPES:
        if etape in r.mesures or etape == "proof":
            marque = next((d for s, d in r.etat.history if s == etape), "")
            print(f"  {etape:<18} {libelle:<42} {marque[:16]}")
    print(f"preuves scellées : {PREUVES / a.run_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
