#!/usr/bin/env python3
"""Équipe comptable au travail : cinq postes, des écritures, un rapprochement.

Ce n'est pas une perturbation, c'est la BASE DE COMPARAISON. Sans activité
normale, un détecteur n'a rien à confondre : il paraît parfait parce qu'il n'a
jamais eu l'occasion de se tromper. C'est ce jeu-là qui rend les faux positifs
mesurables.

Cinq postes, avec les gestes réels du métier :

  fournisseurs   saisit des factures d'achat, contrôle la TVA déductible
  clients        émet des factures de vente, suit les encaissements
  banque         importe des relevés et rapproche lignes bancaires et écritures
  controle       calcule des agrégats budgétaires, produit des synthèses
  chef           clôture : relit le grand livre, vérifie l'équilibre, archive

Chacun crée, relit, complète, renomme un brouillon en version définitive,
supprime ses temporaires, et écrit dans des dossiers cachés — parce que les
vrais tableurs en créent (`.~lock`, `~$fichier`, `.cache`). Le nom d'un fichier
ne suffira jamais à conclure qu'il y a une attaque, et ce jeu le prouve.

Bornes : tout sous `/opt/sawm-labo/comptabilite`, fichiers de quelques dizaines
de kilo-octets, durée maximale, aucune écriture hors de ce bac. La charge ne
s'arrête jamais d'elle-même avant son échéance : si elle s'arrêtait seule, son
arrêt pourrait être crédité à tort à une défense.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import pathlib
import random
import statistics
import sys
import threading
import time

RACINE = pathlib.Path(os.environ.get("LABO_COMPTA", "/opt/sawm-labo/comptabilite"))
ETAT = pathlib.Path("/opt/sawm-labo/charges-etat")

POSTES = ["fournisseurs", "clients", "banque", "controle", "chef"]
COMPTES = {
    "fournisseurs": "m.leroy", "clients": "s.benali", "banque": "p.girard",
    "controle": "n.olsen", "chef": "f.moreau",
}
JOURNAUX = ["achats", "ventes", "banque", "od", "caisse"]
TVA = [0.0, 0.055, 0.10, 0.20]
FOURNISSEURS = ["Papeterie Vaugirard", "Cloud Nord SAS", "Transports Béryl",
                "Ateliers Kermes", "Énergie Saint-Loup"]
CLIENTS = ["Groupe Farelle", "Institut Marbot", "Cabinet Vigne",
           "Société Lannoy", "Comptoir Ardent"]


def _piece(numero: int, sens: str) -> dict:
    ht = round(random.uniform(35, 12_000), 2)
    taux = random.choice(TVA)
    tiers = random.choice(FOURNISSEURS if sens == "achat" else CLIENTS)
    return {
        "piece": f"{'FA' if sens == 'achat' else 'FV'}-{numero:06d}",
        "journal": "achats" if sens == "achat" else "ventes",
        "tiers": tiers,
        "ht": ht,
        "taux_tva": taux,
        "tva": round(ht * taux, 2),
        "ttc": round(ht * (1 + taux), 2),
        "echeance_jours": random.choice([0, 30, 45, 60]),
    }


def ecrire_journal(chemin: pathlib.Path, lignes: list[dict]) -> int:
    neuf = not chemin.exists()
    with chemin.open("a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(lignes[0].keys()))
        if neuf:
            w.writeheader()
        w.writerows(lignes)
    return chemin.stat().st_size


def relire(chemin: pathlib.Path) -> list[dict]:
    """Travail réel : on relit le fichier. Cela produit de vraies lectures."""
    with chemin.open(newline="") as f:
        return list(csv.DictReader(f))


def poste_fournisseurs(espace: pathlib.Path, faits: dict) -> None:
    chemin = espace / "achats.csv"
    lot = [_piece(random.randint(1, 999_999), "achat")
           for _ in range(random.randint(3, 14))]
    faits["octets_ecrits"] += ecrire_journal(chemin, lot)
    faits["ecritures"] += len(lot)
    # Contrôle de TVA déductible : on relit et on recalcule.
    lignes = relire(chemin)
    faits["lectures"] += 1
    total = sum(float(l["tva"]) for l in lignes if l.get("tva"))
    (espace / ".cache").mkdir(exist_ok=True)
    (espace / ".cache" / "tva-deductible.json").write_text(
        json.dumps({"lignes": len(lignes), "tva_totale": round(total, 2)}))
    faits["ecritures_cachees"] += 1


def poste_clients(espace: pathlib.Path, faits: dict) -> None:
    chemin = espace / "ventes.csv"
    lot = [_piece(random.randint(1, 999_999), "vente")
           for _ in range(random.randint(2, 11))]
    faits["octets_ecrits"] += ecrire_journal(chemin, lot)
    faits["ecritures"] += len(lot)
    # Suivi des encaissements : brouillon, puis version définitive.
    brouillon = espace / f"relance-brouillon-{random.randint(100, 999)}.csv"
    with brouillon.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["piece", "tiers", "ttc", "retard_jours"])
        for l in relire(chemin)[-8:]:
            w.writerow([l["piece"], l["tiers"], l["ttc"],
                        random.randint(0, 75)])
    faits["lectures"] += 1
    definitif = brouillon.with_name(brouillon.name.replace("brouillon", "v1"))
    brouillon.rename(definitif)
    faits["renommages"] += 1


def poste_banque(espace: pathlib.Path, faits: dict) -> None:
    """Import d'un relevé et rapprochement : beaucoup de lecture, peu d'écriture."""
    releve = espace / "releve-bancaire.csv"
    lignes = [{"date_ope": f"2026-09-{random.randint(1, 23):02d}",
               "libelle": random.choice(FOURNISSEURS + CLIENTS),
               "montant": round(random.uniform(-9000, 9000), 2)}
              for _ in range(random.randint(5, 20))]
    faits["octets_ecrits"] += ecrire_journal(releve, lignes)
    faits["ecritures"] += len(lignes)
    rapproches = 0
    for source in ("achats.csv", "ventes.csv"):
        chemin = espace / source
        if chemin.exists():
            ecritures = relire(chemin)
            faits["lectures"] += 1
            montants = {round(abs(float(e["ttc"])), 2) for e in ecritures
                        if e.get("ttc")}
            rapproches += sum(1 for l in lignes
                              if round(abs(l["montant"]), 2) in montants)
    (espace / ".cache").mkdir(exist_ok=True)
    (espace / ".cache" / "rapprochement.json").write_text(
        json.dumps({"lignes_releve": len(lignes), "rapprochees": rapproches}))
    faits["ecritures_cachees"] += 1
    faits["rapprochements"] += 1


def poste_controle(espace: pathlib.Path, faits: dict) -> None:
    """Analyse budgétaire : lecture large, calcul, synthèse."""
    montants = []
    for source in ("achats.csv", "ventes.csv"):
        chemin = espace / source
        if chemin.exists():
            for l in relire(chemin):
                try:
                    montants.append(float(l["ht"]))
                except (KeyError, ValueError):
                    continue
            faits["lectures"] += 1
    if not montants:
        return
    synthese = {
        "pieces": len(montants),
        "ht_total": round(sum(montants), 2),
        "ht_median": round(statistics.median(montants), 2),
        "ht_ecart_type": round(statistics.pstdev(montants), 2),
    }
    sortie = espace / "synthese-budgetaire.json"
    sortie.write_text(json.dumps(synthese, ensure_ascii=False))
    faits["analyses"] += 1
    faits["octets_ecrits"] += sortie.stat().st_size


def poste_chef(espace: pathlib.Path, faits: dict) -> None:
    """Clôture : relecture du grand livre, contrôle d'équilibre, archivage."""
    total_debit = total_credit = 0.0
    for source in ("achats.csv", "ventes.csv"):
        chemin = espace / source
        if not chemin.exists():
            continue
        for l in relire(chemin):
            try:
                ttc = float(l["ttc"])
            except (KeyError, ValueError):
                continue
            if l.get("journal") == "achats":
                total_debit += ttc
            else:
                total_credit += ttc
        faits["lectures"] += 1
    archive = espace / "archives"
    archive.mkdir(exist_ok=True)
    cloture = archive / f"cloture-{int(time.time()) % 100000}.json"
    cloture.write_text(json.dumps({
        "debit": round(total_debit, 2), "credit": round(total_credit, 2),
        "solde": round(total_credit - total_debit, 2),
    }))
    faits["clotures"] += 1
    # Un tableur laisse des verrous et des temporaires ; on les nettoie.
    verrou = espace / f".~lock.grand-livre.ods#"
    verrou.write_text(f"poste=chef,pid={os.getpid()}")
    faits["ecritures_cachees"] += 1
    verrou.unlink()
    faits["suppressions"] += 1


GESTES = {
    "fournisseurs": poste_fournisseurs, "clients": poste_clients,
    "banque": poste_banque, "controle": poste_controle, "chef": poste_chef,
}


def travailler(poste: str, budget_s: float, journal: pathlib.Path) -> dict:
    espace = RACINE / COMPTES[poste]
    espace.mkdir(parents=True, exist_ok=True)
    faits = {"poste": poste, "compte": COMPTES[poste], "ecritures": 0,
             "lectures": 0, "analyses": 0, "rapprochements": 0, "clotures": 0,
             "renommages": 0, "suppressions": 0, "ecritures_cachees": 0,
             "octets_ecrits": 0, "erreurs": 0,
             "debut_ms": int(time.time() * 1000)}
    fin = time.monotonic() + budget_s
    while time.monotonic() < fin:
        try:
            GESTES[poste](espace, faits)
        except Exception:
            faits["erreurs"] += 1
        time.sleep(random.uniform(0.4, 2.2))    # rythme humain
    faits["fin_ms"] = int(time.time() * 1000)
    faits["duree_s"] = round((faits["fin_ms"] - faits["debut_ms"]) / 1000, 1)
    with journal.open("a") as f:
        f.write(json.dumps(faits, ensure_ascii=False) + "\n")
    return faits


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--postes", type=int, default=5)
    ap.add_argument("--duree", type=float, default=90.0,
                    help="secondes, borné à 900")
    ap.add_argument("--graine", type=int, default=None)
    a = ap.parse_args()
    if a.graine is not None:
        random.seed(a.graine)
    nb = max(1, min(len(POSTES), a.postes))
    budget = max(5.0, min(900.0, a.duree))

    ETAT.mkdir(parents=True, exist_ok=True)
    RACINE.mkdir(parents=True, exist_ok=True)
    journal = ETAT / "equipe-comptable.jsonl"

    resultats: list[dict] = []
    fils = []
    for poste in POSTES[:nb]:
        t = threading.Thread(
            target=lambda p=poste: resultats.append(
                travailler(p, budget, journal)))
        t.start()
        fils.append(t)
    for t in fils:
        t.join()

    cles = ("ecritures", "lectures", "analyses", "rapprochements", "clotures",
            "renommages", "suppressions", "ecritures_cachees",
            "octets_ecrits", "erreurs")
    total = {k: sum(r.get(k, 0) for r in resultats) for k in cles}
    print(json.dumps({"postes": nb, "duree_s": budget,
                      "par_poste": resultats, "total": total},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
