#!/usr/bin/env python3
"""Activité de bureau ordinaire : plusieurs comptes qui travaillent vraiment.

Ce n'est pas une perturbation. C'est la BASE DE COMPARAISON sans laquelle
aucun chiffre de détection ne veut rien dire : sans activité normale, un
détecteur n'a rien à confondre, et il paraît parfait. C'est ce qui rend les
faux positifs mesurables.

Chaque compte simulé fait ce que fait un employé : il crée un tableau, le
relit, y ajoute des lignes, calcule une synthèse, renomme un brouillon en
version définitive, supprime un fichier temporaire, et parfois range des
choses dans un dossier caché — parce que les vrais outils en créent
(`.cache`, `.tmp`, `~$fichier.xlsx` de Word). Le nom d'un fichier ne suffit
jamais à décider qu'il y a une attaque, et ce jeu de données est là pour le
prouver.

Bornes : un répertoire de travail par compte sous le bac des fixtures, des
fichiers de quelques dizaines de kilo-octets, une durée maximale, et aucune
écriture hors de ce bac. Rien ici ne s'arrête tout seul pour faire joli : la
charge tourne jusqu'à son échéance ou jusqu'à ce qu'on l'arrête de l'extérieur.
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
import time

RACINE = pathlib.Path(os.environ.get("LABO_BUREAU", "/opt/sawm-labo/bureau"))
ETAT = pathlib.Path("/opt/sawm-labo/charges-etat")

# Des noms d'employés et de dossiers qui ressemblent à ceux d'une entreprise :
# si les noms du laboratoire suffisaient à reconnaître l'épreuve, la mesure ne
# vaudrait rien.
COMPTES = ["c.morel", "a.diallo", "l.bernard", "y.nakamura", "s.rossi"]
DOSSIERS = ["budget", "clients", "rh", "achats", "qualite"]
COLONNES = ["reference", "libelle", "quantite", "prix_unitaire", "marge"]


def tableau_neuf(chemin: pathlib.Path, lignes: int) -> int:
    with chemin.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(COLONNES)
        for i in range(lignes):
            w.writerow([f"REF-{i:05d}", f"article {i}",
                        random.randint(1, 400),
                        round(random.uniform(2.5, 900), 2),
                        round(random.uniform(0.02, 0.41), 3)])
    return chemin.stat().st_size


def analyser(chemin: pathlib.Path) -> dict:
    """Travail réel : on relit le fichier et on calcule. Cela produit des
    lectures disque et du temps processeur, comme une vraie analyse."""
    quantites, marges = [], []
    with chemin.open(newline="") as f:
        for ligne in csv.DictReader(f):
            try:
                quantites.append(int(ligne["quantite"]))
                marges.append(float(ligne["marge"]))
            except (KeyError, ValueError):
                continue
    if not quantites:
        return {"lignes": 0}
    return {
        "lignes": len(quantites),
        "quantite_totale": sum(quantites),
        "marge_mediane": round(statistics.median(marges), 4),
        "marge_ecart_type": round(statistics.pstdev(marges), 4),
    }


def ajouter_lignes(chemin: pathlib.Path, n: int) -> None:
    with chemin.open("a", newline="") as f:
        w = csv.writer(f)
        base = random.randint(50000, 99999)
        for i in range(n):
            w.writerow([f"REF-{base + i}", f"ajout {i}",
                        random.randint(1, 120),
                        round(random.uniform(2.5, 500), 2),
                        round(random.uniform(0.02, 0.35), 3)])


def journee(compte: str, budget_s: float, journal: pathlib.Path) -> dict:
    """Une session de travail d'un compte, bornée dans le temps."""
    espace = RACINE / compte
    cache = espace / ".cache"          # dossier caché, usage LÉGITIME
    espace.mkdir(parents=True, exist_ok=True)
    cache.mkdir(exist_ok=True)
    faits = {"compte": compte, "creations": 0, "lectures": 0, "analyses": 0,
             "ajouts": 0, "renommages": 0, "suppressions": 0,
             "ecritures_cachees": 0, "octets_ecrits": 0, "debut_ms": int(time.time() * 1000)}
    fin = time.monotonic() + budget_s
    fichiers: list[pathlib.Path] = []
    while time.monotonic() < fin:
        geste = random.choices(
            ["creer", "analyser", "ajouter", "renommer", "supprimer", "cache"],
            weights=[18, 34, 20, 10, 8, 10])[0]

        if geste == "creer" or not fichiers:
            dossier = espace / random.choice(DOSSIERS)
            dossier.mkdir(exist_ok=True)
            chemin = dossier / f"{random.choice(DOSSIERS)}-{int(time.time()*1000) % 100000}.csv"
            faits["octets_ecrits"] += tableau_neuf(chemin, random.randint(120, 900))
            faits["creations"] += 1
            fichiers.append(chemin)

        elif geste == "analyser":
            chemin = random.choice(fichiers)
            if chemin.exists():
                resultat = analyser(chemin)
                faits["lectures"] += 1
                faits["analyses"] += 1
                # Le résultat d'analyse se range dans le cache : c'est ce que
                # font les tableurs et les outils de rapport.
                sortie = cache / (chemin.stem + ".synthese.json")
                sortie.write_text(json.dumps(resultat))
                faits["ecritures_cachees"] += 1

        elif geste == "ajouter":
            chemin = random.choice(fichiers)
            if chemin.exists():
                ajouter_lignes(chemin, random.randint(5, 60))
                faits["ajouts"] += 1

        elif geste == "renommer":
            chemin = random.choice(fichiers)
            if chemin.exists() and "-v" not in chemin.stem:
                neuf = chemin.with_name(chemin.stem + "-v2.csv")
                chemin.rename(neuf)
                fichiers[fichiers.index(chemin)] = neuf
                faits["renommages"] += 1

        elif geste == "supprimer":
            # On ne supprime qu'un temporaire, comme un tableur le ferait en
            # refermant un document.
            temporaire = espace / random.choice(DOSSIERS) / f"~$doc{random.randint(1,9)}.tmp"
            temporaire.parent.mkdir(exist_ok=True)
            temporaire.write_bytes(os.urandom(2048))
            temporaire.unlink()
            faits["suppressions"] += 1

        else:  # cache
            marque = cache / f"session-{random.randint(1, 5)}.state"
            marque.write_text(json.dumps({"compte": compte,
                                          "ms": int(time.time() * 1000)}))
            faits["ecritures_cachees"] += 1

        time.sleep(random.uniform(0.15, 0.9))   # rythme humain, pas une boucle

    faits["fin_ms"] = int(time.time() * 1000)
    faits["duree_s"] = round((faits["fin_ms"] - faits["debut_ms"]) / 1000, 1)
    with journal.open("a") as f:
        f.write(json.dumps(faits, ensure_ascii=False) + "\n")
    return faits


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--comptes", type=int, default=3,
                    help="nombre de comptes simulés (1 à 5)")
    ap.add_argument("--duree", type=float, default=60.0,
                    help="durée de la session, en secondes (bornée à 900)")
    ap.add_argument("--graine", type=int, default=None)
    a = ap.parse_args()
    if a.graine is not None:
        random.seed(a.graine)
    nb = max(1, min(5, a.comptes))
    budget = max(5.0, min(900.0, a.duree))

    ETAT.mkdir(parents=True, exist_ok=True)
    journal = ETAT / "bureautique.jsonl"
    RACINE.mkdir(parents=True, exist_ok=True)

    import threading
    resultats: list[dict] = []
    fils = []
    for compte in COMPTES[:nb]:
        t = threading.Thread(target=lambda c=compte: resultats.append(
            journee(c, budget, journal)))
        t.start()
        fils.append(t)
    for t in fils:
        t.join()

    total = {k: sum(r.get(k, 0) for r in resultats)
             for k in ("creations", "lectures", "analyses", "ajouts",
                       "renommages", "suppressions", "ecritures_cachees",
                       "octets_ecrits")}
    print(json.dumps({"comptes": nb, "duree_s": budget, "par_compte": resultats,
                      "total": total}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
