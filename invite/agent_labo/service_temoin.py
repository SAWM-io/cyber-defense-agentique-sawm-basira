#!/usr/bin/env python3
"""Service legitime du laboratoire : l'application documentaire fictive.

C'est le TEMOIN. Sa disponibilite et sa latence sont la mesure qui empeche de
confondre « defendu » avec « coupe ». Bloquer tout le serveur n'est pas une
reussite : si ce service tombe pendant une intervention, l'intervention a un
cout, et ce cout doit apparaitre.

Il fait un vrai travail : il lit les fixtures sur disque a chaque requete, ce
qui le rend sensible a une saturation d'E/S, a une charge CPU et a une regle
de refus posee sur une fixture — exactement ce qu'on veut pouvoir constater.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import random
import sys
import time
import jetons
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FIXTURES = pathlib.Path(os.environ.get("LABO_FIXTURES", "/opt/sawm-labo/fixtures"))
# Etat des jetons applicatifs. La REVOCATION se fait par increment de version :
# supprimer une ligne laisserait vivre les jetons deja emis, incrementer la
# version les invalide TOUS d'un coup, y compris ceux qu'on ne connait pas.
JETONS = pathlib.Path(os.environ.get("LABO_JETONS", "/opt/sawm-labo/jetons.json"))
ECOUTE = ("127.0.0.1", int(os.environ.get("LABO_TEMOIN_PORT", "8080")))
DEBUT = time.monotonic()

compteurs = {"requetes": 0, "erreurs": 0, "octets_lus": 0, "refus_noyau": 0,
             "jetons_refuses": 0}


def version_courante() -> int | None:
    """Une configuration absente ou invalide n'autorise aucun jeton."""
    try:
        return jetons.version_courante()
    except (OSError, ValueError, TypeError, KeyError):
        return None


def jeton_valide(entete: str | None) -> tuple[bool, str]:
    """La version et la signature HMAC sont toutes deux obligatoires."""
    ok = jetons.verifier(entete)
    return ok, "ok" if ok else "jeton absent, invalide ou révoqué"


class App(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _json(self, code: int, objet: dict) -> None:
        corps = json.dumps(objet, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(corps)))
        self.end_headers()
        self.wfile.write(corps)

    def do_GET(self):
        compteurs["requetes"] += 1
        t0 = time.monotonic()
        if self.path.startswith("/sante"):
            self._json(200, {
                "etat": "vivant",
                "uptime_s": round(time.monotonic() - DEBUT, 1),
                "version_jeton": version_courante(),
                **compteurs,
            })
            return
        if self.path.startswith("/document"):
            # /sante reste ouvert : la telemetrie doit pouvoir constater la
            # disponibilite meme quand les jetons viennent de tourner.
            ok, motif = jeton_valide(self.headers.get("X-Labo-Jeton"))
            if not ok:
                compteurs["erreurs"] += 1
                compteurs["jetons_refuses"] += 1
                self._json(401, {"erreur": "acces refuse", "motif": motif,
                                 "version_en_vigueur": version_courante()})
                return
            # Travail reel : lecture d'une fixture au hasard, empreinte calculee.
            fichiers = sorted(FIXTURES.glob("*.txt"))
            if not fichiers:
                compteurs["erreurs"] += 1
                self._json(503, {"erreur": "aucune fixture"})
                return
            f = random.choice(fichiers)
            try:
                donnees = f.read_bytes()
            except PermissionError as e:
                # Cas qui compte : une politique de refus du noyau frappe ce
                # service. Il doit le DIRE, pas mourir en silence.
                compteurs["erreurs"] += 1
                compteurs["refus_noyau"] += 1
                self._json(403, {"erreur": "refus du noyau", "fichier": f.name,
                                 "errno": e.errno, "detail": e.strerror})
                return
            except OSError as e:
                compteurs["erreurs"] += 1
                self._json(500, {"erreur": type(e).__name__, "fichier": f.name})
                return
            compteurs["octets_lus"] += len(donnees)
            self._json(200, {
                "fichier": f.name, "octets": len(donnees),
                "empreinte": hashlib.sha256(donnees).hexdigest()[:16],
                "service_ms": round((time.monotonic() - t0) * 1000, 2),
            })
            return
        self._json(404, {"erreur": "route inconnue"})


def main() -> int:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    srv = ThreadingHTTPServer(ECOUTE, App)
    print(f"service temoin sur http://{ECOUTE[0]}:{ECOUTE[1]}/sante", flush=True)
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
