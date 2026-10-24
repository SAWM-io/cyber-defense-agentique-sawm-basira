#!/usr/bin/env python3
"""Calcul SHA256 bénin borné à un processus, un pourcentage et une durée."""
import hashlib
import time
from commun import Mesure, arguments, borne


def charger(source_id, run_id, duree, pourcentage, *, racine=None):
    borne(pourcentage, 1, 100)
    with Mesure(source_id, run_id, duree, racine=racine) as m:
        bloc, tours = b'x'*4096, 0
        m.publier(duty_pct=pourcentage, iterations=0)
        prochain = 0
        while m.actif():
            debut = time.monotonic()
            fin_calcul = min(m.fin, debut + .05*pourcentage/100)
            while time.monotonic() < fin_calcul and m.actif():
                hashlib.sha256(bloc).digest()
                tours += 1
            if time.monotonic() >= prochain:
                m.publier(iterations=tours)
                prochain = time.monotonic()+.25
            repos = min(m.fin-time.monotonic(), debut+.05-time.monotonic())
            if repos > 0:
                time.sleep(repos)
        m.etat['iterations'] = tours
    return m.etat


def main():
    p = arguments(__doc__)
    p.add_argument('--duty-pct', type=int, required=True)
    a = p.parse_args()
    try:
        charger(a.source_id, a.run_id, a.duration, a.duty_pct)
    except (ValueError, OSError) as e:
        p.exit(2, f'{type(e).__name__}: {e}\n')


if __name__ == '__main__':
    main()
