#!/usr/bin/env python3
"""Tâche ordinaire à battements ; systemd, et non ce code, la redémarre.

--deadline-epoch est une échéance absolue commune aux redémarrages.
Configurer Restart=always et RestartPreventExitStatus=78 dans l'unité de test.
"""
from __future__ import annotations

import time
from commun import MAX_DUREE, Mesure, arguments, borne


def travailler(source_id, run_id, duree, echeance, intervalle=.25, *, racine=None):
    borne(float(duree), .05, MAX_DUREE)
    borne(float(intervalle), .05, 5)
    restant = echeance-time.time()
    if restant <= 0:
        # Empêche Restart=always de prolonger le test indéfiniment.
        with Mesure(source_id, run_id, .05, racine=racine) as m:
            m.etat.update(echeance_epoch=echeance, battements=0,
                          cause_fin='fin_naturelle_echeance')
        return 78
    borne(restant, 0, MAX_DUREE)
    with Mesure(source_id, run_id, min(duree, restant), racine=racine) as m:
        m.publier(echeance_epoch=echeance, battements=0, activite='battement_ordinaire')
        while m.actif():
            m.publier(battements=m.etat['battements']+1)
            time.sleep(min(intervalle, max(0, m.fin-time.monotonic())))
    return 0 if m.signal else 78


def main():
    p = arguments(__doc__)
    p.add_argument('--deadline-epoch', required=True, type=float)
    p.add_argument('--interval', type=float, default=.25)
    a = p.parse_args()
    try:
        return travailler(a.source_id, a.run_id, a.duration, a.deadline_epoch, a.interval)
    except (ValueError, OSError) as e:
        p.exit(2, f'{type(e).__name__}: {e}\n')


if __name__ == '__main__':
    raise SystemExit(main())
