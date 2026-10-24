#!/usr/bin/env python3
"""Copie bornée d'une fixture répétée vers 127.0.0.1:9009 uniquement."""
from __future__ import annotations

import socket
import time
from commun import BLOC, MAX_DEBIT, MAX_OCTETS, Mesure, arguments, borne, fixture


def copier(source_id, run_id, octets, duree, debit, nom=None, *, racine=None):
    borne(octets, 1, MAX_OCTETS)
    borne(debit, 1, MAX_DEBIT)
    with Mesure(source_id, run_id, duree, racine=racine) as m:
        with fixture(nom, racine) as (nom_fixture, st, f):
            m.publier(octets_annonces=octets, octets_envoyes=0,
                      debit_limite_bps=debit, destination='127.0.0.1:9009',
                      fixture=nom_fixture, fixture_taille_octets=st.st_size,
                      mode_donnees='lecture_fixture_repetee', octets_uniques_fixture=0,
                      repetitions_completes=0)
            envoyes, prochaine_publication = 0, 0.0
            with socket.create_connection(('127.0.0.1', 9009), timeout=min(3, duree)) as sock:
                sock.settimeout(.2)
                header = f'ANNONCE {octets} {source_id} {run_id}\n'.encode('ascii')
                sock.sendall(header)
                while envoyes < octets and m.actif():
                    bloc = f.read(min(BLOC, octets-envoyes))
                    if not bloc:
                        f.seek(0)
                        continue
                    vue = memoryview(bloc)
                    while vue and m.actif():
                        try:
                            n = sock.send(vue)
                        except socket.timeout:
                            continue
                        if n == 0:
                            raise ConnectionError('socket fermée')
                        envoyes += n
                        vue = vue[n:]
                        m.etat.update(octets_envoyes=envoyes,
                                      octets_uniques_fixture=min(envoyes, st.st_size),
                                      repetitions_completes=envoyes//st.st_size)
                        maintenant = time.monotonic()
                        if maintenant >= prochaine_publication:
                            m.publier()
                            prochaine_publication = maintenant + .25
                        # Limite réelle du débit ; fin et signaux restent contrôlés.
                        attente = m.debut + envoyes/debit - time.monotonic()
                        while attente > 0 and m.actif():
                            time.sleep(min(attente, .05, max(0, m.fin-time.monotonic())))
                            attente = m.debut + envoyes/debit - time.monotonic()
                m.etat['cause_fin'] = ('fin_naturelle_volume' if envoyes == octets
                                       else 'signal_recu' if m.signal else 'fin_naturelle_duree')
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
    return m.etat


def main():
    p = arguments(__doc__)
    p.add_argument('--bytes', dest='octets', type=int, required=True)
    p.add_argument('--rate-bps', dest='debit', type=int, required=True)
    p.add_argument('--fixture')
    a = p.parse_args()
    try:
        copier(a.source_id, a.run_id, a.octets, a.duration, a.debit, a.fixture)
    except (ValueError, OSError) as e:
        p.exit(2, f'{type(e).__name__}: {e}\n')


if __name__ == '__main__':
    main()
