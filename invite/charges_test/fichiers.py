#!/usr/bin/env python3
"""Créations/lectures/renommages/suppressions bénins, 4 KiB sous fixtures."""
import os
import time
from commun import Mesure, RACINE, arguments


def exercer(source_id, run_id, duree, cache=False, *, racine=None):
    base = (racine or RACINE)/'fixtures'
    with Mesure(source_id, run_id, duree, racine=racine) as m:
        fd_base = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        nom = ('.' if cache else '') + f'activite-{source_id}-{run_id}'
        fd = None
        try:
            # Pas de reprise d'un répertoire fourni par un tiers.
            os.mkdir(nom, mode=0o700, dir_fd=fd_base)
            fd = os.open(nom, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd_base)
            tours = 0
            m.publier(repertoire=nom, cycles=0, octets_ecrits=0)
            while m.actif():
                f = os.open('a.txt', os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                            0o600, dir_fd=fd)
                with os.fdopen(f, 'wb') as out:
                    out.write(b'fixture ordinaire\n'.ljust(4096, b'.'))
                os.rename('a.txt', 'b.txt', src_dir_fd=fd, dst_dir_fd=fd)
                f = os.open('b.txt', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                with os.fdopen(f, 'rb') as entree:
                    entree.read(4096)
                os.unlink('b.txt', dir_fd=fd)
                tours += 1
                m.publier(cycles=tours, octets_ecrits=tours*4096)
                time.sleep(min(.25, max(0, m.fin-time.monotonic())))
        finally:
            if fd is not None:
                os.close(fd)
            os.close(fd_base)
    return m.etat


def main():
    p = arguments(__doc__)
    p.add_argument('--hidden', action='store_true')
    a = p.parse_args()
    try:
        exercer(a.source_id, a.run_id, a.duration, a.hidden)
    except (ValueError, OSError) as e:
        p.exit(2, f'{type(e).__name__}: {e}\n')


if __name__ == '__main__':
    main()
