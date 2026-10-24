"""Bornes et reçus des charges bénignes. Aucun verdict défensif ici."""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import pathlib
import re
import signal
import time

RACINE = pathlib.Path('/opt/sawm-labo')
MAX_DUREE = 300.0
MAX_OCTETS = 20 * 1024**3
MAX_DEBIT = 100 * 1024**2
BLOC = 65536


def identifiant(value):
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}', value or ''):
        raise argparse.ArgumentTypeError('identifiant attendu, 1 à 64 caractères')
    return value


def borne(value, minimum, maximum):
    if not minimum <= value <= maximum:
        raise ValueError(f'valeur hors bornes [{minimum}, {maximum}]')
    return value


def arguments(description):
    p = argparse.ArgumentParser(description=description)
    p.add_argument('--source-id', required=True, type=identifiant)
    p.add_argument('--run-id', required=True, type=identifiant)
    p.add_argument('--duration', type=float, required=True)
    return p


@contextlib.contextmanager
def fixture(nom=None, racine=None):
    """Ouvre seulement une fixture régulière, sans lien ni sous-répertoire."""
    base = (racine or RACINE) / 'fixtures'
    fd_base = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fd = None
    try:
        if nom is None:
            noms = sorted(n for n in os.listdir(fd_base) if n.endswith('.txt'))
            if not noms:
                raise ValueError('aucune fixture .txt')
            nom = noms[0]
        if nom in ('.', '..') or pathlib.Path(nom).name != nom:
            raise ValueError('fixture doit être un nom simple')
        fd = os.open(nom, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd_base)
        import stat
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size <= 0:
            raise ValueError('fixture régulière non vide et sans lien multiple requise')
        with os.fdopen(fd, 'rb') as f:
            fd = None
            yield nom, st, f
    finally:
        if fd is not None:
            os.close(fd)
        os.close(fd_base)


class Mesure:
    def __init__(self, source_id, run_id, duree, *, racine=None):
        self.source_id, self.run_id = identifiant(source_id), identifiant(run_id)
        self.duree = borne(float(duree), .05, MAX_DUREE)
        self.debut = time.monotonic()
        self.cpu_debut = time.process_time()
        self.fin = self.debut + self.duree
        self.signal = None
        self.dossier = (racine or RACINE) / 'charges-etat'
        self.dossier.mkdir(mode=0o755, parents=True, exist_ok=True)
        if self.dossier.is_symlink():
            raise ValueError('répertoire état symbolique refusé')
        self.lock_fd = os.open(self.dossier / f'{source_id}.lock',
                               os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(self.lock_fd)
            raise
        self.etat = dict(schema='sawm-lab-charge/v1', source_id=source_id,
                         run_id=run_id, pid=os.getpid(), debut_epoch_ms=int(time.time()*1000),
                         duree_max_s=self.duree, termine=False, cause_fin=None,
                         attribution_arret='non_etablie')
        self.anciens = {}

    def __enter__(self):
        for s in (signal.SIGINT, signal.SIGTERM):
            self.anciens[s] = signal.signal(s, self._signal)
        self.publier()
        return self

    def _signal(self, numero, _frame):
        self.signal = numero

    def actif(self):
        return self.signal is None and time.monotonic() < self.fin

    def publier(self, **champs):
        self.etat.update(champs, echantillon_epoch_ms=int(time.time()*1000),
                         ecoule_s=round(time.monotonic()-self.debut, 6),
                         cpu_processus_s=round(time.process_time()-self.cpu_debut, 6))
        tmp = self.dossier / f'.{self.source_id}.{os.getpid()}.tmp'
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(self.etat, f, ensure_ascii=False)
                f.flush()
            os.replace(tmp, self.dossier / f'{self.source_id}.json')
        finally:
            tmp.unlink(missing_ok=True)

    def __exit__(self, exc_type, exc, _tb):
        cause = ('erreur' if exc else 'signal_recu' if self.signal else
                 self.etat.get('cause_fin') or
                 ('fin_naturelle_duree' if time.monotonic() >= self.fin else 'fin_normale'))
        try:
            self.publier(termine=True, cause_fin=cause, signal_recu=self.signal,
                         erreur=type(exc).__name__ if exc else None)
        finally:
            for s, ancien in self.anciens.items():
                signal.signal(s, ancien)
            os.close(self.lock_fd)
        print(json.dumps(self.etat, ensure_ascii=False), flush=True)
