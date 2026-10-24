"""SQLite synthétique, bornée et locale pour l'épreuve de défense.

La CLI n'accepte aucun chemin. Elle ne touche que ledger.sqlite dans
/opt/sawm-labo/fixtures/database-defense/run-<id>. Aucun réseau, service,
redémarrage, véritable fichier métier ou attribution d'arrêt à SAWM.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import math
import os
import pathlib
import re
import signal
import sqlite3
import stat
import time

RACINE = pathlib.Path('/opt/sawm-labo')
MAX_DURATION = 180
MAX_DATABASE_BYTES = 1024 * 1024
MAX_STATE_BYTES = 8192
APPLICATION_ID = 0x5341574D
SCHEMA = 'sawm-database-defense/v1'
LEDGER = 'ledger.sqlite'
REFERENCE = 'ledger.reference.sqlite'
BEFORE_RESTORE = 'ledger.before-restore.sqlite'


def identifiant(value):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', value or ''):
        raise ValueError('identifiant attendu : 1 à 64 lettres, chiffres, _ ou -')
    return value


def duree(value):
    value = float(value)
    if not math.isfinite(value) or not 1 <= value <= MAX_DURATION:
        raise ValueError('durée requise entre 1 et 180 secondes')
    return value


def _directory(parent, name, *, create=False, private=False):
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
        except FileExistsError:
            pass
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    st = os.fstat(fd)
    if private and (st.st_uid != os.geteuid() or st.st_mode & 0o022):
        os.close(fd)
        raise ValueError('répertoire fixture non privé ou mauvais propriétaire')
    return fd


class _Run:
    """Résolution composant par composant, sans suivre aucun lien symbolique.

    `racine` est uniquement un point d'injection des tests Python, jamais une
    option CLI ou une variable d'environnement. Les répertoires de la fixture
    appartiennent à l'utilisateur effectif et ne sont pas modifiables par autrui.
    """
    def __init__(self, run_id, *, racine=None, prepare=False):
        self.run_id = identifiant(run_id)
        base = pathlib.Path(racine if racine is not None else RACINE)
        if not base.is_absolute() or '..' in base.parts:
            raise ValueError('racine absolue requise')
        self.path = base / 'fixtures' / 'database-defense' / f'run-{self.run_id}'
        self.fd = None
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in base.parts[1:]:
                child = _directory(parent, part)
                os.close(parent)
                parent = child
            st = os.fstat(parent)
            if st.st_uid != os.geteuid() or st.st_mode & 0o022:
                raise ValueError('racine fixture non privée ou mauvais propriétaire')
            for part in ('fixtures', 'database-defense'):
                child = _directory(parent, part, create=prepare, private=True)
                os.close(parent)
                parent = child
            if prepare:
                # Un run existant n'est jamais réinitialisé : ses preuves restent.
                os.mkdir(f'run-{self.run_id}', 0o700, dir_fd=parent)
            self.fd = _directory(parent, f'run-{self.run_id}', private=True)
        finally:
            os.close(parent)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        os.close(self.fd)

    def open(self, name, flags=os.O_RDONLY, *, limit=MAX_DATABASE_BYTES):
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=self.fd)
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > limit
                or st.st_uid != os.geteuid() or st.st_mode & 0o022):
            os.close(fd)
            raise ValueError('fichier fixture régulier, borné et privé requis')
        return fd

    def sha(self, name):
        with os.fdopen(self.open(name), 'rb') as stream:
            digest = hashlib.sha256()
            total = 0
            while data := stream.read(65536):
                total += len(data)
                if total > MAX_DATABASE_BYTES:
                    raise ValueError('fichier fixture trop grand')
                digest.update(data)
            return digest.hexdigest()

    def json(self, name):
        with os.fdopen(self.open(name, limit=MAX_STATE_BYTES), 'r') as stream:
            data = stream.read(MAX_STATE_BYTES + 1)
            if len(data) > MAX_STATE_BYTES:
                raise ValueError('reçu fixture trop grand')
            return json.loads(data)

    def receipt(self, name, value, *, exclusive=False, readonly=False):
        data = json.dumps(value, sort_keys=True).encode('utf-8')
        if len(data) > MAX_STATE_BYTES:
            raise ValueError('reçu trop grand')
        if exclusive:
            fd = self.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
                if readonly:
                    os.fchmod(stream.fileno(), 0o400)
        else:
            # Nom fixe : espace disque borné, remplacement d'un reçu incomplet.
            tmp = f'.{name}.tmp'
            fd = self.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            try:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(tmp, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
                os.fsync(self.fd)
            finally:
                try:
                    os.unlink(tmp, dir_fd=self.fd)
                except FileNotFoundError:
                    pass

    def copy(self, source, destination, *, readonly=False):
        with os.fdopen(self.open(source), 'rb') as src:
            fd = self.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            with os.fdopen(fd, 'wb') as dst:
                total = 0
                while data := src.read(65536):
                    total += len(data)
                    if total > MAX_DATABASE_BYTES:
                        raise ValueError('fichier fixture trop grand')
                    dst.write(data)
                dst.flush()
                os.fsync(dst.fileno())
                if readonly:
                    os.fchmod(dst.fileno(), 0o400)
        os.fsync(self.fd)

    def reference(self):
        manifest = self.json('manifest.json')
        if (not isinstance(manifest, dict) or manifest.get('schema') != SCHEMA
                or manifest.get('run_id') != self.run_id
                or manifest.get('synthetic_rows') != 100
                or not isinstance(manifest.get('reference_sha256'), str)
                or not re.fullmatch(r'[0-9a-f]{64}', manifest.get('reference_sha256', ''))):
            raise ValueError('manifeste fixture invalide')
        reference_sha = self.sha(REFERENCE)
        if reference_sha != manifest['reference_sha256']:
            raise ValueError('référence fixture modifiée')
        return reference_sha

    @contextlib.contextmanager
    def operation(self):
        fd = self.open('operation.lock', os.O_RDWR | os.O_CREAT)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    @contextlib.contextmanager
    def connect(self, *, readonly=False):
        # Les fichiers auxiliaires SQLite ne peuvent pas pointer hors de la fixture.
        for suffix in ('-journal', '-wal', '-shm'):
            try:
                fd = self.open(LEDGER + suffix)
            except FileNotFoundError:
                continue
            else:
                os.close(fd)
        pinned = self.open(LEDGER)
        conn = None
        try:
            uri = (self.path / LEDGER).as_uri() + ('?mode=ro' if readonly else '?mode=rw')
            conn = sqlite3.connect(uri, uri=True, timeout=0.1, isolation_level=None)
            conn.execute('PRAGMA trusted_schema=OFF')
            conn.execute('PRAGMA busy_timeout=100')
            yield conn
        finally:
            if conn is not None:
                conn.close()
            # Ne pas fermer de fd ledger durant un verrou SQLite du même processus.
            os.close(pinned)


def _base(run, command):
    return dict(schema=SCHEMA, command=command, run_id=run.run_id, pid=os.getpid(),
                fixture=str(run.path / LEDGER), observed_epoch_ms=int(time.time() * 1000),
                attribution_arret='non_etablie')


def prepare(run_id, *, racine=None):
    with _Run(run_id, racine=racine, prepare=True) as run, run.operation():
        os.close(run.open(LEDGER, os.O_WRONLY | os.O_CREAT | os.O_EXCL))
        with run.connect() as conn:
            conn.execute('PRAGMA journal_mode=DELETE')
            conn.execute('PRAGMA max_page_count=256')
            conn.execute(f'PRAGMA application_id={APPLICATION_ID}')
            conn.execute('PRAGMA user_version=1')
            conn.execute('BEGIN EXCLUSIVE')
            conn.execute('CREATE TABLE ledger (entry_id INTEGER PRIMARY KEY '
                         'CHECK(entry_id BETWEEN 1 AND 100), account TEXT NOT NULL, '
                         'amount_cents INTEGER NOT NULL, note TEXT NOT NULL)')
            conn.executemany('INSERT INTO ledger VALUES (?, ?, ?, ?)',
                             [(i, f'synthetic-account-{i:03}', i * 100, 'synthetic-fixture')
                              for i in range(1, 101)])
            conn.execute('COMMIT')
        run.copy(LEDGER, REFERENCE, readonly=True)
        result = _base(run, 'prepare') | dict(synthetic_rows=100, prepared=True,
                                            reference_sha256=run.sha(REFERENCE))
        run.receipt('manifest.json', result, exclusive=True, readonly=True)
        return result


def _error(exc):
    # Aucune page SQLite ni contenu arbitraire dans les preuves ou stdout.
    sqlite_name = getattr(exc, 'sqlite_errorname', None)
    if sqlite_name:
        return sqlite_name
    if isinstance(exc, sqlite3.Error):
        # Python 3.10 n'expose pas sqlite_errorname : vocabulaire fermé, jamais
        # de texte d'erreur libre ni confusion entre verrou et corruption.
        known = {
            'database is locked': 'SQLITE_BUSY',
            'database table is locked': 'SQLITE_LOCKED',
            'database schema is locked': 'SQLITE_LOCKED',
            'file is not a database': 'SQLITE_NOTADB',
            'database disk image is malformed': 'SQLITE_CORRUPT',
            'attempt to write a readonly database': 'SQLITE_READONLY',
            'unable to open database file': 'SQLITE_CANTOPEN',
            'database or disk is full': 'SQLITE_FULL',
        }
        return known.get(str(exc), type(exc).__name__)
    return type(exc).__name__


def status(run_id, *, racine=None):
    with _Run(run_id, racine=racine) as run:
        reference_sha = run.reference()
        before = run.sha(LEDGER)
        result = _base(run, 'status') | dict(read_available=False, write_available=False,
            integrity_check=None, sha256=before, reference_sha256=reference_sha,
            reference_matches=before == reference_sha, errors={})
        try:
            with run.connect(readonly=True) as conn:
                deadline = time.monotonic() + 1
                conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
                conn.execute('SELECT COUNT(*) FROM ledger').fetchone()
                result['read_available'] = True
                rows = conn.execute('PRAGMA integrity_check(1)').fetchall()
                result['integrity_check'] = 'ok' if rows == [('ok',)] else 'failed'
        except (sqlite3.Error, OSError, ValueError) as exc:
            result['errors']['read'] = _error(exc)
        try:
            with run.connect() as conn:
                conn.execute('BEGIN IMMEDIATE')
                # Une vraie écriture annulée prouve l'accès ; BEGIN seul ne suffit pas.
                cur = conn.execute('UPDATE ledger SET amount_cents=amount_cents WHERE entry_id=1')
                conn.execute('ROLLBACK')
                result['write_available'] = cur.rowcount == 1
        except (sqlite3.Error, OSError, ValueError) as exc:
            result['errors']['write'] = _error(exc)
        result['sha256'] = run.sha(LEDGER)
        result['hash_stable_during_probe'] = before == result['sha256']
        result['reference_matches'] = result['sha256'] == reference_sha
        return result


def lock(run_id, duration, *, source_id=None, racine=None):
    duration = duree(duration)
    source_id = identifiant(source_id or 'ledger')
    with _Run(run_id, racine=racine) as run, run.operation():
        run.reference()
        result = _base(run, 'lock') | dict(source_id=source_id, duration_max_s=duration,
            locked=False, termine=False, cause_fin=None, signal_recu=None)
        received = []
        previous = {}
        start = time.monotonic()
        try:
            for number in (signal.SIGINT, signal.SIGTERM):
                previous[number] = signal.signal(number, lambda sig, _frame: received.append(sig))
            with run.connect() as conn:
                # DELETE journal préparé : EXCLUSIVE empêche bien lecture ET écriture.
                if conn.execute('PRAGMA journal_mode').fetchone() != ('delete',):
                    raise ValueError('mode journal DELETE obligatoire')
                conn.execute('BEGIN EXCLUSIVE')
                result['locked'] = True
                run.receipt('lock.json', result)
                print(json.dumps(result, sort_keys=True), flush=True)
                while not received and time.monotonic() - start < duration:
                    time.sleep(min(0.1, max(0, duration - (time.monotonic() - start))))
                conn.execute('ROLLBACK')
            result.update(locked=False, termine=True,
                cause_fin='signal_recu' if received else 'fin_naturelle_duree',
                signal_recu=received[0] if received else None)
        except BaseException as exc:
            result.update(locked=False, termine=True, cause_fin='erreur', erreur=_error(exc))
            raise
        finally:
            result['ecoule_s'] = round(time.monotonic() - start, 6)
            try:
                run.receipt('lock.json', result)
            finally:
                for number, handler in previous.items():
                    signal.signal(number, handler)
        return result


def tamper(run_id, duration=None, *, source_id=None, racine=None):
    duration = duree(duration) if duration is not None else None
    source_id = identifiant(source_id or 'ledger')
    with _Run(run_id, racine=racine) as run, run.operation():
        reference_sha = run.reference()
        if run.sha(LEDGER) != reference_sha:
            raise ValueError('altération autorisée seulement sur la fixture originale')
        result = _base(run, 'tamper') | dict(max_changed_rows=1, changed_rows=0,
            max_mutations=20 if duration is not None else 1, mutations=0,
            source_id=source_id, duration_max_s=duration, mutation_interval_s=5,
            termine=False, cause_fin=None, signal_recu=None, before_sha256=reference_sha,
            reference_sha256=reference_sha)
        # Une seule tentative par run, même après restauration ou erreur.
        run.receipt('tamper.json', result, exclusive=True)
        received = []
        previous = {}
        start = time.monotonic()
        next_mutation = start
        # Liaison observable PID/fichier pendant toute la charge, y compris entre
        # deux commits. Un fd ouvert seul ne prouve jamais la causalité du delta.
        held_fd = run.open(LEDGER, os.O_RDWR)
        try:
            for number in (signal.SIGINT, signal.SIGTERM):
                previous[number] = signal.signal(number, lambda sig, _frame: received.append(sig))
            while not received:
                now = time.monotonic()
                if duration is not None and now - start >= duration:
                    break
                if now >= next_mutation and result['mutations'] < result['max_mutations']:
                    with run.connect() as conn:
                        if conn.execute('PRAGMA application_id').fetchone() != (APPLICATION_ID,):
                            raise ValueError('base non synthétique refusée')
                        conn.execute('BEGIN EXCLUSIVE')
                        cur = conn.execute("UPDATE ledger SET amount_cents=amount_cents+1 "
                                           "WHERE entry_id=1 AND note='synthetic-fixture'")
                        if cur.rowcount != 1 or conn.execute('SELECT COUNT(*) FROM ledger').fetchone() != (100,):
                            raise ValueError('fixture attendue de 100 lignes, une modification au maximum')
                        conn.execute('COMMIT')
                    result.update(changed_rows=1, mutations=result['mutations'] + 1,
                                  sha256=run.sha(LEDGER))
                    if result['sha256'] == reference_sha:
                        raise ValueError('aucune différence de hash observée')
                    run.receipt('tamper.json', result)
                    print(json.dumps(result, sort_keys=True), flush=True)
                    next_mutation = time.monotonic() + 5
                if duration is None:
                    break
                time.sleep(min(0.1, max(0, duration - (time.monotonic() - start))))
            result.update(termine=True, cause_fin='signal_recu' if received else
                          'fin_naturelle_duree' if duration is not None else 'fin_normale',
                          signal_recu=received[0] if received else None)
        except BaseException as exc:
            result.update(termine=True, cause_fin='erreur', erreur=_error(exc))
            raise
        finally:
            result['ecoule_s'] = round(time.monotonic() - start, 6)
            try:
                run.receipt('tamper.json', result)
            finally:
                os.close(held_fd)
                for number, handler in previous.items():
                    signal.signal(number, handler)
        return result


def restore(run_id, *, racine=None):
    with _Run(run_id, racine=racine) as run, run.operation():
        reference_sha = run.reference()
        # Réserver une seule restauration et garder l'ancienne fixture intégrale.
        result = _base(run, 'restore') | dict(restored=False, reference_sha256=reference_sha)
        run.receipt('restore.json', result, exclusive=True)
        before_sha = run.sha(LEDGER)
        with run.connect() as conn:
            conn.execute('BEGIN EXCLUSIVE')  # refuser tout verrou encore actif
            conn.execute('ROLLBACK')
        run.copy(LEDGER, BEFORE_RESTORE, readonly=True)
        if run.sha(BEFORE_RESTORE) != before_sha:
            raise ValueError('preuve avant restauration instable')
        run.copy(REFERENCE, '.ledger.restore.sqlite')
        if run.sha('.ledger.restore.sqlite') != reference_sha:
            raise ValueError('copie de référence instable')
        os.replace('.ledger.restore.sqlite', LEDGER, src_dir_fd=run.fd, dst_dir_fd=run.fd)
        os.fsync(run.fd)
        after_sha = run.sha(LEDGER)
        result.update(restored=after_sha == reference_sha, before_sha256=before_sha,
                      sha256=after_sha, preserved_evidence=BEFORE_RESTORE)
        run.receipt('restore.json', result)
        if not result['restored']:
            raise ValueError('restauration non vérifiée')
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('prepare', 'status', 'lock', 'tamper', 'restore'):
        p = sub.add_parser(command)
        p.add_argument('--run-id', required=True)
        if command in ('lock', 'tamper'):
            p.add_argument('--duration', required=command == 'lock', type=float)
            p.add_argument('--source-id', default='ledger')
    args = parser.parse_args(argv)
    try:
        if args.command in ('lock', 'tamper'):
            result = globals()[args.command](args.run_id, args.duration, source_id=args.source_id)
        else:
            result = globals()[args.command](args.run_id)
    except (ValueError, OSError, sqlite3.Error) as exc:
        print(json.dumps(dict(command=args.command, ok=False, error=_error(exc))), flush=True)
        return 1
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
