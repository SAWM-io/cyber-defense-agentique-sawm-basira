#!/usr/bin/env python3
"""Jetons HMAC du témoin de laboratoire ; secret local root, jamais journalisé."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
import urllib.error
import urllib.request

CLE = Path(os.environ.get("LABO_JETONS_CLE", "/opt/sawm-labo/jetons.key"))
ETAT = Path(os.environ.get("LABO_JETONS", "/opt/sawm-labo/jetons.json"))
ROOT_UID = 0
DOMAINE = b"sawm-labo/document-token/v1\0"
FORMAT = re.compile(r"v([1-9][0-9]{0,15})\.([0-9a-f]{32})\.([0-9a-f]{64})\Z")


def _lire(path: Path, *, secret=False) -> bytes:
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as f:
        s = os.fstat(f.fileno())
        if (not stat.S_ISREG(s.st_mode) or s.st_uid != ROOT_UID or s.st_nlink != 1
                or s.st_mode & (0o077 if secret else 0o022)):
            raise ValueError("permissions de jeton non fiables")
        raw = f.read(4097)
    if len(raw) > 4096 or (secret and len(raw) != 32):
        raise ValueError("état de jeton invalide")
    return raw


def version_courante() -> int:
    version = json.loads(_lire(ETAT))["version"]
    if type(version) is not int or not 1 <= version < 10**16:
        raise ValueError("version de jeton invalide")
    return version


def emettre(version: int | None = None) -> str:
    version = version_courante() if version is None else version
    if type(version) is not int or not 1 <= version < 10**16:
        raise ValueError("version de jeton invalide")
    corps = f"v{version}.{secrets.token_hex(16)}"
    signature = hmac.new(_lire(CLE, secret=True), DOMAINE + corps.encode(),
                         hashlib.sha256).hexdigest()
    return f"{corps}.{signature}"


def verifier(jeton: str | None) -> bool:
    match = FORMAT.fullmatch(jeton) if isinstance(jeton, str) else None
    if match is None:
        return False
    try:
        if int(match[1]) != version_courante():
            return False
        corps, signature = jeton.rsplit(".", 1)
        attendue = hmac.new(_lire(CLE, secret=True), DOMAINE + corps.encode(),
                            hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, attendue)
    except (OSError, ValueError, KeyError, TypeError):
        return False


def _ecrire_version(version: int) -> None:
    fd, tmp = tempfile.mkstemp(prefix=".jetons-", dir=ETAT.parent)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({"version": version}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, ETAT)
    finally:
        Path(tmp).unlink(missing_ok=True)


def initialiser() -> int:
    # O_EXCL empêche d'écraser une clé existante ou de suivre un lien.
    try:
        fd = os.open(CLE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        _lire(CLE, secret=True)
    else:
        with os.fdopen(fd, "wb") as f:
            f.write(secrets.token_bytes(32))
            f.flush()
            os.fsync(f.fileno())
    if not ETAT.exists():
        _ecrire_version(1)
    return version_courante()


def tourner() -> int:
    fd = os.open(str(ETAT) + ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        version = version_courante() + 1
        if version >= 10**16:
            raise ValueError("version épuisée")
        _ecrire_version(version)
        return version


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("commande", choices=("init", "version", "emettre", "tourner", "essai"))
    parser.add_argument("version", type=int, nargs="?")
    args = parser.parse_args()
    if args.commande == "init":
        print(initialiser())
    elif args.commande == "version":
        print(version_courante())
    elif args.commande == "tourner":
        print(tourner())
    elif args.commande == "emettre":
        print(emettre(args.version))
    else:
        req = urllib.request.Request("http://127.0.0.1:8080/document",
                                    headers={"X-Labo-Jeton": emettre(args.version)})
        try:
            with urllib.request.urlopen(req, timeout=3) as response:
                print(response.status)
        except urllib.error.HTTPError as error:
            print(error.code)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
