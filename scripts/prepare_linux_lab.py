#!/usr/bin/env python3
"""Prepare a NEW dedicated Linux VM; default is a JSON plan, never execution.

Copies client-side sensors/executor and a deny-by-default manifest. Does not
start services, call Cloud, modify GRUB/firewall/SSH, or install dependencies.
An existing installation is refused rather than silently overwritten.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import sys

REPO = Path(__file__).resolve().parents[1]
DEST = Path('/opt/sawm-labo')
SYSTEMD = Path('/etc/systemd/system')
UNITS = ('sawm-defense.slice', 'sawm-charge.slice', 'sawm-legitime.slice',
         'labo-temoin.service', 'labo-telemetrie.service')


def plan():
    return {
        'mode': 'prepare-only', 'destination': str(DEST),
        'copies': {'invite/agent_labo': 'agent', 'invite/executeur': 'executeur',
                   'invite/capteurs': 'capteurs', 'controleur/maintenance.py': 'maintenance.py',
                   'config/manifeste.observation.json': 'manifeste.json'},
        'systemd_units': list(UNITS), 'services_started': [], 'cloud_calls': False,
        'firewall_changes': False, 'kernel_changes': False,
        'authorization': 'No service may be stopped or limited by the initial manifest.'
    }


def trusted_parent(path):
    if path.resolve() != path:
        raise RuntimeError(f'Symlinked destination refused: {path}')
    for parent in [path, *path.parents]:
        s = parent.stat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise RuntimeError(f'Untrusted destination parent: {parent}')


def prepare():
    if not sys.platform.startswith('linux') or os.geteuid() != 0:
        raise RuntimeError('Apply requires root in a dedicated Linux VM.')
    if not Path('/run/systemd/system').is_dir():
        raise RuntimeError('A running systemd guest is required.')
    trusted_parent(DEST.parent)
    trusted_parent(SYSTEMD)
    if DEST.exists() or DEST.is_symlink():
        raise RuntimeError('Existing /opt/sawm-labo refused; preserve data and plan migration explicitly.')
    for unit in UNITS:
        if (SYSTEMD/unit).exists() or (SYSTEMD/unit).is_symlink():
            raise RuntimeError(f'Existing systemd unit refused: {unit}')
    # Reject any source symlink before copying trusted, reviewed release files as root.
    for folder in ('invite/agent_labo', 'invite/executeur', 'invite/capteurs', 'provisionnement/systemd'):
        if any(p.is_symlink() for p in (REPO/folder).rglob('*')):
            raise RuntimeError(f'Symlinked release source refused: {folder}')
    os.umask(0o077)
    DEST.mkdir(mode=0o755)
    for source, target in [('invite/agent_labo','agent'), ('invite/executeur','executeur'),
                           ('invite/capteurs','capteurs')]:
        shutil.copytree(REPO/source, DEST/target, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    shutil.copyfile(REPO/'controleur/maintenance.py', DEST/'maintenance.py')
    shutil.copyfile(REPO/'controleur/maintenance.py', DEST/'executeur/maintenance.py')
    shutil.copyfile(REPO/'config/manifeste.observation.json', DEST/'manifeste.json')
    for name in ('fixtures', 'reference', 'charges-etat'):
        (DEST/name).mkdir(mode=0o700)
    for name in ('fixtures', 'reference'):
        (DEST/name/'example.txt').write_text('Synthetic SAWM demonstration document. No customer data.\n')
    for p in DEST.rglob('*'):
        p.chmod(0o700 if p.is_dir() else 0o600)
    for unit in UNITS:
        with (SYSTEMD/unit).open('x') as stream:
            stream.write((REPO/'provisionnement/systemd'/unit).read_text())
        (SYSTEMD/unit).chmod(0o644)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--apply', action='store_true', help='Create new guest files; no services started.')
    p.add_argument('--acknowledge-dedicated-vm', action='store_true')
    args = p.parse_args()
    if args.apply:
        if not args.acknowledge_dedicated_vm:
            p.error('--apply requires --acknowledge-dedicated-vm')
        prepare()
    print(json.dumps({**plan(), 'applied': args.apply}, indent=2))


if __name__ == '__main__':
    main()
