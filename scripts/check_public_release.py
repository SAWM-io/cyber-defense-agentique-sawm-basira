#!/usr/bin/env python3
"""Check publishable sources only; never print matched secret values.

This is a regression guard, not a substitute for human publication review.
Local runtime output and credentials must never enter the Git index.
"""
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DENY_PARTS = {'.venv', '__pycache__', '.git', '.pytest_cache', 'releves', 'fixtures'}
DENY_SUFFIXES = {'.pem', '.key', '.qcow2', '.sqlite', '.raw', '.img', '.log', '.pyc', '.jsonl'}
# Construct literal private identifiers to avoid embedding them in public sources.
PERSONAL_PATH = re.compile(r'/(?:Users|home)/[^\s/]+/(?:Documents|Desktop|Downloads)/')
SECRET_PATTERNS = [
    ('private-key', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ('github-token', re.compile(r'\bgh[pousr]_[A-Za-z0-9]{30,}\b')),
    ('provider-key', re.compile(r'\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b')),
    ('cloud-credential', re.compile(r'\bbsr_live_[A-Za-z0-9_-]{24,}\b')),
    ('local-workstation-path', PERSONAL_PATH),
]


def paths():
    if (ROOT/'.git').exists():
        result = subprocess.run(['git','ls-files','-z'], cwd=ROOT, capture_output=True, check=True)
        return [ROOT/name for name in result.stdout.decode().split('\0') if name]
    return [p for p in ROOT.rglob('*') if p.is_file() and not (DENY_PARTS & set(p.relative_to(ROOT).parts))]


def main():
    findings=[]
    for path in paths():
        rel=path.relative_to(ROOT)
        if DENY_PARTS & set(rel.parts) or path.suffix in DENY_SUFFIXES or (path.name.startswith('.env') and path.name != '.env.example'):
            findings.append((str(rel),0,'runtime-or-secret-file-tracked'))
            continue
        if path.is_symlink():
            findings.append((str(rel),0,'symlink-review-required'))
            continue
        if path.suffix in {'.png','.jpg','.jpeg','.webp'}:
            continue
        text=path.read_text(errors='replace')
        for number,line in enumerate(text.splitlines(),1):
            for label, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append((str(rel),number,label))
    for path,line,label in findings:
        print(f'{path}:{line}: {label}')
    print(f'Publication checks: {len(findings)} findings (matched values are never printed).')
    return 1 if findings else 0


if __name__=='__main__':
    sys.exit(main())
