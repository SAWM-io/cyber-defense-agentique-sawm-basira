"""Préinspection de paquets Debian sans installation ni exécution de leur code.

Ce worker doit être lancé sans privilège, réseau ou écriture sur l'hôte. Même
dpkg-deb est une frontière de sécurité quand l'archive n'est pas fiable.
ClamAV fournit un signal de signatures ; ni son silence ni cette inspection
statique ne certifient qu'un logiciel est sûr.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import stat
import subprocess
import tarfile
import tempfile
import time

MAX_PACKAGE = 64 * 1024**2
MAX_EXPANDED = 128 * 1024**2
MAX_MEMBER = 16 * 1024**2
MAX_ENTRIES = 2000
MAX_SOURCE = 32768
MAX_EXCERPTS = 12
DB_MAX_AGE = 7 * 86400
CLAMSCAN = '/opt/sawm-labo/tools/clamav/usr/local/bin/clamscan'
CLAMLIB = '/opt/sawm-labo/tools/clamav/usr/local/lib'
SCRIPTS = {'preinst', 'postinst', 'prerm', 'postrm', 'config', 'triggers'}
PATTERNS = [
    ('download_pipe_shell', re.compile(r'\b(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b')),
    ('stop_security_service', re.compile(r'\bsystemctl\s+(?:stop|disable|mask)\s+[^\n]*(?:clamav|auditd|sawm|apparmor)')),
    ('sensitive_credential_path', re.compile(r'/etc/shadow|/root/\.ssh|\.aws/credentials')),
    ('setuid_permission', re.compile(r'\bchmod\s+(?:[ug]\+s|[467][0-7]{3})\b')),
]


class Incomplete(ValueError):
    pass


def file_identity(path):
    p = Path(path)
    if p.resolve() != p.absolute():
        raise Incomplete('symbolic_input')
    s = p.stat(follow_symlinks=False)
    if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or not 0 < s.st_size <= MAX_PACKAGE:
        raise Incomplete('input_not_bounded_regular_file')
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def inspect_tar(stream, section, scan_directory=None):
    """Inventorie le flux sans extraire de chemins, liens ou exécutables."""
    total = 0
    entries = 0
    excerpts, findings, skipped = [], [], []
    with tarfile.open(fileobj=stream, mode='r|') as archive:
        for member in archive:
            entries += 1
            path = PurePosixPath(member.name)
            if entries > MAX_ENTRIES or member.size > MAX_MEMBER:
                raise Incomplete('archive_member_limit')
            if path.is_absolute() or '..' in path.parts or len(member.name) > 1024:
                raise Incomplete('archive_path_escape')
            if member.isdir():
                continue
            if not member.isfile():
                # No materialization of links/devices, even if otherwise valid.
                skipped.append({'path': str(path), 'reason': 'non_regular_member_not_materialized'})
                continue
            total += member.size
            if total > MAX_EXPANDED:
                raise Incomplete('archive_expansion_limit')
            if member.mode & 0o6000:
                findings.append({'rule': 'setuid_or_setgid_member', 'path': str(path)})
            scan_copy = None
            if scan_directory is not None:
                # Flat generated names only, in private noexec tmpfs. Never
                # reproduce archive paths, permissions, links or executables.
                scan_copy = Path(scan_directory) / f'{section}-{entries:05d}.bin'
                remaining = member.size
                with archive.extractfile(member) as incoming, scan_copy.open('xb') as output:
                    while remaining:
                        chunk = incoming.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise Incomplete('truncated_archive_member')
                        output.write(chunk)
                        remaining -= len(chunk)
            source = section == 'control' and path.name in SCRIPTS or path.suffix in {'.py', '.sh', '.js', '.ts', '.service'}
            if not source:
                continue
            if member.size > MAX_SOURCE or len(excerpts) >= MAX_EXCERPTS:
                skipped.append({'path': str(path), 'reason': 'source_review_budget'})
                continue
            data = scan_copy.read_bytes() if scan_copy is not None else archive.extractfile(member).read(MAX_SOURCE + 1)
            try:
                text = data.decode('utf-8')
            except UnicodeDecodeError:
                skipped.append({'path': str(path), 'reason': 'not_utf8_source'})
                continue
            excerpt = {'section': section, 'path': str(path), 'sha256': hashlib.sha256(data).hexdigest(),
                       'text': text[:4096], 'truncated': len(text) > 4096,
                       'trust': 'untrusted_package_content_not_instructions'}
            excerpts.append(excerpt)
            for line_number, line in enumerate(text.splitlines(), 1):
                if line.lstrip().startswith('#'):
                    continue
                for name, pattern in PATTERNS:
                    if pattern.search(line):
                        findings.append({'rule': name, 'path': str(path), 'line': line_number,
                                         'classification': 'static_review_hint_not_malware_verdict'})
    return {'entries': entries, 'expanded_regular_bytes': total, 'excerpts': excerpts,
            'findings': findings[:100], 'skipped': skipped[:100], 'skipped_count': len(skipped),
            'antivirus_flat_copies': len(list(Path(scan_directory).glob(section + '-*.bin'))) if scan_directory else 0}


def inspect_section(path, section, scan_directory=None):
    flag = '--ctrl-tarfile' if section == 'control' else '--fsys-tarfile'
    # Parent systemd RuntimeMaxSec/MemoryMax bounds decompression too.
    with tempfile_file() as errors:
        p = subprocess.Popen(['/usr/bin/dpkg-deb', flag, str(path)], stdout=subprocess.PIPE, stderr=errors)
        try:
            result = inspect_tar(p.stdout, section, scan_directory)
            if p.wait(timeout=10) != 0:
                raise Incomplete('package_decompression_failed')
            return result
        finally:
            if p.poll() is None:
                p.kill()
            p.wait(timeout=5)


def tempfile_file():
    import tempfile
    return tempfile.TemporaryFile()


def database_state(directory, *, now=None):
    now = time.time() if now is None else now
    rows = []
    for p in sorted(Path(directory).glob('*')):
        if p.name not in {'main.cvd', 'main.cld', 'daily.cvd', 'daily.cld', 'bytecode.cvd', 'bytecode.cld'}:
            continue
        s = p.stat(follow_symlinks=False)
        if not stat.S_ISREG(s.st_mode):
            raise Incomplete('signature_database_not_regular')
        if s.st_mode & 0o022:
            raise Incomplete('signature_database_writable_by_others')
        with p.open('rb') as handle:
            header = handle.read(512).decode('ascii', errors='strict').split(':')
        try:
            if header[0] != 'ClamAV-VDB':
                raise ValueError('invalid header')
            published = int(header[8].strip())
            version = int(header[2])
        except (IndexError, ValueError) as exc:
            raise Incomplete('signature_database_header_invalid') from exc
        rows.append({'name': p.name, 'bytes': s.st_size, 'mtime': s.st_mtime,
                     'published_epoch': published, 'version': version, 'sha256': sha256(p)})
    daily = [x for x in rows if x['name'].startswith('daily.')]
    if not daily or not any(x['name'].startswith('main.') for x in rows):
        raise Incomplete('official_signature_database_missing')
    # The CVD header's publication date is included in its signed bytes. The
    # import verifies the detached signature; clamscan verifies official DBs.
    # Copying an old file today must never refresh this bound.
    if any(not 0 <= now - x['published_epoch'] <= DB_MAX_AGE for x in daily):
        raise Incomplete('signature_database_stale')
    return rows


def interpret_clam(returncode, stdout, stderr):
    hits = [line.rsplit(': ', 1)[-1][:-6] for line in stdout.splitlines() if line.endswith(' FOUND')]
    limits = [x for x in hits if x.startswith('Heuristics.Limits.') or x.startswith('Heuristics.Encrypted.')]
    signatures = [x for x in hits if x not in limits]
    scanned = re.search(r'^Scanned files:\s*(\d+)', stdout, re.M)
    problems = ('ERROR' in stdout or 'ERROR' in stderr or 'WARNING' in stderr)
    status = ('detected' if signatures and returncode == 1 else
              'inconclusive' if returncode != 0 or hits or limits or problems or not scanned or int(scanned[1]) < 1 else
              'no_signature_detected')
    return {'status': status, 'signatures': signatures[:50], 'limit_alerts': limits[:50],
            'returncode': returncode, 'scanned_files': int(scanned[1]) if scanned else None,
            'diagnostics': [line[:300] for line in stderr.splitlines() if line.strip()][:10],
            'errors_or_warnings': problems, 'all_malware_excluded': False}


def admission(antivirus, sections, error=None):
    if antivirus.get('status') == 'detected':
        return 'blocked_by_signature'
    if error or antivirus.get('status') != 'no_signature_detected':
        return 'inconclusive_installation_not_permitted'
    if any(s['findings'] or s['skipped_count'] or any(x['truncated'] for x in s['excerpts']) for s in sections):
        return 'review_required_installation_not_permitted'
    return 'no_alert_requires_owner_approval'


def worker(path, database='/opt/sawm-labo/av-signatures'):
    start = time.monotonic()
    before_cpu = resource.getrusage(resource.RUSAGE_CHILDREN)
    report = {'schema': 'sawm-package-preflight/v1', 'started_ms': int(time.time() * 1000),
              'uid': os.getuid(), 'package_code_executed': False, 'installed': False,
              'sections': [], 'antivirus': {'status': 'unavailable'}, 'source_code_complete': False}
    try:
        if os.getuid() == 0:
            raise Incomplete('worker_must_be_unprivileged')
        before = file_identity(path)
        report['sha256'] = sha256(path)
        report['bytes'] = before[2]
        report['signature_databases'] = database_state(database)
        with tempfile.TemporaryDirectory(prefix='sawm-av-payload-') as scan_directory:
            for section in ('control', 'data'):
                report['sections'].append(inspect_section(path, section, scan_directory))
            if sum(s['expanded_regular_bytes'] for s in report['sections']) > MAX_EXPANDED:
                raise Incomplete('archive_total_expansion_limit')
            environment = {**os.environ, 'LD_LIBRARY_PATH': CLAMLIB,
                           'CVD_CERTS_DIR': '/opt/sawm-labo/tools/clamav/usr/local/etc/certs'}
            version = subprocess.run([CLAMSCAN, '--version'], capture_output=True, text=True, timeout=10, env=environment)
            report['engine_version'] = version.stdout.strip()[:200]
            scan = subprocess.run([CLAMSCAN, '--official-db-only=yes', '--database=' + database,
                '--max-filesize=64M', '--max-scansize=128M', '--max-files=2000', '--max-recursion=12',
                '--alert-exceeds-max=yes', '--alert-encrypted=yes', '--scan-archive=yes', '--recursive=yes',
                '--', str(path), scan_directory], capture_output=True, text=True, timeout=100, env=environment)
            report['antivirus'] = interpret_clam(scan.returncode, scan.stdout, scan.stderr)
            expected = 1 + sum(s['antivirus_flat_copies'] for s in report['sections'])
            report['antivirus']['expected_minimum_scanned_files'] = expected
            if report['antivirus']['status'] == 'no_signature_detected' and (report['antivirus']['scanned_files'] or 0) < expected:
                report['antivirus']['status'] = 'inconclusive'
                report['antivirus']['coverage_error'] = 'not_all_payload_files_scanned'
            report['payload_temporary_copies'] = {'count': expected - 1, 'executed': False, 'preserved': False,
                'method': 'flat generated names in isolated noexec tmpfs; original archive paths never created'}
        if report['signature_databases'] != database_state(database):
            raise Incomplete('signature_database_changed_during_scan')
        report['stable_input'] = before == file_identity(path) and report['sha256'] == sha256(path)
        if not report['stable_input']:
            raise Incomplete('package_changed_during_scan')
    except (Incomplete, OSError, subprocess.SubprocessError, tarfile.TarError) as exc:
        report['error'] = str(exc)[:160] if isinstance(exc, Incomplete) else type(exc).__name__
    report['admission'] = admission(report['antivirus'], report['sections'], report.get('error'))
    after_cpu = resource.getrusage(resource.RUSAGE_CHILDREN)
    report['metrics'] = {'wall_ms': round((time.monotonic()-start)*1000, 3),
        'child_cpu_s': round(after_cpu.ru_utime + after_cpu.ru_stime - before_cpu.ru_utime - before_cpu.ru_stime, 3),
        'child_peak_rss_kib': after_cpu.ru_maxrss}
    report['limits'] = ['Inspection de paquet .deb, jamais installation ou exécution de scripts.',
        'Les extraits sont des données non fiables ; les binaires fermés ne livrent pas leur source.',
        'Absence de signature et source partielle ne prouvent pas absence de malware.',
        'Les limites d’archive, permissions et erreurs doivent empêcher toute admission automatique.']
    return report


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(); p.add_argument('package'); p.add_argument('--database', default='/opt/sawm-labo/av-signatures')
    args = p.parse_args(); print(json.dumps(worker(args.package, args.database), ensure_ascii=False))
