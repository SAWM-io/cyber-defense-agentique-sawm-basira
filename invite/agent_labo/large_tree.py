"""Staging : intégrité d'un arbre explicitement enrôlé, sans action de défense.

SHA-256 par fichier et bloc ; aucune attribution de processus à partir d'un hash.
L'horloge d'un scan n'est jamais présentée comme latence de détection continue.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import stat
import sys
import tempfile
import time

SCHEMA = 'sawm-large-tree-baseline/v1'
DEFAULTS = dict(chunk_bytes=1024*1024, block_bytes=4*1024*1024,
                max_bytes=8*1024**3, max_file_bytes=8*1024**3,
                max_entries=10000, max_blocks=16384, max_seconds=300,
                bytes_per_second=64*1024*1024, max_changes=200)
CAPS = dict(chunk_bytes=4*1024*1024, block_bytes=64*1024*1024,
            max_bytes=64*1024**3, max_file_bytes=64*1024**3,
            max_entries=50000, max_blocks=65536, max_seconds=3600,
            bytes_per_second=1024**3, max_changes=2000)
MAX_JSON = 16*1024*1024
FIELDS = ('device', 'inode', 'size', 'mtime_ns', 'ctime_ns', 'mode', 'uid', 'gid', 'nlink')


class Inconclusive(Exception):
    pass


def limits(values=None):
    values = {} if values is None else values
    if not isinstance(values, dict) or set(values)-set(DEFAULTS):
        raise ValueError('limites_inconnues')
    out = {**DEFAULTS, **values}
    for key, value in out.items():
        if type(value) is not int or not 1 <= value <= CAPS[key]:
            raise ValueError('limite_invalide:'+key)
    if out['chunk_bytes'] > out['block_bytes'] or out['block_bytes'] % out['chunk_bytes']:
        raise ValueError('blocs_non_multiples_des_lectures')
    return out


def metadata(st):
    return dict(device=st.st_dev, inode=st.st_ino, size=st.st_size,
                mtime_ns=st.st_mtime_ns, ctime_ns=st.st_ctime_ns,
                mode=stat.S_IMODE(st.st_mode), uid=st.st_uid, gid=st.st_gid,
                nlink=st.st_nlink, kind='directory' if stat.S_ISDIR(st.st_mode) else 'file')


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()


def open_directory(path):
    """Every absolute component is opened O_NOFOLLOW; no resolve() check race."""
    p = Path(path)
    if not p.is_absolute() or '..' in p.parts or str(p) == '/':
        raise ValueError('racine_absolue_explicite_requise')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in p.parts[1:]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = nxt
        return fd
    except BaseException:
        os.close(fd); raise


def external(path, root):
    p, r = Path(os.path.abspath(path)), Path(os.path.abspath(root))
    if not Path(path).is_absolute() or '..' in Path(path).parts or p == r or r in p.parents:
        raise ValueError('reference_ou_sortie_dans_arbre')
    fd = open_directory(str(p.parent)); os.close(fd)
    if p.is_symlink():
        raise ValueError('chemin_symbolique_refuse')
    return p


def write_json(path, value, root, *, exclusive=False):
    p = external(path, root)
    raw = canonical(value)
    if len(raw) > MAX_JSON:
        raise Inconclusive('budget_json_depasse')
    # Parent descriptor pins the checked directory for atomic creation/replacement.
    parent = open_directory(str(p.parent))
    name = '.large-tree-'+os.urandom(8).hex()
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        if exclusive:
            os.link(name, p.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
            os.unlink(name, dir_fd=parent)
        else:
            os.rename(name, p.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        try: os.unlink(name, dir_fd=parent)
        except FileNotFoundError: pass
        os.close(parent)
    return hashlib.sha256(raw).hexdigest()


def read_trusted(path, root, digest=None):
    p = external(path, root); parent = open_directory(str(p.parent))
    try: fd = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally: os.close(parent)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_mode & 0o022 or before.st_size > MAX_JSON):
            raise ValueError('fichier_controle_non_fiable')
        raw = stream.read(MAX_JSON+1)
        if metadata(before) != metadata(os.fstat(stream.fileno())) or len(raw) > MAX_JSON:
            raise Inconclusive('fichier_controle_change')
    if digest is not None and (not isinstance(digest, str) or len(digest) != 64
                               or hashlib.sha256(raw).hexdigest() != digest):
        raise ValueError('empreinte_reference_non_approuvee')
    return json.loads(raw)


def scan_tree(root, options=None):
    cfg = limits(options); t0 = time.monotonic(); cpu = time.process_time()
    result = dict(schema='sawm-large-tree-scan/v1', root=str(Path(root)),
                  started_ms=int(time.time()*1000), status='inconclusive', entries={}, limits=cfg)
    read_bytes = block_count = entry_count = 0
    root_fd = None

    def budget():
        if time.monotonic()-t0 > cfg['max_seconds']:
            raise Inconclusive('budget_temps_depasse')

    def visit(fd, relative):
        nonlocal read_bytes, block_count, entry_count
        budget()
        before = os.fstat(fd)
        names = []
        # scandir is lazy: an oversized directory cannot allocate an unbounded list.
        with os.scandir(fd) as iterator:
            for ent in iterator:
                entry_count += 1
                if entry_count > cfg['max_entries']:
                    raise Inconclusive('budget_entrees_depasse')
                names.append(ent.name)
        for name in sorted(names):
            budget(); rel = relative+'/'+name if relative else name
            original = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISLNK(original.st_mode):
                raise Inconclusive('lien_symbolique_refuse:'+rel)
            is_dir = stat.S_ISDIR(original.st_mode)
            if not is_dir and not stat.S_ISREG(original.st_mode):
                raise Inconclusive('objet_non_regulier:'+rel)
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if is_dir: flags |= os.O_DIRECTORY
            child = os.open(name, flags, dir_fd=fd)
            try:
                observed = os.fstat(child)
                if metadata(original) != metadata(observed):
                    raise Inconclusive('objet_change_avant_lecture:'+rel)
                item = metadata(observed); result['entries'][rel] = item
                if is_dir:
                    visit(child, rel)
                else:
                    if observed.st_size > cfg['max_file_bytes']:
                        raise Inconclusive('budget_fichier_depasse:'+rel)
                    whole, block, blocks, block_len, count = hashlib.sha256(), hashlib.sha256(), [], 0, 0
                    while True:
                        budget()
                        chunk = os.read(child, min(cfg['chunk_bytes'], cfg['block_bytes']-block_len))
                        if not chunk: break
                        read_bytes += len(chunk); count += len(chunk)
                        if read_bytes > cfg['max_bytes']:
                            raise Inconclusive('budget_octets_depasse')
                        whole.update(chunk); block.update(chunk); block_len += len(chunk)
                        if block_len == cfg['block_bytes']:
                            blocks.append(block.hexdigest()); block = hashlib.sha256(); block_len = 0
                            block_count += 1
                        if block_count > cfg['max_blocks']:
                            raise Inconclusive('budget_blocs_depasse')
                        pause = read_bytes/cfg['bytes_per_second'] - (time.monotonic()-t0)
                        if pause > 0: time.sleep(min(pause, cfg['max_seconds']))
                    if block_len:
                        blocks.append(block.hexdigest()); block_count += 1
                    if block_count > cfg['max_blocks']:
                        raise Inconclusive('budget_blocs_depasse')
                    if count != observed.st_size or metadata(observed) != metadata(os.fstat(child)):
                        raise Inconclusive('fichier_change_pendant_lecture:'+rel)
                    item.update(sha256=whole.hexdigest(), blocks=blocks)
                if metadata(observed) != metadata(os.stat(name, dir_fd=fd, follow_symlinks=False)):
                    raise Inconclusive('objet_remplace_pendant_lecture:'+rel)
            finally: os.close(child)
        if metadata(before) != metadata(os.fstat(fd)):
            raise Inconclusive('repertoire_change_pendant_scan:'+relative)

    def verify(fd, relative):
        budget()
        before = metadata(os.fstat(fd)); seen = set()
        with os.scandir(fd) as iterator:
            for ent in iterator:
                budget(); name = ent.name; seen.add(name)
                if len(seen) > cfg['max_entries']: raise Inconclusive('budget_entrees_depasse')
                rel = relative+'/'+name if relative else name
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                saved = result['entries'].get(rel)
                if not saved or any(saved[k] != metadata(st)[k] for k in (*FIELDS, 'kind')):
                    raise Inconclusive('objet_change_apres_lecture:'+rel)
                if saved['kind'] == 'directory':
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try: verify(child, rel)
                    finally: os.close(child)
        prefix = relative+'/' if relative else ''
        expected = {name[len(prefix):] for name in result['entries']
                    if name != '.' and name.startswith(prefix) and '/' not in name[len(prefix):]}
        if seen != expected or before != metadata(os.fstat(fd)):
            raise Inconclusive('repertoire_change_apres_lecture:'+relative)

    try:
        root_fd = open_directory(root); initial = metadata(os.fstat(root_fd))
        result['root_identity'] = initial
        result['entries']['.'] = initial
        visit(root_fd, '')
        verify(root_fd, '')
        fresh = open_directory(root)
        try:
            if initial != metadata(os.fstat(fresh)) or initial != metadata(os.fstat(root_fd)):
                raise Inconclusive('racine_changee_pendant_scan')
        finally: os.close(fresh)
        budget(); result['status'] = 'complete'
    except (OSError, Inconclusive) as exc:
        result['reason'] = str(exc)[:300]
    finally:
        if root_fd is not None: os.close(root_fd)
        wall = time.monotonic()-t0; used = time.process_time()-cpu
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        result['finished_ms'] = int(time.time()*1000)
        result['metrics'] = dict(scan_seconds=round(wall, 6), cpu_seconds=round(used, 6),
            cpu_one_core_percent=round(100*used/wall, 2) if wall else 0,
            process_peak_rss_bytes=peak if sys.platform=='darwin' else peak*1024,
            bytes_read=read_bytes, files=sum(e['kind']=='file' for e in result['entries'].values()),
            entries=len(result['entries']), blocks=block_count,
            rate_bytes_per_second=round(read_bytes/wall) if wall else 0)
        if result['status'] != 'complete':
            result['entries'] = {}  # Partial inventory must never become trusted state.
    return result


def approve_baseline(root, path, options=None):
    external(path, root)
    if Path(path).exists(): raise ValueError('reference_existante_ne_pas_ecraser')
    observed = scan_tree(root, options)
    if observed['status'] != 'complete': raise Inconclusive(observed.get('reason', 'scan_incomplet'))
    baseline = dict(schema=SCHEMA, root=observed['root'], approved_ms=int(time.time()*1000),
                    entries=observed['entries'], block_bytes=observed['limits']['block_bytes'])
    sha = write_json(path, baseline, root, exclusive=True)
    return dict(baseline_sha256=sha, baseline_path=str(path), metrics=observed['metrics'])


def compare(baseline, current, max_changes=200):
    out = dict(schema='sawm-large-tree-integrity/v1', status='inconclusive',
               root=current['root'], scan_started_ms=current['started_ms'],
               observed_ms=current['finished_ms'], metrics=current['metrics'],
               counts={}, changes=[], attribution='unknown', action_performed=False,
               limits=['Explicit enrolled tree only; no malware verdict or writer attribution.',
                       'Scan duration is not continuous detection latency.',
                       'Metadata consistency checks are not an atomic filesystem snapshot.',
                       'Peak RSS is the process lifetime high-water mark.',
                       'Blocking filesystem I/O needs external service timeout.'])
    if current['status'] != 'complete':
        out['reason'] = current.get('reason', 'scan_incomplet'); return out
    if baseline.get('schema') != SCHEMA or baseline.get('root') != current['root'] or baseline.get('block_bytes') != current['limits']['block_bytes']:
        out['reason'] = 'reference_incompatible'; return out
    old, new = baseline['entries'], current['entries']
    def emit(kind, path, **details):
        out['counts'][kind] = out['counts'].get(kind, 0)+1
        if len(out['changes']) < max_changes:
            out['changes'].append(dict(kind=kind, path=path, **details))
    removed, added = set(old)-set(new), set(new)-set(old)
    # Same inode + same content is a rename candidate, not proof of an actor.
    candidates = {}
    for name in removed:
        e = old[name]; candidates.setdefault((e['device'], e['inode'], e.get('sha256')), []).append(name)
    for name in sorted(added):
        e = new[name]; matches = candidates.get((e['device'], e['inode'], e.get('sha256')), [])
        if len(matches) == 1:
            previous = matches.pop(); removed.remove(previous)
            emit('rename_candidate', name, previous_path=previous)
        else: emit('added', name)
    for name in sorted(removed): emit('deleted', name)
    for name in sorted(set(old)&set(new)):
        a, b = old[name], new[name]
        if a['kind'] != b['kind']: emit('type_changed', name)
        if a.get('sha256') != b.get('sha256'):
            blocks_a, blocks_b = a.get('blocks', []), b.get('blocks', [])
            changed = [i for i in range(max(len(blocks_a), len(blocks_b)))
                       if (blocks_a[i] if i<len(blocks_a) else None) != (blocks_b[i] if i<len(blocks_b) else None)]
            emit('content_changed', name, changed_block_count=len(changed), changed_block_indexes=changed[:64])
        if (a['device'],a['inode']) != (b['device'],b['inode']): emit('object_replaced', name)
        if a['mode'] != b['mode']: emit('permissions_changed', name, previous=a['mode'], current=b['mode'])
        if (a['uid'],a['gid']) != (b['uid'],b['gid']): emit('owner_changed', name, previous=[a['uid'],a['gid']], current=[b['uid'],b['gid']])
    out['changes_truncated'] = sum(out['counts'].values()) > len(out['changes'])
    out['status'] = 'changed' if out['counts'] else 'unchanged'
    return out


def run_config(path):
    # Config root is only used to enforce the external path boundary on second read.
    config = read_trusted(path, '/__sawm_config_not_a_monitored_root__')
    root = config['root']; config = read_trusted(path, root)
    baseline = read_trusted(config['baseline'], root, config['baseline_sha256'])
    cfg = limits(config.get('limits'))
    scan = scan_tree(root, cfg)
    result = compare(baseline, scan, cfg['max_changes'])
    result['baseline_sha256'] = config['baseline_sha256']
    write_json(config['output'], result, root)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config'); p.add_argument('--approve-baseline', action='store_true')
    p.add_argument('--root'); p.add_argument('--baseline'); p.add_argument('--limits-json')
    args = p.parse_args()
    if args.approve_baseline:
        if not args.root or not args.baseline or args.config: p.error('root et baseline explicites requis')
        result = approve_baseline(args.root, args.baseline, json.loads(args.limits_json) if args.limits_json else None)
    elif args.config: result = run_config(args.config)
    else: p.error('config ou approbation explicite requis')
    print(json.dumps(result, ensure_ascii=True))


if __name__ == '__main__':
    main()
