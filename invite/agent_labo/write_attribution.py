"""Bounded, read-only Linux write attribution for explicit laboratory files.

The sensor records *successful* VFS write returns, not file contents. It grants
no action permission. Inode identity, process incarnation and missing coverage
are evidence, not a verdict that a process is malware. mmap, direct device I/O,
remote writers and a hostile kernel remain outside this instrument's proof.
"""
from __future__ import annotations

from collections import deque
import json
import os
from pathlib import Path
import stat
import subprocess
import threading
import time

FIXTURES = Path('/opt/sawm-labo/fixtures')
MAX_TARGETS = 16
MAX_EVENTS = 256
EVENT_FIELDS = {'pid', 'tid', 'uid', 'euid', 'loginuid', 'ppid', 'start_ns',
                'cgroup_id', 'inode', 'device', 'bytes', 'ts_ns', 'op'}
LIMITS = ['explicit_file_inodes_only', 'mmap_not_covered',
          'direct_block_device_not_covered', 'remote_writer_not_covered',
          'kernel_not_attested', 'metadata_does_not_prove_malware']


def targets_for(paths, *, root=FIXTURES):
    """Resolve files without accepting symlinks or arbitrary source code."""
    root = Path(root).resolve(strict=True)
    if not 1 <= len(paths) <= MAX_TARGETS:
        raise ValueError('one_to_sixteen_targets_required')
    out = []
    for raw in paths:
        path = Path(raw).absolute()
        if '..' in path.parts or not path.is_relative_to(root) or not path.resolve(strict=True).is_relative_to(root):
            raise ValueError('outside_fixture_root')
        relative = path.relative_to(root)
        descriptors = []
        try:
            parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            descriptors.append(parent)
            for part in relative.parts[:-1]:
                parent = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=parent)
                descriptors.append(parent)
            if not relative.parts:
                raise ValueError('regular_file_required')
            fd = os.open(relative.parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=parent)
            descriptors.append(fd)
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise ValueError('regular_file_required')
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)
        item = {'path': str(relative), 'inode': st.st_ino,
                'device': (os.major(st.st_dev) << 20) | os.minor(st.st_dev),
                'st_dev': st.st_dev}
        if item not in out:
            out.append(item)
    return out


def build_program(targets):
    if not 1 <= len(targets) <= MAX_TARGETS:
        raise ValueError('invalid_target_count')
    for target in targets:
        for key in ('inode', 'device'):
            if type(target.get(key)) is not int or target[key] < 0:
                raise ValueError('invalid_target_identity')
    predicate = ' || '.join(f'($ino == {x["inode"]} && $dev == {x["device"]})'
                           for x in targets)
    chunks = ['#include <linux/fs.h>\n#include <linux/sched.h>\n#include <linux/cred.h>\n',
              'interval:s:1 { printf("{\\"sensor_ready\\":true}\\n"); }\n']
    for op, name in enumerate(('vfs_write', 'vfs_writev', 'vfs_iter_write'), 1):
        chunks.append(f'''kprobe:{name}
/!@op[tid]/
{{
  $file = (struct file *)arg0;
  $ino = $file->f_inode->i_ino;
  $dev = $file->f_inode->i_sb->s_dev;
  if ({predicate}) {{
    $task = (struct task_struct *)curtask;
    @op[tid] = {op};
    @meta[tid] = ((uint64)pid, (uint64)uid, (uint64)$task->cred->euid.val,
      (uint64)$task->loginuid.val, (uint64)$task->real_parent->tgid,
      (uint64)$task->group_leader->start_boottime,
      (uint64)cgroup, (uint64)$ino, (uint64)$dev);
  }}
}}
kretprobe:{name}
/@op[tid] == {op}/
{{
  if ((int64)retval > 0) {{
    $m = @meta[tid];
    printf("{{\\"pid\\":%d,\\"tid\\":%d,\\"uid\\":%u,\\"euid\\":%u,\\"loginuid\\":%u,\\"ppid\\":%d,\\"start_ns\\":%llu,\\"cgroup_id\\":%llu,\\"inode\\":%llu,\\"device\\":%u,\\"bytes\\":%lld,\\"ts_ns\\":%llu,\\"op\\":%d}}\\n",
      $m.0, tid, $m.1, $m.2, $m.3, $m.4, $m.5, $m.6, $m.7, $m.8, retval, nsecs, {op});
  }}
  delete(@meta[tid]); delete(@op[tid]);
}}
''')
    return ''.join(chunks)


def parse_event(line, targets):
    """Strict numeric wire format: logs/filenames cannot supply instructions."""
    if len(line) > 2048:
        return None
    try:
        event = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(event, dict) or set(event) != EVENT_FIELDS:
        return None
    if any(type(v) is not int or v < 0 for v in event.values()):
        return None
    if event['pid'] <= 0 or event['tid'] <= 0 or event['bytes'] <= 0 or event['op'] not in (1, 2, 3):
        return None
    match = next((x for x in targets if (x['inode'], x['device']) ==
                  (event['inode'], event['device'])), None)
    if not match:
        return None
    return dict(event, path=match['path'], source='kernel_vfs_write_return',
                path_binding='inode_at_sensor_start',
                operation_succeeded=True, content_observed=False)


def _proc_stat(path):
    text = path.read_text()
    fields = text[text.rfind(')') + 2:].split()
    return int(fields[19]), int(fields[1])


def process_metadata(event, *, proc=Path('/proc'), clock_ticks=None):
    """Bind metadata to the exact incarnation; no argv, environment or content."""
    proc = Path(proc)
    base = proc / str(event['pid'])
    hz = clock_ticks or os.sysconf('SC_CLK_TCK')
    try:
        first, ppid = _proc_stat(base / 'stat')
        # /proc truncates nanoseconds to jiffies. The kernel event's start time
        # is from the thread group leader, matching /proc/<tgid>/stat.
        expected = event['start_ns'] * hz // 1_000_000_000
        if first != expected:
            return {'identity_stable': False, 'reason': 'process_incarnation_changed'}
        status = (base / 'status').read_text()
        uidline = next(x for x in status.splitlines() if x.startswith('Uid:'))
        uids = [int(x) for x in uidline.split()[1:]]
        group = (base / 'cgroup').read_text().strip()[:512]
        loginuid = int((base / 'loginuid').read_text())
        executable = os.readlink(base / 'exe')[:512]
        last, _ = _proc_stat(base / 'stat')
        if first != last or len(uids) != 4 or uids[:2] != [event['uid'], event['euid']]:
            return {'identity_stable': False, 'reason': 'identity_changed_during_read'}
        return {'identity_stable': True, 'start_ticks': first, 'ppid': ppid,
                'cgroup': group, 'executable': executable, 'uid': uids[0],
                'euid': uids[1], 'loginuid': None if loginuid == 4294967295 else loginuid,
                'human_identity_verified': False}
    except (OSError, ValueError, IndexError, StopIteration):
        return {'identity_stable': False, 'reason': 'process_metadata_unavailable'}


class WriteAttributionSensor:
    def __init__(self, paths, *, root=FIXTURES):
        self.targets = targets_for(paths, root=root)
        self.events = deque(maxlen=MAX_EVENTS)
        self.lock = threading.Lock()
        self.ready = threading.Event()
        self.process = None
        self.observed = self.evicted = self.lost = self.invalid = 0
        self.error = None
        self.boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()

    def start(self, *, timeout=15):
        if self.process is not None:
            raise RuntimeError('sensor_already_started')
        self.process = subprocess.Popen(['bpftrace', '-B', 'line', '-'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, close_fds=True)
        for name in ('_read_stdout', '_read_stderr'):
            threading.Thread(target=getattr(self, name), daemon=True).start()
        self.process.stdin.write(build_program(self.targets))
        self.process.stdin.close()
        if not self.ready.wait(timeout) or self.process.poll() is not None:
            self.close()
            raise RuntimeError('write_sensor_not_ready')
        return self

    def _read_stdout(self):
        for line in self.process.stdout:
            if line.strip() == '{"sensor_ready":true}':
                self.ready.set()
                continue
            item = parse_event(line, self.targets)
            if not item:
                if line.startswith('{'):
                    self.invalid += 1
                continue
            item['boot_id'] = self.boot_id
            item['received_at_ms'] = int(time.time() * 1000)
            elapsed = time.monotonic_ns() - item['ts_ns']
            item['capture_latency_ms'] = elapsed / 1_000_000 if elapsed >= 0 else None
            item['process'] = process_metadata(item)
            with self.lock:
                self.observed += 1
                if len(self.events) == MAX_EVENTS:
                    self.evicted += 1
                self.events.append(item)

    def _read_stderr(self):
        for line in self.process.stderr:
            with self.lock:
                if 'Lost ' in line and 'events' in line:
                    # bpftrace versions differ: retain a loss indication rather
                    # than inventing a precise count from a variable format.
                    self.lost += 1
                if 'ERROR' in line:
                    self.error = 'kernel_sensor_error'

    def snapshot(self):
        with self.lock:
            return {'schema': 'sawm-write-attribution/v1', 'boot_id': self.boot_id,
                    'active': bool(self.ready.is_set() and self.process and self.process.poll() is None),
                    'targets': self.targets, 'events': list(self.events),
                    'observed_events': self.observed, 'evicted_events': self.evicted,
                    'loss_notifications': self.lost, 'invalid_events': self.invalid,
                    'error': self.error, 'limits': LIMITS}

    def close(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)

    def __enter__(self):
        return self.start()

    def __exit__(self, *args):
        self.close()
