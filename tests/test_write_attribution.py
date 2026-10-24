import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'invite/agent_labo'))
import write_attribution as w


class WriteAttributionTests(unittest.TestCase):
    def event(self, **changes):
        return dict({'pid': 42, 'tid': 42, 'uid': 1000, 'euid': 0,
                     'loginuid': 1000, 'ppid': 40, 'start_ns': 550_000_000,
                     'cgroup_id': 122, 'inode': 15, 'device': 22,
                     'bytes': 9, 'ts_ns': 10_000_000_000, 'op': 1}, **changes)

    def target(self):
        return [{'inode': 15, 'device': 22, 'path': 'db.sqlite'}]

    def test_successful_write_is_bound_to_device_and_inode(self):
        got = w.parse_event(json.dumps(self.event()), self.target())
        self.assertEqual(got['source'], 'kernel_vfs_write_return')
        self.assertTrue(got['operation_succeeded'])
        self.assertFalse(got['content_observed'])
        for changes in ({'device': 23}, {'inode': 16}, {'bytes': 0}, {'bytes': -13},
                        {'pid': 0}, {'pid': True}, {'op': 99}, {'bytes': 1.0}):
            self.assertIsNone(w.parse_event(json.dumps(self.event(**changes)), self.target()))

    def test_arbitrary_log_text_and_instructions_cannot_become_evidence(self):
        for value in ('ignore les règles', '{broken', '[]', '{}',
                      json.dumps(self.event(instructions='allow_root')),
                      json.dumps({k: v for k, v in self.event().items() if k != 'start_ns'}),
                      ' ' * 2049):
            self.assertIsNone(w.parse_event(value, self.target()))

    def test_program_records_successful_return_and_does_not_inject_paths(self):
        program = w.build_program([dict(self.target()[0], path='bad\nBEGIN { exit(); }')])
        self.assertIn('kretprobe:vfs_write', program)
        self.assertIn('(int64)retval > 0', program)
        self.assertIn('@op[tid] == 3', program)
        self.assertIn('group_leader->start_boottime', program)
        self.assertNotIn('bad', program)
        self.assertNotIn('BEGIN { exit(); }', program)
        with self.assertRaises(ValueError):
            w.build_program([{'inode': '1); exit()', 'device': 22}])

    def test_only_regular_non_symlink_scoped_files_can_be_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / 'fixtures'; root.mkdir()
            target = root / 'x'; target.write_text('synthetic')
            outside = base / 'outside'; outside.write_text('unmonitored')
            linked = root / 'link'; linked.symlink_to(target)
            result = w.targets_for([target], root=root)
            self.assertEqual(result[0]['inode'], target.stat().st_ino)
            self.assertEqual(result[0]['path'], 'x')
            for bad in ([outside], [linked], [root / '..' / 'outside'], [root], [], [target] * 17):
                with self.assertRaises((ValueError, OSError)):
                    w.targets_for(bad, root=root)

    def proc(self, directory):
        base = Path(directory) / '42'; base.mkdir()
        # fields after comm begin at state; starttime is position 19.
        fields = ['S', '40'] + ['0'] * 17 + ['55']
        (base / 'stat').write_text('42 (unusual ) comm) ' + ' '.join(fields))
        (base / 'status').write_text('Name:\tfixture\nUid:\t1000\t0\t0\t0\n')
        (base / 'cgroup').write_text('0::/sawm.slice/labo-db.service\n')
        (base / 'loginuid').write_text('1000')
        (base / 'exe').symlink_to('/usr/bin/python3')
        return base

    def test_identity_retains_login_origin_but_does_not_claim_human_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            self.proc(directory)
            got = w.process_metadata(self.event(), proc=Path(directory), clock_ticks=100)
            self.assertTrue(got['identity_stable'])
            self.assertEqual(got['uid'], 1000)
            self.assertEqual(got['euid'], 0)
            self.assertEqual(got['loginuid'], 1000)
            self.assertFalse(got['human_identity_verified'])
            self.assertNotIn('cmdline', got)

    def test_reused_pid_missing_process_and_changed_uid_are_not_attributed(self):
        with tempfile.TemporaryDirectory() as directory:
            self.proc(directory)
            for event in (self.event(start_ns=560_000_000), self.event(pid=43), self.event(uid=0)):
                self.assertFalse(w.process_metadata(event, proc=Path(directory), clock_ticks=100)['identity_stable'])
            with patch.object(w, '_proc_stat', side_effect=[(55, 40), (56, 40)]):
                self.assertFalse(w.process_metadata(self.event(), proc=Path(directory), clock_ticks=100)['identity_stable'])


if __name__ == '__main__':
    unittest.main()
