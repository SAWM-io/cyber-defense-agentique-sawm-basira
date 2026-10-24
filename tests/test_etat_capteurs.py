"""État exec : identité systemd stable et preuve perf, sans VM ni processus réel."""
import importlib.util
import json
import pathlib
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

AGENT = pathlib.Path(__file__).resolve().parents[1]/'invite/agent_labo'
sys.path.insert(0, str(AGENT))
spec = importlib.util.spec_from_file_location('telemetrie_etat_capteurs', AGENT/'telemetrie.py')
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
UNIT = 'labo-capteur-exec.service'
CGROUP = '/sawm.slice/sawm-defense.slice/'+UNIT
PROPS = {'Id': UNIT, 'LoadState': 'loaded', 'ActiveState': 'active', 'SubState': 'running',
         'MainPID': '593', 'ControlGroup': CGROUP, 'InvocationID': 'a'*32}
PERF = {'pid': 593, 'fd': 7, 'prog_id': 27, 'fd_type': 'tracepoint', 'tracepoint': 'sched_process_exec'}


def proc_stat(ticks):
    return '593 (bpftrace ) possible) '+' '.join(['S']+['0']*18+[str(ticks)]+['0']*5)


class EtatCapteursTests(unittest.TestCase):
    def observe(self, *, props=None, after=None, rows=None, error=None, perf_code=0,
                ticks=(55, 55, 55, 55), exe='/usr/bin/bpftrace', group=None):
        properties = dict(PROPS if props is None else props)
        systemd = iter([properties, properties if after is None else after])
        starts = iter(ticks)
        def read(path):
            if path == '/proc/sys/kernel/random/boot_id': return '00000000-0000-0000-0000-000000000001'
            if path == '/proc/593/stat': return proc_stat(next(starts))
            if path == '/proc/593/cgroup': return '0::'+(group or CGROUP)
            if path in ('/var/log/capteur_exec.jsonl', '/var/log/capteur_exec.err'): return ''
            if path == '/run/capteur_exec.pid':
                self.fail('Le PID-file historique ne doit pas décider de la santé du capteur')
            self.fail('Lecture inattendue : '+path)
        def run(args, **kwargs):
            self.assertTrue(kwargs['capture_output'])
            self.assertLessEqual(kwargs['timeout'], 1)
            if args[:3] == ['systemctl', 'show', UNIT]:
                return SimpleNamespace(returncode=0, stdout='\n'.join(k+'='+v for k, v in next(systemd).items()))
            self.assertEqual(args, ['bpftool', '-j', 'perf', 'show'])
            if error: raise error
            return SimpleNamespace(returncode=perf_code, stdout=json.dumps([PERF] if rows is None else rows))
        with patch.object(t, 'lire', side_effect=read), patch.object(t.subprocess, 'run', side_effect=run), \
                patch.object(t.os, 'readlink', return_value=exe), patch.object(t.os.path, 'exists', return_value=False), \
                patch.object(t, '_compteurs_bpf', return_value=None):
            return t.capteurs()

    def test_systemd_and_exact_perf_attachment_work_without_pidfile(self):
        status = self.observe()
        self.assertIs(status['ebpf_exec_actif'], True)
        self.assertIs(status['ebpf_exec_processus_actif'], True)
        self.assertEqual(status['ebpf_exec_preuve']['programme_ids'], [27])
        self.assertEqual(status['ebpf_exec_preuve']['starttime_ticks'], 55)
        self.assertEqual(status['ebpf_exec_preuve']['motif'], 'attachement_verifie')

    def test_live_process_without_matching_kernel_attachment_is_not_healthy(self):
        for rows in ([], [{**PERF, 'pid': 594}], [{**PERF, 'tracepoint': 'sys_enter_execve'}],
                     [{**PERF, 'fd_type': 'kprobe'}]):
            with self.subTest(rows=rows):
                status = self.observe(rows=rows)
                self.assertIs(status['ebpf_exec_processus_actif'], True)
                self.assertIs(status['ebpf_exec_actif'], False)
                self.assertEqual(status['ebpf_exec_preuve']['motif'], 'attachement_absent')

    def test_perf_failure_or_malformed_result_keeps_attachment_unknown(self):
        for changes in ({'perf_code': 1}, {'error': subprocess.TimeoutExpired('bpftool', 1)},
                        {'error': OSError('PRIVATE_ERROR')}, {'rows': {'pid': 593}},
                        {'rows': [None]}, {'rows': [{**PERF, 'pid': '593'}]},
                        {'rows': [{**PERF, 'prog_id': True}]}, {'rows': [{**PERF, 'fd': -1}]}):
            with self.subTest(changes=changes):
                status = self.observe(**changes)
                self.assertIs(status['ebpf_exec_processus_actif'], True)
                self.assertIsNone(status['ebpf_exec_actif'])
                self.assertEqual(status['ebpf_exec_preuve']['motif'], 'attachement_indisponible')
                self.assertNotIn('PRIVATE_ERROR', json.dumps(status))

    def test_pid_reuse_and_invocation_change_discard_even_matching_perf_proof(self):
        for changes in ({'ticks': (55, 56)}, {'ticks': (55, 55, 56, 56)},
                        {'after': {**PROPS, 'InvocationID': 'b'*32}},
                        {'after': {**PROPS, 'MainPID': '594'}}):
            with self.subTest(changes=changes):
                status = self.observe(**changes)
                self.assertIsNone(status['ebpf_exec_actif'])
                self.assertIsNone(status['ebpf_exec_processus_actif'])
                self.assertFalse(status['ebpf_exec_preuve']['identite_stable'])
                self.assertEqual(status['ebpf_exec_preuve']['programme_ids'], [])

    def test_wrong_executable_or_cgroup_cannot_impersonate_sensor(self):
        for changes in ({'exe': '/usr/bin/other'}, {'group': '/other.service'},
                        {'props': {**PROPS, 'ControlGroup': '/other.service'}},
                        {'props': {**PROPS, 'MainPID': '593;id'}}):
            with self.subTest(changes=changes):
                status = self.observe(**changes)
                self.assertIsNone(status['ebpf_exec_actif'])
                self.assertEqual(status['ebpf_exec_preuve']['motif'], 'identite_non_verifiee')

    def test_stably_inactive_service_is_distinct_from_unavailable_systemd(self):
        stopped = {**PROPS, 'ActiveState': 'inactive', 'SubState': 'dead', 'MainPID': '0'}
        status = self.observe(props=stopped)
        self.assertIs(status['ebpf_exec_actif'], False)
        self.assertIs(status['ebpf_exec_processus_actif'], False)
        self.assertEqual(status['ebpf_exec_preuve']['motif'], 'service_inactif')
        missing = self.observe(props={**PROPS, 'LoadState': 'not-found'})
        self.assertIsNone(missing['ebpf_exec_actif'])
        self.assertIsNone(missing['ebpf_exec_processus_actif'])
        self.assertEqual(missing['ebpf_exec_preuve']['motif'], 'observation_indisponible')


if __name__ == '__main__':
    unittest.main()
