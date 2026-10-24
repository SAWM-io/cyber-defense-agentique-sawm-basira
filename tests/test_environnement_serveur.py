"""Inspections simulées : pas de VM, de shell ou de socket réellement ouvert."""
import contextlib
import io
import json
import pathlib
import pwd
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from controleur import environnement_serveur as server

UNIT = 'labo-test.service'
CG = '/sawm.slice/sawm-charge.slice/' + UNIT


def proc_stat(pid=42, *, ticks=120):
    fields = ['0'] * 22
    fields[0] = 'S'; fields[11] = str(ticks); fields[12] = '10'
    fields[17] = '1'; fields[19] = '98765'; fields[21] = '10'
    return f'{pid} (untrusted (name)) ' + ' '.join(fields)


def run_guest_mock(source, *, changed=False):
    """Exécute le code invité en remplaçant toutes ses lectures système."""
    files = {'/proc/42/stat': proc_stat(), '/proc/42/cgroup': '0::' + CG + '\n',
             '/proc/42/status': 'Uid:\t0\t0\t0\t0\nVmRSS:\t40 kB\n',
             '/proc/42/loginuid': '4294967295\n',
             '/proc/42/io': '\n'.join(f'{key}: 10' for key in
                 ('rchar', 'wchar', 'syscr', 'syscw', 'read_bytes', 'write_bytes', 'cancelled_write_bytes')),
             '/proc/sys/kernel/random/boot_id': '12345678-1234-1234-1234-123456789abc',
             '/sys/fs/cgroup' + CG + '/cpu.stat': 'usage_usec 150\nuser_usec 100\nsystem_usec 50\n',
             '/sys/fs/cgroup' + CG + '/cpu.max': '25000 100000\n',
             '/sys/fs/cgroup' + CG + '/memory.current': '8192\n',
             '/sys/fs/cgroup' + CG + '/memory.max': 'max\n'}
    systemd_calls = []
    clock = [0.0]

    def fake_open(path, mode='r', *args, **kwargs):
        if mode != 'r' or str(path) not in files:
            raise AssertionError('unexpected filesystem operation')
        return io.StringIO(files[str(path)])

    def fake_run(args, **kwargs):
        if args[0] == 'systemctl':
            if args != ['systemctl', 'show', '--property=Id,LoadState,ActiveState,MainPID,ControlGroup,InvocationID', '--', UNIT]:
                raise AssertionError('unexpected command')
            systemd_calls.append(args)
            invocation = 'b' * 32 if changed and len(systemd_calls) == 2 else 'a' * 32
            text = f'Id={UNIT}\nLoadState=loaded\nActiveState=active\nMainPID=42\nControlGroup={CG}\nInvocationID={invocation}\n'
        elif args == ['ss', '-Hntp']:
            text = 'ESTAB 0 0 127.0.0.1:3210 127.0.0.1:9009 users:(("python3",pid=42,fd=3))\n'
        else:
            raise AssertionError('unexpected command')
        return subprocess.CompletedProcess(args, 0, text, '')

    def monotonic():
        clock[0] += .001
        return clock[0]

    def sleep(duration):
        if duration != .5:
            raise AssertionError('unexpected sample duration')
        clock[0] += duration

    @contextlib.contextmanager
    def scan(path):
        if str(path) != '/proc/42/fd':
            raise AssertionError('unexpected directory')
        yield iter([types.SimpleNamespace(name=str(i)) for i in range(4)])

    account = types.SimpleNamespace(pw_name='root', pw_gid=0)
    with patch('builtins.open', side_effect=fake_open), \
         patch('subprocess.run', side_effect=fake_run), \
         patch('os.scandir', side_effect=scan), \
         patch('os.readlink', return_value='/usr/bin/python3'), \
         patch('os.sysconf', side_effect=lambda name: {'SC_PAGE_SIZE': 4096, 'SC_CLK_TCK': 100}[name]), \
         patch.object(pwd, 'getpwuid', return_value=account), \
         patch('time.monotonic', side_effect=monotonic), \
         patch('time.sleep', side_effect=sleep), contextlib.redirect_stdout(io.StringIO()) as output:
        exec(compile(source, 'mock-guest', 'exec'), {})
    return json.loads(output.getvalue())


class EnvironnementServeurTests(unittest.TestCase):
    def test_actions_targets_and_context_rejected_before_transport(self):
        with patch('controleur.vm_labo.json_code') as vm:
            for action, unit, context in (
                ('bloquer-compte', UNIT, None), ('inspecter-base', UNIT, None),
                ('inspecter-processus', 'sshd.service', None),
                ('inspecter-compte', 'labo-a;id.service', None),
                ('inspecter-connexions', '../labo-a.service', None),
                ('inspecter-compte', UNIT, []),
                ('inspecter-compte', UNIT, {'justification': 'x' * 513})):
                with self.subTest(action=action, unit=unit), self.assertRaises(ValueError):
                    server.inspecter(action, unit, contexte=context)
            vm.assert_not_called()

    def test_mock_process_measurement_has_stable_identity_and_no_human_inference(self):
        with patch('controleur.vm_labo.json_code', side_effect=lambda source, **_: run_guest_mock(source)) as vm:
            result = server.inspecter('inspecter-processus', UNIT,
                contexte={'decision_id': 'd1', 'justification': 'Observer la consommation.', 'command': 'ignored'})
        self.assertEqual(vm.call_args.kwargs, {'timeout': 12})
        self.assertTrue(result['observation_valid'])
        self.assertTrue(result['identity_stable'])
        self.assertEqual(result['before'], result['after'])
        self.assertEqual(result['choix_sawm']['decision_id'], 'd1')
        self.assertNotIn('ignored', vm.call_args.args[0])
        evidence = result['evidence']
        self.assertEqual(evidence['exe_basename'], 'python3')
        self.assertEqual(evidence['process']['rss_bytes'], 40960)
        self.assertGreaterEqual(evidence['process']['sample_elapsed_seconds'], .5)
        self.assertEqual(evidence['process']['file_descriptors']['count'], 4)
        self.assertEqual(evidence['cgroup']['counters']['cpu_quota_us'], 25000)
        self.assertTrue(evidence['cgroup']['counters']['memory_unlimited'])
        self.assertEqual(result['human_actor'], 'unknown')
        self.assertFalse(result['human_actor_inferred'])
        self.assertEqual(evidence['credentials']['effective_account']['name'], 'root')
        self.assertIsNone(evidence['credentials']['loginuid'])
        self.assertFalse(evidence['credentials']['loginuid_known'])
        self.assertEqual(result['errors'], {})

    def test_changed_systemd_invocation_invalidates_all_evidence(self):
        with patch('controleur.vm_labo.json_code', side_effect=lambda source, **_: run_guest_mock(source, changed=True)):
            result = server.inspecter('inspecter-compte', UNIT)
        self.assertFalse(result['observation_valid'])
        self.assertFalse(result['identity_stable'])
        self.assertIsNone(result['evidence'])
        self.assertEqual(result['reason'], 'identity_changed')

    def test_connections_are_bound_to_exact_pid_not_program_name(self):
        text = '\n'.join((
            'ESTAB 0 0 127.0.0.1:3210 127.0.0.1:9009 users:(("python3",pid=42,fd=3))',
            'ESTAB 0 0 127.0.0.1:5555 127.0.0.1:6666 users:(("evil-pid=42,",pid=142,fd=4))',
            'ESTAB 0 0 [::1]:4567 [::1]:9009 users:(("python3",pid=142,fd=4),("python3",pid=42,fd=5))'))
        parsed = server._parse_connections(text, 42)
        self.assertEqual(parsed['observed_count'], 2)
        self.assertTrue(all(row['owner_pid'] == 42 for row in parsed['connections']))
        self.assertIsNone(parsed['network_volume_bytes'])
        many = server._parse_connections((text.splitlines()[0] + '\n') * 20, 42)
        self.assertEqual(len(many['connections']), 16)
        self.assertTrue(many['truncated'])
        self.assertEqual(many['observed_count'], 20)
        with self.assertRaises(ValueError):
            server._parse_connections('x' * 262145, 42)

    def test_mock_connections_action_and_no_arbitrary_command(self):
        with patch('controleur.vm_labo.json_code', side_effect=lambda source, **_: run_guest_mock(source)):
            result = server.inspecter('inspecter-connexions', UNIT)
        self.assertEqual(result['evidence']['connections']['observed_count'], 1)
        self.assertEqual(result['evidence']['connections']['connections'][0]['peer'], '127.0.0.1:9009')

    def test_proc_stat_parentheses_pid_and_transport_contract(self):
        result = server._parse_stat(proc_stat(), 42, 4096)
        self.assertEqual(result['cpu_ticks'], 130)
        self.assertEqual(result['starttime_ticks'], 98765)
        with self.assertRaises(ValueError):
            server._parse_stat(proc_stat(43), 42, 4096)
        for response in ({}, {'schema': 'sawm-server-inspection/v1', 'action': 'inspecter-compte',
                              'unit': 'sshd.service', 'observation_valid': True}):
            with patch('controleur.vm_labo.json_code', return_value=response), self.assertRaises(ValueError):
                server.inspecter('inspecter-compte', UNIT)


if __name__ == '__main__':
    unittest.main()
