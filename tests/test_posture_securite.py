"""Configuration observée, sorties privées filtrées et cache sans commandes réelles."""
import copy
from contextlib import ExitStack
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

AGENT = Path(__file__).resolve().parents[1]/'invite/agent_labo'
sys.path.insert(0, str(AGENT))
import posture_securite as p

NOW = 1_800_000_000_000
SSH = 'permitrootlogin no\npasswordauthentication no\npermitemptypasswords no\nmaxauthtries 4\n'
VALUES = {path: ('2' if identifier == 'os_aslr' else '1') for identifier, path, _, _ in p.SYSCTLS}


def runner(command):
    return {p.SSHD: (0, SSH), p.AUDITD: (0, 'active\n'), p.NTP: (0, 'yes\n')}[command]


def collect(**kwargs):
    return p.collect(read_file=kwargs.pop('read_file', VALUES.__getitem__),
                     run_command=kwargs.pop('run_command', runner),
                     platform=kwargs.pop('platform', 'linux'), observed_ms=NOW, **kwargs)


def by_id(result):
    return {row['id']: row for row in result['controls']}


class PostureObservationTests(unittest.TestCase):
    def test_measured_profile_has_twelve_bounded_controls(self):
        result = collect()
        self.assertEqual(result['schema'], 'sawm-posture-os/v1')
        self.assertEqual(result['observed_ms'], NOW)
        self.assertEqual(len(result['controls']), 12)
        self.assertTrue(all(row['status'] == 'satisfait' for row in result['controls']))
        self.assertTrue(all(set(row) == {'id','status','source','observed_value','expected','limitation'} for row in result['controls']))
        self.assertEqual(by_id(result)['os_aslr']['observed_value'], 2)

    def test_missing_files_and_commands_remain_unknown(self):
        result = collect(read_file=Mock(side_effect=PermissionError('private path')),
                         run_command=Mock(side_effect=FileNotFoundError('private config')))
        self.assertTrue(all(row['status'] == 'inconnu' and row['observed_value'] is None for row in result['controls']))
        self.assertNotIn('private', json.dumps(result))

    def test_non_linux_never_calls_system_readers(self):
        reader, run = Mock(side_effect=AssertionError), Mock(side_effect=AssertionError)
        result = collect(platform='darwin', read_file=reader, run_command=run)
        reader.assert_not_called(); run.assert_not_called()
        self.assertTrue(all(row['status'] == 'inconnu' for row in result['controls']))

    def test_observed_deviations_are_not_unknown_or_malware_claims(self):
        def changed(command):
            return {p.SSHD:(0, SSH.replace(' no', ' yes').replace('tries 4', 'tries 9')),
                    p.AUDITD:(3,'inactive'), p.NTP:(0,'no')}[command]
        result = collect(read_file=lambda _: '0', run_command=changed)
        self.assertTrue(all(row['status'] == 'ecart' for row in result['controls']))
        self.assertNotIn('malware', json.dumps(result))

    def test_malformed_kernel_values_are_unknown(self):
        for value in ('-1', '1;reboot', 'nan', '100000', '', None, True):
            with self.subTest(value=value):
                rows=collect(read_file=lambda _: value)['controls'][:6]
                self.assertTrue(all(row['status']=='inconnu' for row in rows))

    def test_config_secrets_and_unknown_keys_never_leave_probe(self):
        raw = SSH + 'banner secret-file-content\nprivatekey ULTRA_PRIVATE_VALUE\n'
        result=collect(run_command=lambda cmd: (0, raw) if cmd==p.SSHD else runner(cmd))
        self.assertNotIn('ULTRA_PRIVATE_VALUE', json.dumps(result))
        self.assertNotIn('secret-file-content', json.dumps(result))
        self.assertTrue(all(by_id(result)[row[0]]['status']=='satisfait' for row in p.SSH_KEYS))

    def test_duplicate_or_unparseable_ssh_option_is_unknown(self):
        for raw in (SSH+'permitrootlogin no\n', SSH.replace('permitrootlogin no','permitrootlogin'),
                    SSH.replace('permitrootlogin no','permitrootlogin unrecognized')):
            with self.subTest(raw=raw):
                result=collect(run_command=lambda cmd:(0,raw) if cmd==p.SSHD else runner(cmd))
                self.assertEqual(by_id(result)['os_ssh_root_login']['status'],'inconnu')

    def test_command_failures_oversize_and_bad_status_are_unknown(self):
        for command_result in ((1,'active'),(0,'x'*(p.MAX_OUTPUT+1)),(True,'active'),['0','yes'],(0,'yes extra')):
            with self.subTest(result=command_result):
                rows=collect(run_command=lambda _: command_result)['controls'][6:]
                self.assertTrue(all(row['status']=='inconnu' for row in rows))

    def test_status_recomputed_from_typed_values_not_claims(self):
        self.assertEqual(p.status_for('os_aslr', 0), 'ecart')
        self.assertEqual(p.status_for('os_aslr', 2), 'satisfait')
        self.assertEqual(p.status_for('os_ssh_max_authtries', 4), 'satisfait')
        self.assertEqual(p.status_for('os_ssh_max_authtries', 5), 'ecart')
        for identifier, value in (('os_aslr', True), ('os_kptr_restrict', 9999),
                                  ('os_ptrace_scope', -1), ('os_auditd_active', 'satisfait'),
                                  ('os_ssh_password_auth', {'value': 'no'}), ([], 'no')):
            with self.subTest(identifier=identifier, value=value):
                self.assertEqual(p.status_for(identifier, value), 'inconnu')

    def test_audit_exit_code_and_active_text_must_agree(self):
        for contradictory in ((3, 'active'), (0, 'inactive')):
            with self.subTest(result=contradictory):
                rows=by_id(collect(run_command=lambda cmd: contradictory if cmd==p.AUDITD else runner(cmd)))
                self.assertEqual(rows['os_auditd_active']['status'], 'inconnu')
                self.assertIsNone(rows['os_auditd_active']['observed_value'])

    def test_fixed_commands_only_and_bounded_reader(self):
        with patch.object(p.subprocess,'Popen') as spawn:
            with self.assertRaises(ValueError): p._run_command(('/bin/sh','-c','anything'))
            with self.assertRaises(ValueError): p._run_command(list(p.SSHD))
            spawn.assert_not_called()
        with patch.object(p.Path,'open') as opened:
            opened.return_value.__enter__.return_value.read.return_value=b'0'*65
            with self.assertRaises(ValueError): p._read_file(p.SYSCTLS[0][1])
            opened.return_value.__enter__.return_value.read.assert_called_once_with(65)
        with self.assertRaises(ValueError): p._read_file('/etc/shadow')

    def test_command_output_bound_kills_only_its_child(self):
        process=Mock(); process.stdout.fileno.return_value=123; process.poll.return_value=None
        selector=Mock();selector.select.return_value=[(object(),1)]
        with patch.object(p.subprocess,'Popen',return_value=process) as spawn, \
             patch.object(p.selectors,'DefaultSelector',return_value=selector), \
             patch.object(p.os,'read',return_value=b'x'*(p.MAX_OUTPUT+1)):
            with self.assertRaisesRegex(ValueError,'trop longue'): p._run_command(p.SSHD)
        process.kill.assert_called_once(); process.wait.assert_called_once_with(timeout=1)
        process.stdout.close.assert_called_once()
        self.assertFalse(spawn.call_args.kwargs['shell'])
        self.assertEqual(spawn.call_args.args,(p.SSHD,))
        self.assertEqual(spawn.call_args.kwargs['stderr'],p.subprocess.DEVNULL)

    def test_command_timeout_is_bounded(self):
        process=Mock();process.poll.return_value=None
        selector=Mock();selector.select.return_value=[]
        with patch.object(p.subprocess,'Popen',return_value=process), \
             patch.object(p.selectors,'DefaultSelector',return_value=selector):
            with self.assertRaises(TimeoutError): p._run_command(p.AUDITD)
        self.assertLessEqual(selector.select.call_args.args[0],p.COMMAND_TIMEOUT)
        process.kill.assert_called_once(); process.stdout.close.assert_called_once()


class DeferredThread:
    def __init__(self, target, **kwargs): self.target=target;self.alive=False
    def start(self): self.alive=True
    def is_alive(self): return self.alive
    def finish(self): self.target();self.alive=False


class PostureCacheTests(unittest.TestCase):
    def setUp(self):
        self.wall=NOW/1000;self.mono=100.;self.threads=[]
        def factory(**kwargs):
            thread=DeferredThread(**kwargs);self.threads.append(thread);return thread
        self.patch=patch.object(p.threading,'Thread',side_effect=factory);self.patch.start();self.addCleanup(self.patch.stop)
        self.loader=Mock(side_effect=lambda observed_ms: p.collect(platform='linux',read_file=VALUES.__getitem__,run_command=runner,observed_ms=observed_ms))
        self.cache=p.PostureCache(loader=self.loader,wall=lambda:self.wall,monotone=lambda:self.mono)

    def prime(self):
        first=self.cache.snapshot();self.threads[-1].finish();return first

    def test_initial_state_unknown_then_original_date_preserved_and_copied(self):
        first=self.prime();self.assertTrue(all(r['status']=='inconnu' for r in first['controls']))
        self.wall+=15;self.mono+=15
        result=self.cache.snapshot();self.assertEqual(result['observed_ms'],NOW)
        result['controls'].clear()
        self.assertEqual(len(self.cache.snapshot()['controls']),12)
        self.loader.assert_called_once()

    def test_ttl_expiry_does_not_refresh_old_evidence_timestamp(self):
        self.prime();self.wall+=60;self.mono+=60
        expired=self.cache.snapshot()
        self.assertTrue(all(r['status']=='inconnu' for r in expired['controls']))
        self.assertEqual(len(self.threads),2)
        self.threads[-1].finish()
        self.assertEqual(self.cache.snapshot()['observed_ms'],NOW+60000)
        self.assertEqual(self.loader.call_count,2)

    def test_refresh_before_expiry_preserves_dated_proof_without_gap(self):
        self.prime();old=self.cache.snapshot()
        self.wall+=50;self.mono+=50
        self.assertEqual(self.cache.snapshot(),old)
        self.assertEqual(len(self.threads),2)
        self.cache.snapshot();self.assertEqual(len(self.threads),2)
        self.threads[-1].finish()
        self.assertEqual(self.cache.snapshot()['observed_ms'],NOW+50000)
        self.assertEqual(self.loader.call_count,2)

    def test_backward_wall_or_monotone_clock_invalidates_cache(self):
        self.prime();self.wall-=10
        result=self.cache.snapshot()
        self.assertLessEqual(result['observed_ms'],int(self.wall*1000))
        self.assertTrue(all(r['status']=='inconnu' for r in result['controls']))
        self.threads[-1].finish();self.mono-=1
        self.assertTrue(all(r['status']=='inconnu' for r in self.cache.snapshot()['controls']))

    def test_one_inflight_read_and_exception_never_breaks_telemetry(self):
        self.loader.side_effect=RuntimeError('secret failure')
        self.cache.snapshot();self.cache.snapshot();self.assertEqual(len(self.threads),1)
        self.threads[0].finish()
        result=self.cache.snapshot()
        self.assertNotIn('secret failure',json.dumps(result))
        self.assertTrue(all(r['status']=='inconnu' for r in result['controls']))
        with patch.object(p,'_CACHE',Mock(snapshot=Mock(side_effect=RuntimeError))):
            self.assertTrue(all(r['status']=='inconnu' for r in p.snapshot()['controls']))

    def test_future_report_from_loader_never_reaches_telemetry_as_valid(self):
        self.loader.side_effect=lambda observed_ms: p.unknown(observed_ms+1000)
        self.prime()
        result=self.cache.snapshot()
        self.assertEqual(result['observed_ms'],NOW)
        self.assertTrue(all(r['status']=='inconnu' for r in result['controls']))


class PostureTelemetryTests(unittest.TestCase):
    def test_snapshot_is_connected_to_real_sample_without_retimestamp(self):
        spec=importlib.util.spec_from_file_location('telemetrie_posture',AGENT/'telemetrie.py')
        telemetry=importlib.util.module_from_spec(spec);spec.loader.exec_module(telemetry)
        measured=collect()
        with ExitStack() as stack:
            for name in ('cpu_global','memoire','disque','reseau','champ_cgroup','chemin_tranche','capteurs',
                         'service_temoin','recepteur','connexions','authentification','defense_fichiers','integrite_arbres'):
                stack.enter_context(patch.object(telemetry,name,return_value=None))
            stack.enter_context(patch.object(telemetry,'lire',return_value='0 0 0'))
            stack.enter_context(patch.object(telemetry,'geographie_reseau',return_value={}))
            stack.enter_context(patch.object(telemetry.capteur_fichiers,'etat',return_value={}))
            stack.enter_context(patch.object(telemetry.ssh_observation,'etat',return_value={}))
            stack.enter_context(patch.object(telemetry.posture_securite,'snapshot',return_value=copy.deepcopy(measured)))
            sample=telemetry.echantillon(5)
        self.assertEqual(sample['posture_securite'],measured)
        self.assertEqual(sample['posture_securite']['observed_ms'],NOW)
        self.assertEqual(sample['sequence'],5)


if __name__=='__main__': unittest.main()
