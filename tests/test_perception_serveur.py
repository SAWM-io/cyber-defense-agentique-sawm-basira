"""Perception permanente simulée : cadence, périmètre et réarmement, sans VM."""
import copy
import pathlib
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from controleur.perception_serveur import PerceptionServeur

UNIT = 'labo-work.service'


def manifest(units=None):
    units = units or [UNIT]
    return {'unites_autorisees': units, 'unites_protegees': [],
            'veille': {'enquete_autonome': True, 'unites_surveillees': units}}


def observed(unit=UNIT, *, cpu=10, ram=20, pid=42, start=12345):
    cg = '/sawm.slice/sawm-charge.slice/' + unit
    identity = {'pid': pid, 'starttime_ticks': start, 'cgroup': cg,
                'boot_id': '12345678-1234-1234-1234-123456789abc', 'invocation_id': 'a' * 32,
                'systemd': {'Id': unit, 'LoadState': 'loaded', 'ActiveState': 'active',
                            'MainPID': str(pid), 'ControlGroup': cg, 'InvocationID': 'a' * 32}}
    return {'schema': 'sawm-server-inspection/v1', 'action': 'inspecter-processus', 'unit': unit,
            'observed_epoch_ms': 1_800_000_000_000, 'observation_valid': True,
            'identity_stable': True, 'before': identity, 'after': copy.deepcopy(identity),
            'evidence': {'process': {'cpu_percent_one_core': cpu,
                                     'rss_bytes': int(ram * 1024**2),
                                     'sample_elapsed_seconds': .501}}}


class PerceptionServeurTests(unittest.TestCase):
    def test_strict_opt_in_and_root_scope_protected_units(self):
        for flag in (False, None, 'true', 1):
            m = manifest(); m['veille']['enquete_autonome'] = flag
            inspector = Mock()
            self.assertEqual(PerceptionServeur().analyser(m, inspecter_fn=inspector, now=lambda: 0), [])
            inspector.assert_not_called()
        m = manifest([UNIT, 'labo-temoin.service', 'labo-secret.service'])
        m['unites_protegees'] = ['labo-secret']
        m['veille']['unites_surveillees'] += ['labo-foreign.service', 'sshd.service', 'labo-a;id.service']
        inspector = Mock(return_value=observed())
        monitor = PerceptionServeur()
        monitor.analyser(m, inspecter_fn=inspector, now=lambda: 0)
        inspector.assert_called_once_with('inspecter-processus', UNIT)

    def test_one_inspection_per_call_max_eight_targets_and_ten_second_interval(self):
        units = [f'labo-work-{index}.service' for index in range(10)]
        m = manifest(units)
        inspector = Mock(side_effect=lambda action, unit: observed(unit))
        monitor = PerceptionServeur()
        for index in range(8):
            monitor.analyser(m, inspecter_fn=inspector, now=lambda: 0)
            self.assertEqual(inspector.call_count, index + 1)
        monitor.analyser(m, inspecter_fn=inspector, now=lambda: 9.999)
        self.assertEqual(inspector.call_count, 8)
        monitor.analyser(m, inspecter_fn=inspector, now=lambda: 10)
        self.assertEqual(inspector.call_count, 9)
        self.assertEqual(inspector.call_args.args, ('inspecter-processus', units[0]))
        self.assertEqual({call.args[1] for call in inspector.call_args_list}, set(units[:8]))

    def test_overload_deduplicates_and_rearms_after_baseline_or_new_identity(self):
        monitor = PerceptionServeur()
        inspector = Mock(side_effect=[observed(cpu=90), observed(cpu=99), observed(cpu=20),
                                      observed(cpu=90), observed(cpu=90, pid=43, start=54321)])
        outputs = [monitor.analyser(manifest(), inspecter_fn=inspector, now=lambda t=t: t)
                   for t in (0, 10, 20, 30, 40)]
        self.assertEqual([len(output) for output in outputs], [1, 0, 0, 1, 1])
        events = [output[0] for output in outputs if output]
        self.assertEqual(len({event['id'] for event in events}), 3)
        for event in events:
            self.assertEqual(event['genre'], 'ressources_a_enqueter')
            self.assertTrue(event['analysable'])
            self.assertEqual(event['canal'], 'incident')
            self.assertEqual(event['survenu_observe_ms'], 1_800_000_000_000)
            self.assertEqual(event['identite_os'], event['faits'][0]['identite_os'])
        self.assertEqual(events[1]['faits'][0]['mesures']['cpu_delta_points'], 70)
        self.assertEqual(monitor.derniere_unite, UNIT)
        self.assertEqual(monitor.derniere_observation['before']['pid'], 43)

    def test_cpu_and_ram_classes_have_independent_rearming(self):
        monitor = PerceptionServeur()
        inspector = Mock(side_effect=[observed(cpu=80), observed(cpu=90, ram=256),
                                      observed(cpu=10, ram=300), observed(cpu=85, ram=300)])
        outputs = [monitor.analyser(manifest(), inspecter_fn=inspector, now=lambda t=t: t)
                   for t in (0, 10, 20, 30)]
        self.assertEqual(outputs[0][0]['faits'][0]['classes'], ['cpu'])
        self.assertEqual(outputs[1][0]['faits'][0]['classes_nouvellement_declenchees'], ['ram'])
        self.assertEqual(outputs[2], [])
        self.assertEqual(outputs[3][0]['faits'][0]['classes_nouvellement_declenchees'], ['cpu'])

    def test_missing_inactive_and_changed_identity_are_observations_only(self):
        bad = observed(cpu=100)
        bad['after']['starttime_ticks'] += 1
        inactive = observed(cpu=100)
        inactive['before']['systemd']['ActiveState'] = 'inactive'
        inactive['after'] = copy.deepcopy(inactive['before'])
        incomplete = observed(cpu=100)
        incomplete['evidence']['process']['cpu_percent_one_core'] = True
        for response in (None, {}, bad, inactive, incomplete):
            with self.subTest(response=response):
                monitor = PerceptionServeur()
                inspector = Mock(return_value=response)
                first = monitor.analyser(manifest(), inspecter_fn=inspector, now=lambda: 0)
                second = monitor.analyser(manifest(), inspecter_fn=inspector, now=lambda: 10)
                self.assertEqual(len(first), 1)
                self.assertFalse(first[0]['analysable'])
                self.assertEqual(first[0]['canal'], 'observation')
                self.assertEqual(second, [])

    def test_read_failure_preserves_high_state_and_does_not_retrigger(self):
        monitor = PerceptionServeur()
        inspector = Mock(side_effect=[observed(cpu=90), RuntimeError('private error'), observed(cpu=95)])
        outputs = [monitor.analyser(manifest(), inspecter_fn=inspector, now=lambda t=t: t)
                   for t in (0, 10, 20)]
        self.assertTrue(outputs[0][0]['analysable'])
        self.assertFalse(outputs[1][0]['analysable'])
        self.assertNotIn('private error', str(outputs[1]))
        self.assertEqual(outputs[2], [])

    def test_initial_incident_id_ignores_measurements_timestamp_and_prior_notices(self):
        first = PerceptionServeur().analyser(manifest(), inspecter_fn=Mock(return_value=observed(cpu=90)),
                                             now=lambda: 0)[0]
        monitor = PerceptionServeur()
        monitor.analyser(manifest(), inspecter_fn=Mock(side_effect=RuntimeError()), now=lambda: 0)
        later = observed(cpu=99)
        later['observed_epoch_ms'] += 99999
        second = monitor.analyser(manifest(), inspecter_fn=Mock(return_value=later), now=lambda: 10)[0]
        self.assertEqual(first['id'], second['id'])

    def test_manifest_thresholds_and_invalid_thresholds(self):
        m = manifest(); m['veille'].update(cpu_alerte_pct=25, ram_alerte_mio=64)
        inspector = Mock(return_value=observed(cpu=26, ram=65))
        result = PerceptionServeur().analyser(m, inspecter_fn=inspector, now=lambda: 0)
        self.assertEqual(result[0]['faits'][0]['classes'], ['cpu', 'ram'])
        for value in (0, -1, True, float('nan'), float('inf'), '80'):
            m['veille']['cpu_alerte_pct'] = value
            inspector.reset_mock()
            result = PerceptionServeur().analyser(m, inspecter_fn=inspector, now=lambda: 0)
            self.assertFalse(result[0]['analysable'])
            inspector.assert_not_called()


if __name__ == '__main__':
    unittest.main()
