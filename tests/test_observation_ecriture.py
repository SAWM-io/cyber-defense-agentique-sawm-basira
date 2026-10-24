"""Contrat de parsing/identité/BTF, sans VM ni attachement de sonde."""
import copy
import json
import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from controleur import observation_ecriture as obs


TARGET = {'pid': 42, 'inode': 900, 'device_major': 8, 'device_minor': 1}


def transcript(events=0, written=0, **metadata):
    meta = {'schema': 'sawm-vfs-write/v1', **TARGET,
            'observed_ns': 7_004_522_795, 'complete': 1, **metadata}
    messages = [{'type': 'printf', 'data': json.dumps(meta) + '\n'},
                {'type': 'map', 'data': {'@events': events}},
                {'type': 'map', 'data': {'@bytes': written}}]
    return '\n'.join(json.dumps(message) for message in messages)


def btf():
    return {'types': [
        {'id': 1, 'kind': 'STRUCT', 'name': 'file', 'size': 232,
         'members': [{'name': 'f_inode', 'type_id': 6, 'bits_offset': 1344}]},
        {'id': 2, 'kind': 'STRUCT', 'name': 'inode', 'size': 632,
         'members': [{'name': 'i_sb', 'type_id': 7, 'bits_offset': 448},
                     {'name': 'i_ino', 'type_id': 4, 'bits_offset': 640}]},
        {'id': 3, 'kind': 'STRUCT', 'name': 'super_block', 'size': 1408,
         'members': [{'name': 's_dev', 'type_id': 8, 'bits_offset': 128}]},
        {'id': 4, 'kind': 'INT', 'name': 'long unsigned int', 'size': 8,
         'bits_offset': 0, 'nr_bits': 64, 'encoding': '(none)'},
        {'id': 5, 'kind': 'INT', 'name': 'unsigned int', 'size': 4,
         'bits_offset': 0, 'nr_bits': 32, 'encoding': '(none)'},
        {'id': 6, 'kind': 'PTR', 'name': '(anon)', 'type_id': 2},
        {'id': 7, 'kind': 'PTR', 'name': '(anon)', 'type_id': 3},
        {'id': 8, 'kind': 'TYPEDEF', 'name': 'dev_t', 'type_id': 5},
    ]}


class ObservationEcritureTests(unittest.TestCase):
    def test_zero_and_successful_write_aggregates(self):
        for events, written in ((0, 0), (2, 8192)):
            with self.subTest(events=events):
                result = obs._parse_counts(transcript(events, written), TARGET)
                self.assertEqual(result['write_events'], events)
                self.assertEqual(result['written_bytes'], written)
                self.assertEqual(result['observed_ns'], 7_004_522_795)

    def test_incomplete_malformed_and_impossible_counts_rejected(self):
        cases = [transcript(complete=0), transcript(observed_ns=1),
                 transcript(True, 1), transcript(-1, 1), transcript(2, 1),
                 transcript(1, 0), transcript(1, 2**63), 'not json',
                 transcript() + '\n' + json.dumps({'type': 'map', 'data': {'@bytes': 0}}),
                 transcript().replace('"@bytes"', '"@events"')]
        for text in cases:
            with self.subTest(text=text), self.assertRaises(ValueError):
                obs._parse_counts(text, TARGET)

    def test_changed_target_identity_rejected(self):
        for key, value in (('pid', 43), ('inode', 901), ('device_major', 9), ('device_minor', 2)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                obs._parse_counts(transcript(2, 8192, **{key: value}), TARGET)

    def test_btf_offsets_alignment_bounds_pointer_and_integer_types(self):
        self.assertEqual(obs._layout_from_btf(json.dumps(btf())),
                         {'__FILE_INODE__': 168, '__INODE_SB__': 56,
                          '__INODE_INO__': 80, '__SUPER_DEV__': 16})
        cases = []
        unaligned = btf(); unaligned['types'][0]['members'][0]['bits_offset'] = 1345
        cases.append(unaligned)
        outside = btf(); outside['types'][0]['members'][0]['bits_offset'] = 232 * 8
        cases.append(outside)
        pointer = btf(); pointer['types'][5]['type_id'] = 3
        cases.append(pointer)
        size = btf(); size['types'][4]['size'] = 8
        cases.append(size)
        ambiguous = btf(); ambiguous['types'].append(copy.deepcopy(ambiguous['types'][0]))
        cases.append(ambiguous)
        for data in cases:
            with self.subTest(data=data), self.assertRaises(ValueError):
                obs._layout_from_btf(json.dumps(data))

    def test_scope_checked_before_transport_and_fixed_guest_source_compiles(self):
        with patch('controleur.vm_labo.json_code', return_value={'mock': True}) as transport:
            for unit, run in (('sshd.service', 'test'), ('labo-a;id.service', 'test'),
                              ('labo-ok.service', '../outside')):
                with self.subTest(unit=unit, run=run), self.assertRaises(ValueError):
                    obs.observer_ecritures(unit, run)
            transport.assert_not_called()
            self.assertEqual(obs.observer_ecritures('labo-ok.service', 'test'), {'mock': True})
            compile(transport.call_args.args[0], 'guest-source', 'exec')
            self.assertEqual(transport.call_args.kwargs, {'timeout': 17})
        self.assertNotIn('BEGIN', obs._PROGRAM)
        self.assertNotIn('END', obs._PROGRAM)
        self.assertIn('(int64)retval', obs._PROGRAM)
        self.assertIn('nsecs - @started', obs._PROGRAM)


if __name__ == '__main__':
    unittest.main()
