"""Real temporary files, streaming/race/error contracts; no network or VM."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1]/'invite/agent_labo/large_tree.py'
spec = importlib.util.spec_from_file_location('sawm_large_tree_tests', SOURCE)
lt = importlib.util.module_from_spec(spec); spec.loader.exec_module(lt)
FAST = dict(chunk_bytes=128, block_bytes=256, bytes_per_second=1024**3)


class LargeTreeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve(); self.root = self.base/'tree'; self.root.mkdir()
        self.path = self.root/'data.bin'; self.path.write_bytes(bytes(range(256))*8)
        self.reference = self.base/'approved.json'

    def enroll(self):
        receipt = lt.approve_baseline(str(self.root), str(self.reference), FAST)
        baseline = lt.read_trusted(str(self.reference), str(self.root), receipt['baseline_sha256'])
        return receipt, baseline

    def test_streams_whole_and_block_hashes_with_fixed_read_cap(self):
        actual = os.read; lengths = []
        def observed(fd, count): lengths.append(count); return actual(fd, count)
        with patch.object(lt.os, 'read', side_effect=observed):
            result = lt.scan_tree(str(self.root), FAST)
        content = self.path.read_bytes(); item = result['entries']['data.bin']
        self.assertEqual(result['status'], 'complete')
        self.assertTrue(lengths); self.assertLessEqual(max(lengths), 128)
        self.assertEqual(item['sha256'], hashlib.sha256(content).hexdigest())
        self.assertEqual(item['blocks'], [hashlib.sha256(content[i:i+256]).hexdigest() for i in range(0,len(content),256)])
        self.assertEqual(result['metrics']['bytes_read'], len(content))

    def test_same_size_mutation_add_delete_rename_and_permissions_are_visible(self):
        (self.root/'deleted').write_bytes(b'delete'); (self.root/'renamed').write_bytes(b'rename')
        _, baseline = self.enroll()
        with self.path.open('r+b') as stream: stream.seek(300); stream.write(b'changed')
        (self.root/'deleted').unlink(); (self.root/'renamed').rename(self.root/'new-name')
        (self.root/'added').write_bytes(b'new'); self.path.chmod(0o600)
        result = lt.compare(baseline, lt.scan_tree(str(self.root), FAST))
        self.assertEqual(result['status'], 'changed')
        self.assertEqual(set(result['counts']), {'content_changed','added','deleted','rename_candidate','permissions_changed'})
        changed = next(x for x in result['changes'] if x['kind']=='content_changed')
        self.assertEqual(changed['changed_block_indexes'], [1])
        self.assertEqual(result['attribution'], 'unknown'); self.assertFalse(result['action_performed'])

    def test_short_reads_keep_exact_block_boundaries(self):
        actual=os.read
        with patch.object(lt.os,'read',side_effect=lambda fd,count:actual(fd,min(count,19))):
            result=lt.scan_tree(str(self.root),FAST)
        data=self.path.read_bytes()
        self.assertEqual(result['entries']['data.bin']['blocks'],
                         [hashlib.sha256(data[i:i+256]).hexdigest() for i in range(0,len(data),256)])

    def test_earlier_file_modified_while_later_file_is_read_is_inconclusive(self):
        later=self.root/'zzz.bin';later.write_bytes(b'last file')
        actual=os.read;changed=False;late_inode=later.stat().st_ino
        def racing(fd,count):
            nonlocal changed
            chunk=actual(fd,count)
            if not changed and os.fstat(fd).st_ino==late_inode:
                changed=True
                with self.path.open('r+b') as stream:stream.write(b'changed afterwards')
            return chunk
        with patch.object(lt.os,'read',side_effect=racing):result=lt.scan_tree(str(self.root),FAST)
        self.assertEqual(result['status'],'inconclusive')
        self.assertIn('change_apres_lecture',result['reason'])

    def test_owner_and_replaced_object_are_separate_even_when_content_equal(self):
        _, baseline = self.enroll()
        self.path.rename(self.base/'old-inode'); self.path.write_bytes((self.base/'old-inode').read_bytes())
        current = lt.scan_tree(str(self.root), FAST)
        current['entries']['data.bin']['uid'] += 1  # OS-independent representation contract.
        result = lt.compare(baseline, current)
        self.assertIn('object_replaced', result['counts']); self.assertIn('owner_changed',result['counts'])
        self.assertNotIn('content_changed', result['counts'])

    def test_reference_requires_explicit_approval_and_never_overwrites(self):
        receipt, baseline = self.enroll()
        self.assertEqual(lt.compare(baseline,lt.scan_tree(str(self.root),FAST))['status'],'unchanged')
        with self.assertRaisesRegex(ValueError,'reference_existante'):
            lt.approve_baseline(str(self.root),str(self.reference),FAST)
        self.reference.write_text('{}')
        with self.assertRaisesRegex(ValueError,'empreinte_reference'):
            lt.read_trusted(str(self.reference),str(self.root),receipt['baseline_sha256'])

    def test_reference_or_output_inside_tree_and_symbolic_paths_refused(self):
        with self.assertRaisesRegex(ValueError,'dans_arbre'):
            lt.approve_baseline(str(self.root),str(self.root/'baseline'),FAST)
        link = self.base/'link'; link.symlink_to(self.root, target_is_directory=True)
        result = lt.scan_tree(str(link),FAST)
        self.assertEqual(result['status'],'inconclusive')
        (self.root/'external-link').symlink_to('/etc/passwd')
        result=lt.scan_tree(str(self.root),FAST)
        self.assertIn('lien_symbolique_refuse',result['reason']); self.assertEqual(result['entries'],{})

    def test_mutation_during_read_never_becomes_approved_or_unchanged(self):
        actual=os.read; changed=False
        def racing(fd,count):
            nonlocal changed
            chunk=actual(fd,count)
            if not changed:
                changed=True
                with self.path.open('r+b') as stream:stream.seek(0);stream.write(b'altered')
            return chunk
        with patch.object(lt.os,'read',side_effect=racing):result=lt.scan_tree(str(self.root),FAST)
        self.assertEqual(result['status'],'inconclusive');self.assertEqual(result['entries'],{})
        self.assertIn('change_pendant',result['reason'])

    def test_concurrent_tree_entry_added_is_inconclusive(self):
        actual=os.read; changed=False
        def racing(fd,count):
            nonlocal changed
            chunk=actual(fd,count)
            if not changed:changed=True;(self.root/'arrived').write_bytes(b'new')
            return chunk
        with patch.object(lt.os,'read',side_effect=racing):result=lt.scan_tree(str(self.root),FAST)
        self.assertEqual(result['status'],'inconclusive')

    def test_limits_reject_invalid_config_and_discard_partial_inventory(self):
        for cfg in ({'max_bytes':True},{'max_entries':0},{'unexpected':1},{'chunk_bytes':129,'block_bytes':256}):
            with self.assertRaises(ValueError):lt.limits(cfg)
        for cfg,reason in (({'max_bytes':256},'budget_octets'),({'max_file_bytes':512},'budget_fichier'),
                           ({'max_blocks':1},'budget_blocs')):
            result=lt.scan_tree(str(self.root),{**FAST,**cfg})
            self.assertEqual(result['status'],'inconclusive');self.assertIn(reason,result['reason'])
            self.assertEqual(result['entries'],{})
        (self.root/'extra').write_bytes(b'')
        result=lt.scan_tree(str(self.root),{**FAST,'max_entries':1})
        self.assertIn('budget_entrees',result['reason'])

    def test_changes_truncated_counts_still_include_all_and_no_future_reference(self):
        _,baseline=self.enroll()
        for i in range(5):(self.root/f'added-{i}').write_bytes(b'x')
        current=lt.scan_tree(str(self.root),FAST)
        result=lt.compare(baseline,current,max_changes=2)
        self.assertEqual(result['counts']['added'],5);self.assertEqual(len(result['changes']),2)
        self.assertTrue(result['changes_truncated'])
        baseline['block_bytes']+=1
        self.assertEqual(lt.compare(baseline,current)['status'],'inconclusive')

    def test_config_uses_pinned_external_reference_and_writes_summary(self):
        receipt,_=self.enroll();output=self.base/'status.json';config=self.base/'config.json'
        cfg=dict(root=str(self.root),baseline=str(self.reference),baseline_sha256=receipt['baseline_sha256'],
                 output=str(output),limits=FAST)
        config.write_text(json.dumps(cfg));config.chmod(0o600)
        self.assertEqual(lt.run_config(str(config))['status'],'unchanged')
        self.assertEqual(json.loads(output.read_text())['attribution'],'unknown')
        cfg['baseline_sha256']='0'*64;config.write_text(json.dumps(cfg))
        with self.assertRaisesRegex(ValueError,'empreinte_reference'):
            lt.run_config(str(config))

    def test_fifo_is_not_opened_and_stale_scan_is_not_a_change_verdict(self):
        os.mkfifo(self.root/'fifo')
        result=lt.scan_tree(str(self.root),FAST)
        self.assertEqual(result['status'],'inconclusive');self.assertIn('objet_non_regulier',result['reason'])


if __name__=='__main__':unittest.main()
