"""Offline signature importer: synthetic headers and mocked crypto replies.

These tests exercise refusal/routing. They do not replace verification of the
official CVD/signature pair with the real sigtool executable in the VM.
"""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from invite.agent_labo import signature_import as m

NOW=1_800_000_000


def cvd(epoch=NOW-60,version=63):
    return ('ClamAV-VDB:sample date:'+str(version)+':100:1:md5:signed:builder:'+str(epoch)).encode().ljust(512,b' ')


class SignatureImportTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.stage=self.root/'staging';self.stage.mkdir()
        self.fd=m.open_directory(self.stage);self.addCleanup(os.close,self.fd)

    def test_header_version_count_and_publication_epoch(self):
        self.assertEqual(m.header(cvd()),{'version':63,'signatures':100,'published_epoch':NOW-60})

    def test_bad_header_rejected(self):
        for raw in (b'',b'not a CVD',cvd().replace(b':63:',b':x:'),cvd().replace(b':100:',b':0:')):
            with self.assertRaises(m.ImportRefused):m.header(raw)

    def test_fresh_file_mtime_cannot_hide_old_publication(self):
        path=self.stage/'daily.cvd';path.write_bytes(cvd(NOW-m.DAILY_MAX_AGE-1));os.utime(path,(NOW,NOW))
        with self.assertRaises(m.ImportRefused):m.check_publication('daily',m.header(path.read_bytes()),now=NOW)

    def test_old_main_is_allowed_but_future_daily_is_not(self):
        m.check_publication('main',m.header(cvd(NOW-365*86400)),now=NOW)
        m.check_publication('daily',m.header(cvd(NOW-m.DAILY_MAX_AGE)),now=NOW)
        with self.assertRaises(m.ImportRefused):m.check_publication('daily',m.header(cvd(NOW+1)),now=NOW)

    def test_stable_copy_hash_and_readonly_output(self):
        raw=cvd();(self.stage/'main.cvd').write_bytes(raw);out=self.root/'copy.cvd'
        result=m.stable_copy(self.fd,'main.cvd',out,limit=1024)
        self.assertEqual(result,{'sha256':hashlib.sha256(raw).hexdigest(),'bytes':512})
        self.assertEqual(out.stat().st_mode & 0o777,0o444)

    def test_symlink_hardlink_fifo_and_oversized_file_refused(self):
        target=self.root/'original';target.write_bytes(cvd());path=self.stage/'main.cvd'
        path.symlink_to(target)
        with self.assertRaises(OSError):m.stable_copy(self.fd,'main.cvd',self.root/'out',limit=1024)
        path.unlink();os.link(target,path)
        with self.assertRaises(m.ImportRefused):m.stable_copy(self.fd,'main.cvd',self.root/'out',limit=1024)
        path.unlink();os.mkfifo(path)
        with self.assertRaises(m.ImportRefused):m.stable_copy(self.fd,'main.cvd',self.root/'out',limit=1024)
        path.unlink();path.write_bytes(cvd())
        with self.assertRaises(m.ImportRefused):m.stable_copy(self.fd,'main.cvd',self.root/'out',limit=100)

    def test_staging_directory_cannot_follow_symlink_parent(self):
        link=self.root/'link';link.symlink_to(self.stage,target_is_directory=True)
        with self.assertRaises(OSError):m.open_directory(link)

    def test_arbitrary_signature_filenames_refused(self):
        for name in ('../main.cvd','main.cvd; echo bad','other.cvd','daily-2.cvd.sign/extra'):
            with self.assertRaises(m.ImportRefused):m.stable_copy(self.fd,name,self.root/'out',limit=1024)

    def test_verification_runs_unprivileged_without_network(self):
        args=m.verification_command(self.root/'daily.cvd','--verify')
        self.assertIn('DynamicUser=yes',args);self.assertIn('PrivateNetwork=yes',args)
        self.assertIn('NoNewPrivileges=yes',args);self.assertIn('CapabilityBoundingSet=',args)
        self.assertIn('--setenv=CVD_CERTS_DIR='+str(m.CERTIFICATES),args)
        self.assertEqual(args[-3:],[str(m.SIGTOOL),'--verify',str(self.root/'daily.cvd')])

    def test_external_signature_and_embedded_info_both_required(self):
        calls=[]
        def runner(args,**kwargs):
            calls.append(args)
            text=('Successfully verified signed by ClamAV_datafiles_release' if '--verify' in args
                  else 'Version: 63\nSignatures: 100\nVerification OK.')
            return subprocess.CompletedProcess(args,0,text,'')
        result=m.verify_copy(self.root/'main.cvd',m.header(cvd()),runner=runner)
        self.assertTrue(result['external_signature_verified']);self.assertEqual(len(calls),2)

    def test_failed_or_wrong_signer_does_not_reach_promotion(self):
        for code,text in [(1,'Successfully verified signed by ClamAV_datafiles_release'),
                          (0,'Successfully verified signed by somebody'),(0,'')]:
            def runner(args,**kwargs):return subprocess.CompletedProcess(args,code,text,'')
            with self.assertRaises(m.ImportRefused):m.verify_copy(self.root/'main.cvd',m.header(cvd()),runner=runner)

    def test_mismatching_info_rejected(self):
        def runner(args,**kwargs):
            text=('Successfully verified signed by ClamAV_datafiles_release' if '--verify' in args
                  else 'Version: 64\nSignatures: 100\nVerification OK.')
            return subprocess.CompletedProcess(args,0,text,'')
        with self.assertRaises(m.ImportRefused):m.verify_copy(self.root/'main.cvd',m.header(cvd()),runner=runner)

    def test_rollback_and_changed_same_version_rejected(self):
        previous={'version':63,'sha256':'a'*64}
        for now in ({'version':62,'sha256':'a'*64},{'version':63,'sha256':'b'*64}):
            with self.assertRaises(m.ImportRefused):m.no_rollback(previous,now)
        m.no_rollback(previous,previous);m.no_rollback(previous,{'version':64,'sha256':'b'*64})

    def test_initial_promotion_is_directory_rename(self):
        source=self.root/'approved';source.mkdir();(source/'main.cvd').write_bytes(cvd())
        destination=self.root/'active'
        self.assertIsNone(m.atomic_promote(source,destination))
        self.assertTrue((destination/'main.cvd').is_file());self.assertFalse(source.exists())


if __name__=='__main__':unittest.main()
