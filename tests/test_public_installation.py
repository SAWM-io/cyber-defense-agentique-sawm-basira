"""Publication bootstrap must never mutate a host without explicit checks."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('prepare_lab',ROOT/'scripts/prepare_linux_lab.py')
prepare_lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare_lab)


class PublicInstallationTest(unittest.TestCase):
    def test_plan_has_no_implicit_execution(self):
        p=prepare_lab.plan()
        self.assertEqual(p['services_started'],[])
        self.assertFalse(p['cloud_calls'])
        self.assertFalse(p['firewall_changes'])
        self.assertFalse(p['kernel_changes'])

    def test_initial_manifest_does_not_delegate_actions(self):
        m=json.loads((ROOT/'config/manifeste.observation.json').read_text())
        self.assertEqual(m['unites_autorisees'],[])
        self.assertEqual(m['tranches_autorisees'],[])
        self.assertEqual(m['veille']['actions_automatiques'],[])
        self.assertIn('ssh.service',m['unites_protegees'])

    def test_nonlinux_apply_refused_before_filesystem_write(self):
        with patch.object(prepare_lab.sys,'platform','darwin'), patch.object(Path,'mkdir') as mkdir:
            with self.assertRaisesRegex(RuntimeError,'dedicated Linux VM'):
                prepare_lab.prepare()
            mkdir.assert_not_called()

    def test_nonroot_apply_refused_before_filesystem_write(self):
        with patch.object(prepare_lab.sys,'platform','linux'), patch.object(prepare_lab.os,'geteuid',return_value=1000), patch.object(Path,'mkdir') as mkdir:
            with self.assertRaisesRegex(RuntimeError,'dedicated Linux VM'):
                prepare_lab.prepare()
            mkdir.assert_not_called()

    def test_missing_explicit_ack_refused(self):
        with patch.object(prepare_lab.sys,'argv',['prepare_linux_lab.py','--apply']), patch.object(prepare_lab,'prepare') as mutate:
            with self.assertRaises(SystemExit):prepare_lab.main()
            mutate.assert_not_called()

    def test_symlinked_parent_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();(root/'real').mkdir();(root/'alias').symlink_to(root/'real')
            with self.assertRaisesRegex(RuntimeError,'Symlinked'):
                prepare_lab.trusted_parent(root/'alias')


if __name__=='__main__':unittest.main()
