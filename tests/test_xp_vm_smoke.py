import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('xp_vm_smoke', Path(__file__).resolve().parents[1] / 'tools/xp_vm_smoke.py')
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)


class PreparationBoundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=vm.ROOT / 'work')
        self.root = Path(self.temp.name)
        self.patch = patch.object(vm, 'ROOT', self.root)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.temp.cleanup()

    def test_existing_run_preserved(self):
        folder = vm.reserve_run('run-1')
        marker = folder / 'important'
        marker.write_text('keep')
        with self.assertRaises(FileExistsError):
            vm.reserve_run('run-1')
        self.assertEqual(marker.read_text(), 'keep')

    def test_reject_path_and_option_injection(self):
        for value in ('../escape', '/tmp/escape', '-option', 'a,b', 'a\nb', 'a' * 49):
            with self.subTest(value=value), self.assertRaises(ValueError):
                vm.reserve_run(value)

    def test_symlink_cannot_escape_project(self):
        (self.root / 'work').symlink_to(self.root.parent, target_is_directory=True)
        with self.assertRaises(ValueError):
            vm.reserve_run('escape')

    def test_network_controller_recognized_behind_bridge(self):
        nic = {'class_info': {'class': 0x0200}}
        buses = [{'devices': [{'pci_bridge': {'bus': {'devices': [nic]}}}]}]
        self.assertEqual(vm.pci_network_devices(buses), [nic])

    def test_storage_is_not_network(self):
        self.assertEqual(vm.pci_network_devices([{'devices': [{'class_info': {'class': 0x0101}}]}]), [])

    def test_qmp_events_do_not_replace_response(self):
        qmp = vm.QMP.__new__(vm.QMP)
        qmp.counter = 0
        qmp.process = type('Process', (), {'stdin': io.BytesIO()})()
        replies = [{'event': 'STOP'}, {'id': 1, 'return': {'status': 'paused'}}]
        with patch.object(qmp, 'receive', side_effect=replies):
            self.assertEqual(qmp.call('query-status'), {'status': 'paused'})
        self.assertEqual(json.loads(qmp.process.stdin.getvalue())['execute'], 'query-status')

    def test_qmp_error_is_failure(self):
        qmp = vm.QMP.__new__(vm.QMP)
        qmp.counter = 0
        qmp.process = type('Process', (), {'stdin': io.BytesIO()})()
        with patch.object(qmp, 'receive', return_value={'id': 1, 'error': {'desc': 'denied'}}):
            with self.assertRaises(RuntimeError):
                qmp.call('stop')


if __name__ == '__main__':
    unittest.main()
