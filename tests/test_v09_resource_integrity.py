#!/usr/bin/env python3
"""Offline fail-closed regression tests for V0.9 residue detection."""
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'scripts' / 'v09_resource_integrity.py'
EXPECTED_SHA = 'af716c4c2b5049d9e2a6d59e5f0000779056af8c44f4259a7fb84246b4ac31b8'


def load_checker():
    if SOURCE.is_symlink() or not SOURCE.is_file():
        raise RuntimeError('Unexpected checker source path')
    if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != EXPECTED_SHA:
        raise RuntimeError('Checker source SHA256 mismatch')
    spec = importlib.util.spec_from_file_location('v09_resource_integrity', SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ResourceIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checker = load_checker()

    def test_clean_environment(self):
        got = self.checker.findings('', [{'ifname': 'lo'}, {'ifname': 'eth0'}], False)
        self.assertEqual(got, ([], [], False))

    def test_each_project_namespace_detected(self):
        for name in sorted(self.checker.NAMESPACES):
            with self.subTest(namespace=name):
                found = self.checker.findings(name + ' (id: 1)\n', [], False)
                self.assertEqual(found, ([name], [], False))

    def test_each_project_interface_detected(self):
        for name in sorted(self.checker.HOST_IFACES):
            with self.subTest(interface=name):
                found = self.checker.findings('', [{'ifname': name}], False)
                self.assertEqual(found, ([], [name], False))

    def test_additional_project_prefix_detected(self):
        self.assertEqual(self.checker.findings('', [{'ifname': 'ztlab-unexpected'}], False),
                         ([], ['ztlab-unexpected'], False))

    def test_state_marker_detected(self):
        self.assertEqual(self.checker.findings('', [], True), ([], [], True))

    def test_unrelated_resources_not_misclassified(self):
        found = self.checker.findings('unrelated-ns (id: 2)\n',
                                      [{'ifname': 'lo'}, {'ifname': 'eth0'},
                                       {'ifname': 'veth-other'}], False)
        self.assertEqual(found, ([], [], False))

    def test_invalid_link_input_rejected(self):
        for invalid in (None, {}, [{'name': 'missing-ifname'}],
                        [{'ifname': 123}], [None]):
            with self.subTest(invalid=repr(invalid)):
                with self.assertRaises(ValueError):
                    self.checker.findings('', invalid, False)

    def test_broken_state_symlink_is_detected(self):
        replies = [mock.Mock(returncode=0), mock.Mock(returncode=1),
                   mock.Mock(returncode=0)]
        with mock.patch.object(self.checker, 'checked', side_effect=replies) as checked:
            self.assertTrue(self.checker.privileged_state_exists())
            self.assertEqual(checked.call_count, 3)

    def test_privileged_check_failure_is_not_treated_as_clean(self):
        with mock.patch.object(self.checker, 'checked', side_effect=RuntimeError('sudo denied')):
            with self.assertRaises(RuntimeError):
                self.checker.privileged_state_exists()

    def test_missing_lock_fails_closed_without_commands(self):
        with mock.patch.object(self.checker.os, 'open', side_effect=FileNotFoundError('missing lock')):
            with mock.patch.object(self.checker, 'checked', side_effect=AssertionError('must not run commands')):
                with self.assertRaises(FileNotFoundError):
                    self.checker.live_check()


if __name__ == '__main__':
    unittest.main(verbosity=2)
