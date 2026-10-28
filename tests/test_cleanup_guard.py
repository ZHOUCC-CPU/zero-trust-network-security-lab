"""Only the extracted guard runs, with fake commands; no topology script runs."""
from pathlib import Path
import subprocess
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'scripts/topology_down.sh'

class CleanupGuardTests(unittest.TestCase):
    def guard(self, status, pids):
        source = SOURCE.read_text()
        guard = source[source.index('verify_namespace() {'):source.index('\nverify_iface() {')]
        harness = '''
set -Eeuo pipefail
die() { exit 19; }
ns_exists() { return 0; }
stat() { printf '42:9001'; }
ip() { printf '%s' "$FAKE_PIDS"; return "$FAKE_STATUS"; }
PHASE=ACTIVE
NS_employee_ns_INODE=42:9001
'''
        return subprocess.run(['bash', '-c', harness + guard + '\nverify_namespace employee-ns'],
                              env={'PATH': '/usr/bin:/bin', 'FAKE_PIDS': pids,
                                   'FAKE_STATUS': str(status)},
                              capture_output=True, text=True).returncode

    def test_empty_process_list(self):
        self.assertEqual(self.guard(0, ''), 0)

    def test_running_process_refused(self):
        self.assertNotEqual(self.guard(0, '123'), 0)

    def test_process_query_error_refused(self):
        self.assertNotEqual(self.guard(7, ''), 0)

    def namespace_query(self, status, inventory, name='employee-ns'):
        source = SOURCE.read_text()
        helper = source[source.index('ns_exists() {'):source.index('\nread_state() {')]
        # Execute the actual lookup helper with an ip function, never real ip.
        harness = '''
set -Eeuo pipefail
die() { exit 19; }
ip() { printf '%s' "$FAKE_INVENTORY"; return "$FAKE_STATUS"; }
'''
        return subprocess.run(['bash', '-c', harness + helper + '\nif ns_exists "$NAME"; then exit 0; else exit 3; fi'],
                              env={'PATH': '/usr/bin:/bin', 'FAKE_STATUS': str(status),
                                   'FAKE_INVENTORY': inventory, 'NAME': name},
                              capture_output=True, text=True).returncode

    def test_namespace_list_failure_is_fatal(self):
        self.assertEqual(self.namespace_query(7, ''), 19)

    def test_namespace_absence_distinguished(self):
        self.assertEqual(self.namespace_query(0, ''), 3)

    def test_namespace_exact_match(self):
        self.assertEqual(self.namespace_query(0, 'employee-ns (id: 1)\n'), 0)
        self.assertEqual(self.namespace_query(0, 'not-employee-ns\n'), 3)
