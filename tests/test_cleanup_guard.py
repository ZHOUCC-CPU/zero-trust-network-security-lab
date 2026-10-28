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
