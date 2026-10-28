"""Synthetic malformed configuration/report checks; no probes or real reports."""
import contextlib
import csv
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]

def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class ReleaseValidationTests(unittest.TestCase):
    def invalid_plan(self, name):
        module = load(name)
        plan = json.loads((ROOT / 'tests/v07_benchmark_plan.json').read_text())
        plan['conditions'] = ['SYNTHETIC_INVALID_CONDITION']
        with mock.patch.object(module.Path, 'read_text', return_value=json.dumps(plan)):
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError, 'plan'):
                    module.check_plan()

    def test_invalid_latency_plan_rejected(self):
        self.invalid_plan('v07_tcp_latency')

    def test_invalid_throughput_plan_rejected(self):
        self.invalid_plan('v07_iperf3_throughput')

    def invalid_report(self, count):
        module = load('v06_compare')
        matrix = json.loads((ROOT / 'tests/v06_scenario_matrix.json').read_text())['scenarios']
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'summary.json').write_text('{"all_passed":true}')
            with (path / 'scenarios.csv').open('w', newline='') as handle:
                writer = csv.DictWriter(handle, fieldnames=['scenario', 'condition', 'verdict'])
                writer.writeheader()
                for _ in range(count):
                    writer.writerow({'scenario': 'SYNTHETIC_UNKNOWN', 'condition': 'baseline', 'verdict': 'PASS'})
            with mock.patch.object(module, 'REPORT', path / 'must-not-exist.md'):
                with self.assertRaisesRegex(ValueError, 'scenario'):
                    module.make_report(path, matrix)
                self.assertFalse((path / 'must-not-exist.md').exists())

    def test_incomplete_report_rejected(self):
        self.invalid_report(0)

    def test_wrong_scenario_groups_rejected(self):
        self.invalid_report(36)
