"""Read-only inventory validation uses synthetic bytes, never archived execution."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from verify_v101_compatibility import source_inventory

class CompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'sample.py').write_bytes(b'original')
        self.digest = hashlib.sha256(b'original').hexdigest()
        self.source = "raise RuntimeError('must never execute')\nFILES = " + repr({'sample.py': self.digest})

    def test_unchanged_source(self):
        got = source_inventory(self.source, lambda name: b'original', self.root)[0]
        self.assertEqual(got['historical_integrity'], 'PASS')
        self.assertEqual(got['legacy_source_pin'], 'PASS')

    def test_current_change_is_not_historical_corruption(self):
        (self.root / 'sample.py').write_bytes(b'maintained')
        got = source_inventory(self.source, lambda name: b'original', self.root)[0]
        self.assertEqual(got['historical_integrity'], 'PASS')
        self.assertEqual(got['legacy_source_pin'], 'FAIL')
        self.assertEqual(got['relationship'], 'changed_since_v1')

    def test_archived_corruption_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            source_inventory(self.source, lambda name: b'corrupt', self.root)

    def test_missing_current_source_rejected(self):
        (self.root / 'sample.py').unlink()
        with self.assertRaises(OSError):
            source_inventory(self.source, lambda name: b'original', self.root)

    def test_unsafe_inventory_rejected(self):
        source = 'FILES = ' + repr({'../outside': self.digest})
        with self.assertRaisesRegex(ValueError, 'Unsafe'):
            source_inventory(source, lambda name: b'original', self.root)

    def test_dynamic_inventory_is_not_executed(self):
        with self.assertRaises(ValueError):
            source_inventory('FILES = dangerous_function()', lambda name: b'', self.root)
