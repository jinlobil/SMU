import unittest
from pathlib import Path

from web_backend.release import RELEASE, audit_bundle


ROOT = Path(__file__).resolve().parents[1]


class ReleaseBundleTests(unittest.TestCase):
    def test_source_bundle_contains_every_required_file(self):
        self.assertRegex(RELEASE, r"^\d{4}\.\d{2}\.\d{2}\.\d+$")
        self.assertEqual(audit_bundle(ROOT, require_build=False), [])
