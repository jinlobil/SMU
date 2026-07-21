import unittest
from pathlib import Path

from web_backend.release import RELEASE, audit_bundle


ROOT = Path(__file__).resolve().parents[1]


class ReleaseBundleTests(unittest.TestCase):
    def test_source_bundle_contains_every_required_file(self):
        self.assertRegex(RELEASE, r"^\d{4}\.\d{2}\.\d{2}\.\d+$")
        self.assertEqual(audit_bundle(ROOT, require_build=False), [])

    def test_web_runtime_does_not_import_desktop_packages(self):
        for path in [ROOT / "run_web.py", *(ROOT / "web_backend").glob("*.py")]:
            source = path.read_text(encoding="utf-8")
            self.assertNotIn("from core", source, path)
            self.assertNotIn("import core", source, path)
            self.assertNotIn("from modules", source, path)
            self.assertNotIn("import modules", source, path)
