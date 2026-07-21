import tempfile
import unittest
from pathlib import Path

from restore_smu_sources import BUNDLE, REQUIRED, audit, restore


class RestoreSourcesTests(unittest.TestCase):
    def test_bundle_contains_every_shared_source(self):
        missing = [relative for relative in REQUIRED if not (BUNDLE / relative).is_file()]
        self.assertEqual(missing, [])
        repository = Path(__file__).resolve().parents[1]
        mismatched = [
            relative for relative in REQUIRED
            if (repository / relative).read_bytes() != (BUNDLE / relative).read_bytes()
        ]
        self.assertEqual(mismatched, [])

    def test_restore_recreates_missing_core_and_modules_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            restored = restore(root=root)
            self.assertEqual(set(restored), set(REQUIRED))
            self.assertEqual(audit(root), [])
            self.assertIn("APP_CACHE_DB_PATH", (root / "core/storage/sqlite_cache.py").read_text(encoding="utf-8"))

    def test_restore_never_overwrites_existing_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "core/paths.py"
            target.parent.mkdir(parents=True)
            target.write_text("USER_COPY = True\n", encoding="utf-8")
            restore(root=root)
            self.assertEqual(target.read_text(encoding="utf-8"), "USER_COPY = True\n")
