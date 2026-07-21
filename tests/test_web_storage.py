import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from web_backend import storage


class StandaloneWebStorageTests(unittest.TestCase):
    def test_daily_email_json_load_does_not_import_desktop_core(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "2026-07-21.json").write_text(json.dumps([{"subject": "hello"}]), encoding="utf-8")
            with patch.object(storage, "EMAILS_DAY_DIR", root), patch.object(storage, "APP_CACHE_DB_PATH", root / "missing.db"):
                self.assertEqual(storage.load_emails_by_range("2026-07-21", "2026-07-21"), [{"subject": "hello"}])

    def test_dlp_jsonl_and_detection_classification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "2026-07-21.jsonl").write_text('{"event":"copy"}\n', encoding="utf-8")
            with patch.object(storage, "DLP_DAY_DIR", root), patch.object(storage, "APP_CACHE_DB_PATH", root / "missing.db"):
                self.assertEqual(storage.load_dlp_by_range("2026-07-21", "2026-07-21"), [{"event": "copy"}])
            self.assertEqual(storage._sensor({"sensor": {"type": "endpoint"}}), "endpoint")

    def test_module_has_no_desktop_package_dependency(self):
        source = Path(storage.__file__).read_text(encoding="utf-8")
        self.assertNotIn("from core", source)
        self.assertNotIn("from modules", source)
