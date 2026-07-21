import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import run_web


class RunWebTests(unittest.TestCase):
    def test_launcher_anchors_imports_and_working_directory_to_repo(self):
        self.assertEqual(Path.cwd(), run_web.ROOT)
        self.assertEqual(Path(sys.path[0]), run_web.ROOT)

    def test_missing_frontend_returns_error_and_writes_log(self):
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "web_server.log"
            with (
                patch.object(run_web, "LOG_DIR", Path(directory)),
                patch.object(run_web, "LOG_PATH", log_path),
                patch("web_backend.release.audit_bundle", return_value=["web_frontend/dist/index.html"]),
            ):
                self.assertEqual(run_web.main(), 2)
            logging.shutdown()
            contents = log_path.read_text(encoding="utf-8")
            self.assertIn("Required release file is missing", contents)
            self.assertIn("INSTALL_WEB.bat", contents)
