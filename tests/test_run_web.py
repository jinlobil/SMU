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

    def test_local_package_bootstrap_does_not_depend_on_import_path(self):
        original_module = sys.modules.pop("core", None)
        original_path = list(sys.path)
        try:
            sys.path[:] = [entry for entry in sys.path if Path(entry or ".").resolve() != run_web.ROOT]
            package_dir = run_web.ensure_local_package("core")
            from core import paths

            self.assertEqual(package_dir, run_web.ROOT / "core")
            self.assertEqual(Path(paths.__file__).resolve(), run_web.ROOT / "core" / "paths.py")
        finally:
            sys.modules.pop("core", None)
            if original_module is not None:
                sys.modules["core"] = original_module
            sys.path[:] = original_path

    def test_missing_local_package_has_actionable_error(self):
        with patch.object(run_web, "ROOT", Path("Z:/definitely-missing-smu")):
            with self.assertRaisesRegex(RuntimeError, "Required SMU package is missing"):
                run_web.ensure_local_package("core")

    def test_missing_frontend_returns_error_and_writes_log(self):
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "web_server.log"
            with (
                patch.object(run_web, "FRONTEND_INDEX", Path(directory) / "missing.html"),
                patch.object(run_web, "LOG_DIR", Path(directory)),
                patch.object(run_web, "LOG_PATH", log_path),
            ):
                self.assertEqual(run_web.main(), 2)
            logging.shutdown()
            contents = log_path.read_text(encoding="utf-8")
            self.assertIn("Frontend build is missing", contents)
            self.assertIn("INSTALL_WEB.bat", contents)
