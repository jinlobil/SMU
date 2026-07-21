import logging
import os
import shutil
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
            with self.assertRaisesRegex(RuntimeError, "Required SMU directory is missing"):
                run_web.ensure_local_package("core")

    def test_empty_init_file_can_be_omitted_from_zip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "core"
            package.mkdir()
            (package / "example.py").write_text("VALUE = 42\n", encoding="utf-8")
            original = sys.modules.pop("core", None)
            try:
                with patch.object(run_web, "ROOT", root):
                    run_web.ensure_local_package("core")
                    from core.example import VALUE

                    self.assertEqual(VALUE, 42)
                    self.assertEqual(list(sys.modules["core"].__path__), [str(package)])
            finally:
                for name in [key for key in sys.modules if key == "core" or key.startswith("core.")]:
                    sys.modules.pop(name, None)
                if original is not None:
                    sys.modules["core"] = original

    def test_reused_storage_tree_imports_without_any_package_markers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(run_web.ROOT / "core", root / "core", ignore=shutil.ignore_patterns("__init__.py", "__pycache__"))
            shutil.copytree(run_web.ROOT / "modules", root / "modules", ignore=shutil.ignore_patterns("__init__.py", "__pycache__"))
            saved = {name: module for name, module in sys.modules.items() if name == "core" or name == "modules" or name.startswith(("core.", "modules."))}
            try:
                for name in saved:
                    sys.modules.pop(name, None)
                with patch.object(run_web, "ROOT", root):
                    run_web.ensure_local_package("core")
                    run_web.ensure_local_package("modules")
                    from core.storage import sqlite_cache

                    self.assertEqual(sqlite_cache.APP_CACHE_SOURCES["detections"]["ext"], ".json")
            finally:
                for name in [key for key in sys.modules if key == "core" or key == "modules" or key.startswith(("core.", "modules."))]:
                    sys.modules.pop(name, None)
                sys.modules.update(saved)

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
