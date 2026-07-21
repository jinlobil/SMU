import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class WindowsLauncherTests(unittest.TestCase):
    def assert_ascii_batch(self, name):
        content = (ROOT / name).read_bytes()
        self.assertTrue(content.isascii(), f"{name} must stay ASCII for Windows cmd.exe")

    def test_install_launcher_can_bootstrap_node_and_build_frontend(self):
        script = (ROOT / "INSTALL_WEB.bat").read_text(encoding="utf-8")
        self.assertIn("OpenJS.NodeJS.LTS", script)
        self.assertIn("npm --prefix web_frontend install", script)
        self.assertIn("npm --prefix web_frontend run build", script)
        self.assertIn(".venv\\Scripts\\python.exe", script)
        self.assertIn("run_web.py --check", script)
        self.assertIn("restore_smu_sources.py", script)
        self.assert_ascii_batch("INSTALL_WEB.bat")

    def test_start_launcher_falls_back_to_installer(self):
        script = (ROOT / "START_WEB.bat").read_text(encoding="utf-8")
        self.assertIn("web_frontend\\dist\\index.html", script)
        self.assertIn("INSTALL_WEB.bat", script)
        self.assertIn("run_web.py", script)
        self.assertIn("restore_smu_sources.py", script)
        self.assertIn("logs\\web_server.log", script)
        self.assertIn("notepad", script)
        self.assert_ascii_batch("START_WEB.bat")

    def test_log_viewer_is_ascii_and_opens_persistent_log(self):
        script = (ROOT / "SHOW_WEB_LOG.bat").read_text(encoding="utf-8")
        self.assertIn("logs\\web_server.log", script)
        self.assertIn("notepad", script)
        self.assert_ascii_batch("SHOW_WEB_LOG.bat")

    def test_frontend_has_no_fragile_motion_runtime_dependency(self):
        package = (ROOT / "web_frontend" / "package.json").read_text(encoding="utf-8")
        source = (ROOT / "web_frontend" / "src" / "main.tsx").read_text(encoding="utf-8")
        self.assertNotIn("framer-motion", package)
        self.assertNotIn("framer-motion", source)
        self.assertNotIn("motion.", source)
