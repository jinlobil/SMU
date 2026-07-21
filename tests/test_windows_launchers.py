import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class WindowsLauncherTests(unittest.TestCase):
    def test_install_launcher_can_bootstrap_node_and_build_frontend(self):
        script = (ROOT / "INSTALL_WEB.bat").read_text(encoding="utf-8")
        self.assertIn("OpenJS.NodeJS.LTS", script)
        self.assertIn("npm --prefix web_frontend install", script)
        self.assertIn("npm --prefix web_frontend run build", script)
        self.assertIn(".venv\\Scripts\\python.exe", script)

    def test_start_launcher_falls_back_to_installer(self):
        script = (ROOT / "START_WEB.bat").read_text(encoding="utf-8")
        self.assertIn("web_frontend\\dist\\index.html", script)
        self.assertIn("INSTALL_WEB.bat", script)
        self.assertIn("run_web.py", script)
