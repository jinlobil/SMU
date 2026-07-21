import tempfile
import unittest
from pathlib import Path

from web_backend.theme_store import ensure_color_env_file, load_color_env, save_color_env


class ThemeStoreTests(unittest.TestCase):
    def test_creates_and_round_trips_color_file_without_qt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "Color_env.txt")
            created = ensure_color_env_file(path)
            self.assertEqual(created["Primary_Blue"], "#0863E2")
            created["Primary_Blue"] = "#123abc"
            save_color_env(created, path)
            self.assertEqual(load_color_env(path)["Primary_Blue"], "#123ABC")

    def test_invalid_color_uses_existing_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Color_env.txt"
            path.write_text("Primary_Blue=not-a-color\n", encoding="utf-8")
            self.assertEqual(load_color_env(str(path))["Primary_Blue"], "#0863E2")
