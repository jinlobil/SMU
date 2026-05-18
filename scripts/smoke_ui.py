"""Headless startup smoke test for the PyQt UI.

Run with:
    QT_QPA_PLATFORM=offscreen python scripts/smoke_ui.py
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PyQt5.QtWidgets import QApplication
except ModuleNotFoundError as exc:
    raise SystemExit("PyQt5 is required to run this smoke test") from exc

from uimain_window import MainWindow


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    print(f"MainWindow created with {window.tabs.count()} tabs")
    window.close()
    app.quit()


if __name__ == "__main__":
    main()
