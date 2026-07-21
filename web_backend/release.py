"""Release identity and on-disk integrity checks for the local web bundle."""

from __future__ import annotations

from pathlib import Path

RELEASE = "2026.07.21.2"
REQUIRED_FILES = (
    "INSTALL_WEB.bat",
    "START_WEB.bat",
    "SHOW_WEB_LOG.bat",
    "run_web.py",
    "requirements-web.txt",
    "web_backend/__init__.py",
    "web_backend/app.py",
    "web_backend/release.py",
    "web_backend/runtime_paths.py",
    "web_backend/storage.py",
    "web_backend/theme_store.py",
    "web_frontend/index.html",
    "web_frontend/package.json",
    "web_frontend/src/main.tsx",
    "web_frontend/src/styles.css",
)


def audit_bundle(root: Path, require_build: bool = True) -> list[str]:
    missing = [relative for relative in REQUIRED_FILES if not (root / relative).is_file()]
    if require_build and not (root / "web_frontend" / "dist" / "index.html").is_file():
        missing.append("web_frontend/dist/index.html")
    return missing
