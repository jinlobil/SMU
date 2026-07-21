"""Restore required shared Python sources from the web release bundle.

Some source ZIP delivery paths have omitted the repository's ``core`` and
``modules`` directories.  The web release carries a verified copy and restores
only missing files before installation; existing user files are never replaced.
"""

from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUNDLE = ROOT / "web_source_bundle"
REQUIRED = (
    "core/__init__.py",
    "core/detection.py",
    "core/env.py",
    "core/json_utils.py",
    "core/paths.py",
    "core/storage/__init__.py",
    "core/storage/sqlite_cache.py",
    "core/theme.py",
    "core/time_utils.py",
    "modules/__init__.py",
    "modules/dlp/__init__.py",
    "modules/dlp/formatters.py",
)


def restore(root: Path = ROOT, bundle: Path = BUNDLE) -> list[str]:
    restored: list[str] = []
    for relative in REQUIRED:
        source = bundle / relative
        destination = root / relative
        if not source.is_file():
            raise RuntimeError(f"SMU source bundle is incomplete: {source}")
        if destination.exists():
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        restored.append(relative)
    return restored


def audit(root: Path = ROOT) -> list[str]:
    return [relative for relative in REQUIRED if not (root / relative).is_file()]


if __name__ == "__main__":
    copied = restore()
    missing = audit()
    for relative in copied:
        print(f"Restored: {relative}")
    if missing:
        raise SystemExit(f"Required SMU sources are still missing: {missing}")
    print(f"SMU shared source audit passed: {len(REQUIRED)} files")
