"""Self-contained runtime paths for the local web application."""

from __future__ import annotations

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
CACHE_DIR = BASE_DIR / "cache"
DETECTIONS_DAY_DIR = CACHE_DIR / "detections"
EMAILS_DAY_DIR = CACHE_DIR / "emails"
DLP_DAY_DIR = CACHE_DIR / "dlp"
INDEX_DIR = CACHE_DIR / "index"
APP_CACHE_DB_PATH = INDEX_DIR / "app_cache.db"
ENV_DIR = BASE_DIR / "env"
COLOR_ENV_PATH = ENV_DIR / "Color_env.txt"

for directory in (CACHE_DIR, DETECTIONS_DAY_DIR, EMAILS_DAY_DIR, DLP_DAY_DIR, INDEX_DIR, ENV_DIR):
    directory.mkdir(parents=True, exist_ok=True)
