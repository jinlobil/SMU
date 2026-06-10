# -*- coding: utf-8 -*-
"""Application paths and filesystem bootstrap.

This module owns path discovery and directory creation.  It intentionally keeps
only side-effect-safe constants so the legacy UI can import the same names while
we continue modularizing storage, API clients, workers, and UI tabs.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime


def get_base_dir() -> str:
    """Return the executable directory when frozen, otherwise the repo/app dir."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


BASE_DIR = get_base_dir()
CACHE_DIR = os.path.join(BASE_DIR, "cache")
DETECTIONS_DAY_DIR = os.path.join(CACHE_DIR, "detections")
EMAILS_DAY_DIR = os.path.join(CACHE_DIR, "emails")
LIVE_DISCOVER_DIR = os.path.join(CACHE_DIR, "live_discover")
LOG_DIR = os.path.join(BASE_DIR, "logs")
EXPORT_DIR = os.path.join(BASE_DIR, "exports")
REPORT_DIR = os.path.join(BASE_DIR, "reports")
ENV_DIR = os.path.join(BASE_DIR, "env")
ENV_PATH = os.path.join(ENV_DIR, "Sophos_env.txt")
FIREWALL_ENV_PATH = os.path.join(ENV_DIR, "Firewall_env.txt")
DLP_ENV_PATH = os.path.join(ENV_DIR, "DLP_env.txt")
USER_GROUP_ENV_PATH = os.path.join(ENV_DIR, "User_group_env.txt")
REPORT_EXCEPTION_LIST_PATH = os.path.join(ENV_DIR, "Report_exception_List.txt")
COLOR_ENV_PATH = os.path.join(ENV_DIR, "Color_env.txt")
COLOR_THEME_DIR = os.path.join(ENV_DIR, "themes")
DLP_DAY_DIR = os.path.join(CACHE_DIR, "dlp")
TIMELINE_INDEX_DIR = os.path.join(CACHE_DIR, "index")
APP_CACHE_DB_PATH = os.path.join(TIMELINE_INDEX_DIR, "app_cache.db")
TIMELINE_INDEX_DB_PATH = os.path.join(TIMELINE_INDEX_DIR, "timeline_index.db")
TIMELINE_RENDER_BATCH_SIZE = 250
TIMELINE_DETAIL_ROW_LIMIT = 1000

# Daily log paths stay date-based exactly as before.
LOG_PATH = os.path.join(LOG_DIR, f"ui_engine_{datetime.now().strftime('%Y%m%d')}.log")
AUTO_LOG_PATH = os.path.join(LOG_DIR, f"auto_refresh_{datetime.now().strftime('%Y%m%d')}.log")


def ensure_app_directories() -> None:
    """Create all runtime folders used by cache, logs, exports, reports, and env."""
    for path in (
        CACHE_DIR,
        LOG_DIR,
        DETECTIONS_DAY_DIR,
        EMAILS_DAY_DIR,
        LIVE_DISCOVER_DIR,
        EXPORT_DIR,
        REPORT_DIR,
        DLP_DAY_DIR,
        TIMELINE_INDEX_DIR,
        ENV_DIR,
        COLOR_THEME_DIR,
    ):
        os.makedirs(path, exist_ok=True)


ensure_app_directories()
