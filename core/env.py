# -*- coding: utf-8 -*-
"""Environment-file loaders used by Sophos, DLP, and Firewall clients."""

from __future__ import annotations

import os


def load_env_from_file(path: str) -> None:
    """Load KEY=VALUE pairs into os.environ, matching legacy parsing behavior."""
    if not os.path.exists(path):
        raise RuntimeError(f"Env file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                os.environ[k.strip()] = v.strip()


def load_dlp_env(path: str) -> dict:
    """Return KEY=VALUE pairs for DLP_env.txt without mutating os.environ."""
    if not os.path.exists(path):
        raise RuntimeError(f"Env file not found: {path}")
    values = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                values[k.strip()] = v.strip()
    return values
