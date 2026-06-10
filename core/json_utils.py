# -*- coding: utf-8 -*-
"""JSON/JSONL file helpers shared by cache, export, report, and indexing code."""

from __future__ import annotations

import json
import logging
import os
from typing import Any

log = logging.getLogger("SophosUI")


def load_json(path: str) -> Any:
    """Load a JSON file and return [] if the file is missing or invalid."""
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def load_jsonl(path: str) -> list:
    """Load dict rows from JSON Lines, preserving the legacy warning behavior."""
    results = []
    if not os.path.exists(path):
        return results
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                    if isinstance(row, dict):
                        results.append(row)
                except Exception as e:
                    log.warning(f"Failed to parse jsonl line in {path}: {e}")
    except Exception as e:
        log.warning(f"Failed to load jsonl file {path}: {e}")
    return results


def save_json(path: str, data: Any) -> None:
    """Atomically save JSON data using the same UTF-8/ensure_ascii behavior as before."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def save_jsonl(path: str, rows: list) -> None:
    """Atomically save dict rows as JSON Lines."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for row in rows:
            if not isinstance(row, dict):
                continue
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    os.replace(tmp, path)


def safe_json_loads(value: Any, default: Any = None) -> Any:
    """Parse JSON text defensively and return default on blank/invalid input."""
    if default is None:
        default = {}
    if isinstance(value, dict):
        return value
    if not value:
        return default
    try:
        return json.loads(value)
    except Exception:
        return default
