# -*- coding: utf-8 -*-
"""DLP display formatting helpers used by File tab, Timeline, exports, and reports."""

from __future__ import annotations


def format_dlp_event_id(value):
    event_id = str(value or "None")
    mapping = {
        "Content Threat Detected": "탐지됨",
        "Content Threat Blocked": "차단",
    }
    return mapping.get(event_id.strip(), event_id)


def bytes_to_mb_text(value):
    try:
        size_bytes = float(value)
        size_mb = size_bytes / (1024 * 1024)
        return f"{size_mb:.2f} MB"
    except Exception:
        return str(value)
