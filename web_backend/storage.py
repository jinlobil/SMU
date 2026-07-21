"""Standalone read access to the existing SMU cache.

This module intentionally has no dependency on the desktop ``core`` package. It
reads the same SQLite/JSON/JSONL files, allowing the local web release to operate
even when a user downloads only the web migration files.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterator

from web_backend.runtime_paths import (
    APP_CACHE_DB_PATH,
    CACHE_DIR,
    DETECTIONS_DAY_DIR,
    DLP_DAY_DIR,
    EMAILS_DAY_DIR,
)

log = logging.getLogger("smu.web.storage")
XDR_EMAIL_RULES = {
    "XDR-sophos-email-maliciousurl",
    "XDR-sophos-email-virus",
    "XDR-sophos-email-impersonation",
}
SINGLE_FILES = {
    "endpoints": CACHE_DIR / "endpoints.json",
    "orgs": CACHE_DIR / "user_groups.json",
    "users": CACHE_DIR / "users.json",
}


def _dates(start: str, end: str) -> Iterator[str]:
    current = datetime.strptime(start, "%Y-%m-%d")
    last = datetime.strptime(end, "%Y-%m-%d")
    while current <= last:
        yield current.strftime("%Y-%m-%d")
        current += timedelta(days=1)


def _read_json(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []
    except Exception:
        log.exception("Unable to read JSON cache %s", path)
        return []


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                value = json.loads(line)
                if isinstance(value, dict):
                    rows.append(value)
    except Exception:
        log.exception("Unable to read JSONL cache %s", path)
    return rows


def _daily(directory: Path, extension: str, start: str, end: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for day in _dates(start, end):
        path = directory / f"{day}{extension}"
        rows.extend(_read_jsonl(path) if extension == ".jsonl" else _read_json(path))
    return rows


def _indexed(table: str, start: str, end: str, where: str = "", params: tuple[Any, ...] = ()) -> list[dict[str, Any]] | None:
    if not APP_CACHE_DB_PATH.exists():
        return None
    try:
        with sqlite3.connect(APP_CACHE_DB_PATH) as conn:
            query = f"""
                SELECT raw_json FROM {table}
                WHERE COALESCE(NULLIF(event_date_kst, ''), cache_date) BETWEEN ? AND ?
                {where}
                ORDER BY COALESCE(NULLIF(event_time, ''), cache_date), source_file, row_index
            """
            values = conn.execute(query, (start, end, *params)).fetchall()
        rows = []
        for (raw,) in values:
            value = json.loads(raw)
            if isinstance(value, dict):
                rows.append(value)
        return rows
    except (sqlite3.Error, ValueError, json.JSONDecodeError):
        log.exception("Indexed read failed for %s; using source files", table)
        return None


def _sensor(row: dict[str, Any]) -> str:
    sensor = row.get("sensor")
    if isinstance(sensor, dict) and sensor.get("type"):
        return str(sensor["type"]).strip().lower()
    for key in ("sensorType", "sensor_type", "type", "source"):
        value = str(row.get(key, "")).strip().lower()
        if value in {"endpoint", "email"}:
            return value
    description = row.get("detectionDescription")
    if isinstance(description, dict) and description.get("createdReasonId") in XDR_EMAIL_RULES:
        return "email"
    return ""


def _rule(row: dict[str, Any]) -> str:
    description = row.get("detectionDescription")
    if isinstance(description, dict) and description.get("createdReasonId"):
        return str(description["createdReasonId"])
    return str(row.get("detectionRule", ""))


def load_endpoint_detections_by_range(start: str, end: str) -> list[dict[str, Any]]:
    indexed = _indexed("detection_events", start, end, "AND sensor_type = ?", ("endpoint",))
    rows = indexed if indexed is not None else _daily(DETECTIONS_DAY_DIR, ".json", start, end)
    return rows if indexed is not None else [row for row in rows if _sensor(row) == "endpoint"]


def load_xdr_email_detections_by_range(start: str, end: str) -> list[dict[str, Any]]:
    placeholders = ",".join("?" for _ in XDR_EMAIL_RULES)
    params = ("email", *sorted(XDR_EMAIL_RULES))
    indexed = _indexed("detection_events", start, end, f"AND sensor_type = ? AND rule IN ({placeholders})", params)
    rows = indexed if indexed is not None else _daily(DETECTIONS_DAY_DIR, ".json", start, end)
    return rows if indexed is not None else [row for row in rows if _sensor(row) == "email" and _rule(row) in XDR_EMAIL_RULES]


def load_emails_by_range(start: str, end: str) -> list[dict[str, Any]]:
    indexed = _indexed("email_events", start, end)
    return indexed if indexed is not None else _daily(EMAILS_DAY_DIR, ".json", start, end)


def load_dlp_by_range(start: str, end: str) -> list[dict[str, Any]]:
    indexed = _indexed("dlp_events", start, end)
    return indexed if indexed is not None else _daily(DLP_DAY_DIR, ".jsonl", start, end)


def load_app_cache_single(source: str) -> list[dict[str, Any]]:
    path = SINGLE_FILES[source]
    if APP_CACHE_DB_PATH.exists():
        try:
            with sqlite3.connect(APP_CACHE_DB_PATH) as conn:
                values = conn.execute(
                    "SELECT raw_json FROM app_cache_records WHERE source = ? ORDER BY row_index",
                    (source,),
                ).fetchall()
            rows = [json.loads(raw) for (raw,) in values]
            if rows:
                return [row for row in rows if isinstance(row, dict)]
        except (sqlite3.Error, json.JSONDecodeError):
            log.exception("Single-file index read failed for %s", source)
    return _read_json(path)


def sync_app_cache_all() -> dict[str, Any]:
    """Perform a safe standalone cache inventory for the web UI.

    Existing desktop-created SQLite indexes remain authoritative. Source files
    are counted so the web job has useful output without importing desktop code.
    """
    return {
        "database": str(APP_CACHE_DB_PATH),
        "databaseExists": APP_CACHE_DB_PATH.exists(),
        "sourceFiles": {
            "detections": len(list(DETECTIONS_DAY_DIR.glob("*.json"))),
            "emails": len(list(EMAILS_DAY_DIR.glob("*.json"))),
            "dlp": len(list(DLP_DAY_DIR.glob("*.jsonl"))),
        },
    }
