# -*- coding: utf-8 -*-
"""JSON fallback loaders and SQLite app-cache read models.

JSON/JSONL files remain the source of truth.  This module keeps the same
fallback/error logging behavior while serving indexed rows to UI tabs, exports,
reports, and Timeline indexing.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone, timedelta

from core.detection import XDR_EMAIL_RULES, get_detection_sensor_type
from core.json_utils import load_json, load_jsonl, safe_json_loads
from core.paths import (
    APP_CACHE_DB_PATH, CACHE_DIR, DETECTIONS_DAY_DIR, DLP_DAY_DIR, EMAILS_DAY_DIR,
    TIMELINE_INDEX_DIR,
)
from core.time_utils import dlp_time_to_dt, iso_to_kst_dt
from modules.dlp.formatters import format_dlp_event_id

log = logging.getLogger("SophosUI")
def load_detections_by_range_json(start_date: str, end_date: str):
    results = []

    current = datetime.strptime(start_date, "%Y-%m-%d")
    end = datetime.strptime(end_date, "%Y-%m-%d")

    while current <= end:
        file_path = os.path.join(
            DETECTIONS_DAY_DIR,
            f"{current.strftime('%Y-%m-%d')}.json"
        )

        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        results.extend(data)
            except Exception as e:
                log.warning(f"Failed to load {file_path}: {e}")

        current += timedelta(days=1)

    log.info(f"Loaded detections from {start_date} ~ {end_date} : {len(results)}")
    return results


def load_emails_by_range_json(start_date: str, end_date: str):
    results = []

    current = datetime.strptime(start_date, "%Y-%m-%d")
    end = datetime.strptime(end_date, "%Y-%m-%d")

    while current <= end:
        file_path = os.path.join(
            EMAILS_DAY_DIR,
            f"{current.strftime('%Y-%m-%d')}.json"
        )

        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        results.extend(data)
            except Exception as e:
                log.warning(f"Failed to load {file_path}: {e}")

        current += timedelta(days=1)

    log.info(f"Loaded emails from {start_date} ~ {end_date} : {len(results)}")
    return results
    

def join_list(values):
    if not values:
        return "None"
    if isinstance(values, list):
        return ", ".join([str(x) for x in values])
    return str(values)


def join_or_none(values):
    if not values:
        return "None"
    if isinstance(values, list):
        return ", ".join([str(x) for x in values if str(x).strip()]) or "None"
    return str(values) if str(values).strip() else "None"


def email_addr(obj):
    if not isinstance(obj, dict):
        return "None"
    return f"{obj.get('localAddress','')}@{obj.get('domainAddress','')}".strip("@")


def extract_xdr_email_fields(d):
    rule = "None"
    dd = d.get("detectionDescription", {}) if isinstance(d, dict) else {}
    if isinstance(dd, dict):
        rule = dd.get("createdReasonId", "None") or "None"
    if rule == "None" and isinstance(d, dict):
        rule = d.get("detectionRule", "None") or "None"

    raw_data = d.get("rawData", {}) if isinstance(d, dict) else {}
    if not isinstance(raw_data, dict):
        raw_data = {}

    raw = safe_json_loads(raw_data.get("raw"), {})
    if not isinstance(raw, dict):
        raw = {}

    mailbox = "None"
    if raw.get("mailboxAddress"):
        mailbox = raw.get("mailboxAddress")
    elif raw.get("envelopeRecipients"):
        mailbox = join_or_none(raw.get("envelopeRecipients"))

    return {
        "mailbox": str(mailbox),
        "subject": str(raw.get("subject") or "None"),
        "sender_ip": str(raw.get("clientIp") or "None"),
        "rule": str(rule),
    }


# ======================================================
# Core storage / SQLite app cache and indexed query tables
# - JSON refresh remains the source of truth.
# - app_cache_records stores raw rows for compatibility.
# - detection_events/email_events/dlp_events are indexed read models used by tabs, exports, and reports.
# - Later module target: core/storage/sqlite_cache.py
# ======================================================
APP_CACHE_SOURCES = {
    "detections": {"dir": DETECTIONS_DAY_DIR, "ext": ".json", "format": "json"},
    "emails": {"dir": EMAILS_DAY_DIR, "ext": ".json", "format": "json"},
    "dlp": {"dir": DLP_DAY_DIR, "ext": ".jsonl", "format": "jsonl"},
}

APP_CACHE_SINGLE_FILES = {
    "endpoints": os.path.join(CACHE_DIR, "endpoints.json"),
    "orgs": os.path.join(CACHE_DIR, "user_groups.json"),
    "users": os.path.join(CACHE_DIR, "users.json"),
}


def iter_json_files(base_dir, suffix):
    if not os.path.exists(base_dir):
        return []
    return sorted(
        os.path.join(base_dir, name)
        for name in os.listdir(base_dir)
        if name.lower().endswith(suffix)
    )


def iter_date_strings(start_date: str, end_date: str):
    current = datetime.strptime(start_date, "%Y-%m-%d")
    end = datetime.strptime(end_date, "%Y-%m-%d")
    while current <= end:
        yield current.strftime("%Y-%m-%d")
        current += timedelta(days=1)


def app_cache_connect():
    os.makedirs(TIMELINE_INDEX_DIR, exist_ok=True)
    conn = sqlite3.connect(APP_CACHE_DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    init_app_cache_db(conn)
    return conn


def init_app_cache_db(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS app_cache_files (
            path TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            cache_date TEXT,
            mtime REAL NOT NULL,
            size INTEGER NOT NULL,
            rows INTEGER NOT NULL DEFAULT 0,
            indexed_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS app_cache_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            cache_date TEXT,
            source_file TEXT NOT NULL,
            row_index INTEGER NOT NULL,
            raw_json TEXT NOT NULL,
            UNIQUE(source_file, row_index)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_app_cache_records_source_date ON app_cache_records(source, cache_date)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_app_cache_records_file ON app_cache_records(source_file)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS detection_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_file TEXT NOT NULL,
            row_index INTEGER NOT NULL,
            cache_date TEXT,
            event_time TEXT,
            event_date_kst TEXT,
            sensor_type TEXT,
            rule TEXT,
            hostname TEXT,
            mailbox TEXT,
            sender_ip TEXT,
            subject TEXT,
            raw_json TEXT NOT NULL,
            UNIQUE(source_file, row_index)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_detection_events_date_sensor ON detection_events(event_date_kst, sensor_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_detection_events_rule ON detection_events(rule)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_detection_events_file ON detection_events(source_file)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS email_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_file TEXT NOT NULL,
            row_index INTEGER NOT NULL,
            cache_date TEXT,
            event_time TEXT,
            event_date_kst TEXT,
            sender TEXT,
            recipients TEXT,
            subject TEXT,
            reason TEXT,
            client_ip TEXT,
            raw_json TEXT NOT NULL,
            UNIQUE(source_file, row_index)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_email_events_date ON email_events(event_date_kst)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_email_events_file ON email_events(source_file)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS dlp_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_file TEXT NOT NULL,
            row_index INTEGER NOT NULL,
            cache_date TEXT,
            event_time TEXT,
            event_date_kst TEXT,
            machine_name TEXT,
            client_name TEXT,
            event_id TEXT,
            event_label TEXT,
            filename TEXT,
            destination TEXT,
            filehash TEXT,
            raw_json TEXT NOT NULL,
            UNIQUE(source_file, row_index)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dlp_events_date ON dlp_events(event_date_kst)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dlp_events_machine ON dlp_events(machine_name)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dlp_events_file ON dlp_events(source_file)")


def load_cache_file_rows(path, file_format):
    if file_format == "jsonl":
        return load_jsonl(path)
    data = load_json(path)
    return data if isinstance(data, list) else []


def dt_to_kst_date_text(dt, fallback_date=""):
    if not dt:
        return fallback_date or ""
    try:
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone(timedelta(hours=9))).replace(tzinfo=None)
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return fallback_date or ""


def detection_index_values(row, source, path, idx, cache_date, raw_json):
    event_dt = iso_to_kst_dt(row.get("time")) if isinstance(row, dict) else None
    event_date = dt_to_kst_date_text(event_dt, cache_date)
    sensor_type = get_detection_sensor_type(row)
    dd = row.get("detectionDescription", {}) if isinstance(row, dict) else {}
    rule = ""
    if isinstance(dd, dict):
        rule = str(dd.get("createdReasonId", "") or "").strip()
    if not rule and isinstance(row, dict):
        rule = str(row.get("detectionRule", "") or "").strip()
    raw = row.get("rawData", {}) if isinstance(row, dict) and isinstance(row.get("rawData"), dict) else {}
    hostname = str(raw.get("meta_hostname", "") or "").strip()
    mailbox = ""
    sender_ip = ""
    subject = ""
    if sensor_type == "email":
        try:
            xdr = extract_xdr_email_fields(row)
            mailbox = str(xdr.get("mailbox", "") or "").strip()
            sender_ip = str(xdr.get("sender_ip", "") or "").strip()
            subject = str(xdr.get("subject", "") or "").strip()
        except Exception:
            pass
    return (
        path,
        idx,
        cache_date,
        row.get("time") if isinstance(row, dict) else "",
        event_date,
        sensor_type,
        rule,
        hostname,
        mailbox,
        sender_ip,
        subject,
        raw_json,
    )


def email_index_values(row, source, path, idx, cache_date, raw_json):
    event_time = row.get("receivedAt") if isinstance(row, dict) else ""
    event_date = dt_to_kst_date_text(iso_to_kst_dt(event_time), cache_date)
    from_addr = ""
    recipients = ""
    if isinstance(row, dict):
        try:
            from_addr = email_addr(row.get("from"))
            to_list = [email_addr(x) for x in (row.get("to", []) or []) if isinstance(x, dict)]
            cc_list = [email_addr(x) for x in (row.get("cc", []) or []) if isinstance(x, dict)]
            recipients = join_list(to_list + cc_list)
        except Exception:
            pass
    return (
        path,
        idx,
        cache_date,
        event_time,
        event_date,
        from_addr,
        recipients,
        str(row.get("subject", "") or "") if isinstance(row, dict) else "",
        str(row.get("reason", "") or "") if isinstance(row, dict) else "",
        str(row.get("clientIp", "") or "") if isinstance(row, dict) else "",
        raw_json,
    )


def dlp_index_values(row, source, path, idx, cache_date, raw_json):
    event_time = str(row.get("eventtimelocal", "") or "") if isinstance(row, dict) else ""
    event_dt = dlp_time_to_dt(event_time)
    event_date = dt_to_kst_date_text(event_dt, cache_date)
    event_id = str(row.get("event_id", "") or "") if isinstance(row, dict) else ""
    return (
        path,
        idx,
        cache_date,
        event_time,
        event_date,
        str(row.get("machine_name", "") or "") if isinstance(row, dict) else "",
        str(row.get("client_name", "") or "") if isinstance(row, dict) else "",
        event_id,
        format_dlp_event_id(event_id),
        str(row.get("filename", "") or "") if isinstance(row, dict) else "",
        str(row.get("destination", "") or "") if isinstance(row, dict) else "",
        str(row.get("filehash", "") or "") if isinstance(row, dict) else "",
        raw_json,
    )


APP_CACHE_INDEX_INSERTS = {
    "detections": (
        "DELETE FROM detection_events WHERE source_file = ?",
        """
        INSERT OR REPLACE INTO detection_events
            (source_file, row_index, cache_date, event_time, event_date_kst, sensor_type, rule, hostname, mailbox, sender_ip, subject, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        detection_index_values,
    ),
    "emails": (
        "DELETE FROM email_events WHERE source_file = ?",
        """
        INSERT OR REPLACE INTO email_events
            (source_file, row_index, cache_date, event_time, event_date_kst, sender, recipients, subject, reason, client_ip, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        email_index_values,
    ),
    "dlp": (
        "DELETE FROM dlp_events WHERE source_file = ?",
        """
        INSERT OR REPLACE INTO dlp_events
            (source_file, row_index, cache_date, event_time, event_date_kst, machine_name, client_name, event_id, event_label, filename, destination, filehash, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        dlp_index_values,
    ),
}


def sync_app_cache_file(conn, source, path, cache_date=None, file_format="json"):
    stat = os.stat(path)
    rows = load_cache_file_rows(path, file_format)
    if not isinstance(rows, list):
        rows = []

    conn.execute("DELETE FROM app_cache_records WHERE source_file = ?", (path,))
    index_spec = APP_CACHE_INDEX_INSERTS.get(source)
    if index_spec:
        conn.execute(index_spec[0], (path,))

    payload = []
    index_payload = []
    for idx, row in enumerate(rows):
        if not isinstance(row, (dict, list)):
            continue
        raw_json = json.dumps(row, ensure_ascii=False)
        payload.append((source, cache_date, path, idx, raw_json))
        if index_spec and isinstance(row, dict):
            try:
                index_payload.append(index_spec[2](row, source, path, idx, cache_date, raw_json))
            except Exception as e:
                log.warning(f"SQLite index row build failed source={source} path={path} row={idx}: {e}")
    if payload:
        conn.executemany(
            """
            INSERT OR REPLACE INTO app_cache_records
                (source, cache_date, source_file, row_index, raw_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            payload,
        )
    if index_payload:
        conn.executemany(index_spec[1], index_payload)
    conn.execute(
        """
        INSERT OR REPLACE INTO app_cache_files
            (path, source, cache_date, mtime, size, rows, indexed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            path,
            source,
            cache_date,
            float(stat.st_mtime),
            int(stat.st_size),
            len(payload),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    return len(payload)


def app_cache_file_current(conn, path):
    if not os.path.exists(path):
        return True
    stat = os.stat(path)
    row = conn.execute(
        "SELECT mtime, size FROM app_cache_files WHERE path = ?",
        (path,),
    ).fetchone()
    if not row:
        return False
    return float(row[0] or 0) == float(stat.st_mtime) and int(row[1] or 0) == int(stat.st_size)


def app_cache_index_current(conn, source, path):
    if not app_cache_file_current(conn, path):
        return False
    table_map = {
        "detections": "detection_events",
        "emails": "email_events",
        "dlp": "dlp_events",
    }
    table = table_map.get(source)
    if not table:
        return True
    try:
        return conn.execute(f"SELECT 1 FROM {table} WHERE source_file = ? LIMIT 1", (path,)).fetchone() is not None
    except sqlite3.Error:
        return False


def sync_app_cache_range(source, start_date, end_date, progress_cb=None):
    cfg = APP_CACHE_SOURCES[source]
    stats = {"indexed": 0, "skipped": 0, "rows": 0, "files": 0, "source": source}
    with app_cache_connect() as conn:
        for cache_date in iter_date_strings(start_date, end_date):
            path = os.path.join(cfg["dir"], f"{cache_date}{cfg['ext']}")
            if not os.path.exists(path):
                continue
            stats["files"] += 1
            if app_cache_index_current(conn, source, path):
                stats["skipped"] += 1
                continue
            if progress_cb:
                progress_cb(f"SQLite 데이터 반영중 - {source} {cache_date}")
            stats["rows"] += sync_app_cache_file(conn, source, path, cache_date, cfg["format"])
            stats["indexed"] += 1
        conn.commit()
    return stats


def sync_app_cache_all(progress_cb=None):
    totals = {"data_rows": 0, "data_files": 0, "data_indexed": 0, "data_skipped": 0}
    with app_cache_connect() as conn:
        for source, cfg in APP_CACHE_SOURCES.items():
            for path in iter_json_files(cfg["dir"], cfg["ext"]):
                cache_date = os.path.splitext(os.path.basename(path))[0]
                totals["data_files"] += 1
                if app_cache_index_current(conn, source, path):
                    totals["data_skipped"] += 1
                    continue
                if progress_cb:
                    progress_cb(f"SQLite 데이터 반영중 - {source} {cache_date}")
                totals["data_rows"] += sync_app_cache_file(conn, source, path, cache_date, cfg["format"])
                totals["data_indexed"] += 1
        for source, path in APP_CACHE_SINGLE_FILES.items():
            if not os.path.exists(path):
                continue
            totals["data_files"] += 1
            if app_cache_file_current(conn, path):
                totals["data_skipped"] += 1
                continue
            if progress_cb:
                progress_cb(f"SQLite 데이터 반영중 - {source}")
            totals["data_rows"] += sync_app_cache_file(conn, source, path, None, "json")
            totals["data_indexed"] += 1
        existing_paths = set()
        for source, cfg in APP_CACHE_SOURCES.items():
            existing_paths.update(iter_json_files(cfg["dir"], cfg["ext"]))
        existing_paths.update(path for path in APP_CACHE_SINGLE_FILES.values() if os.path.exists(path))
        stale_rows = conn.execute("SELECT path FROM app_cache_files").fetchall()
        removed = 0
        for (path,) in stale_rows:
            if path not in existing_paths:
                conn.execute("DELETE FROM app_cache_records WHERE source_file = ?", (path,))
                conn.execute("DELETE FROM detection_events WHERE source_file = ?", (path,))
                conn.execute("DELETE FROM email_events WHERE source_file = ?", (path,))
                conn.execute("DELETE FROM dlp_events WHERE source_file = ?", (path,))
                conn.execute("DELETE FROM app_cache_files WHERE path = ?", (path,))
                removed += 1
        totals["data_removed"] = removed
        conn.commit()
        totals["data_total_rows"] = conn.execute("SELECT COUNT(*) FROM app_cache_records").fetchone()[0]
        totals["data_total_files"] = conn.execute("SELECT COUNT(*) FROM app_cache_files").fetchone()[0]
    totals["app_db_path"] = APP_CACHE_DB_PATH
    return totals


def load_app_cache_records(source, start_date=None, end_date=None):
    if start_date is not None and end_date is not None:
        sync_app_cache_range(source, start_date, end_date)

    with app_cache_connect() as conn:
        if start_date is not None and end_date is not None:
            rows = conn.execute(
                """
                SELECT raw_json FROM app_cache_records
                WHERE source = ? AND cache_date BETWEEN ? AND ?
                ORDER BY cache_date ASC, source_file ASC, row_index ASC
                """,
                (source, start_date, end_date),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT raw_json FROM app_cache_records
                WHERE source = ?
                ORDER BY source_file ASC, row_index ASC
                """,
                (source,),
            ).fetchall()
    results = []
    for (raw_json,) in rows:
        try:
            value = json.loads(raw_json)
            if isinstance(value, dict):
                results.append(value)
        except Exception as e:
            log.warning(f"SQLite cache row parse failed source={source}: {e}")
    return results


def load_app_cache_single(source, path, json_fallback=True):
    try:
        if os.path.exists(path):
            with app_cache_connect() as conn:
                if not app_cache_file_current(conn, path):
                    sync_app_cache_file(conn, source, path, None, "json")
                    conn.commit()
        rows = load_app_cache_records(source)
        if rows or not json_fallback:
            log.info(f"Loaded {source} from SQLite cache : {len(rows)}")
            return rows
    except Exception as e:
        log.warning(f"SQLite {source} load failed, fallback to JSON: {e}")
    return load_json(path)


def load_indexed_raw_rows(table, start_date, end_date, extra_where="", params=()):
    with app_cache_connect() as conn:
        sql = f"""
            SELECT raw_json FROM {table}
            WHERE COALESCE(NULLIF(event_date_kst, ''), cache_date) BETWEEN ? AND ?
            {extra_where}
            ORDER BY COALESCE(NULLIF(event_time, ''), cache_date) ASC, source_file ASC, row_index ASC
        """
        rows = conn.execute(sql, (start_date, end_date, *params)).fetchall()
    results = []
    for (raw_json,) in rows:
        try:
            value = json.loads(raw_json)
            if isinstance(value, dict):
                results.append(value)
        except Exception as e:
            log.warning(f"SQLite indexed row parse failed table={table}: {e}")
    return results


def load_indexed_detections_by_range(start_date, end_date, sensor_type=None, xdr_email_only=False):
    sync_app_cache_range("detections", start_date, end_date)
    extra = ""
    params = []
    if sensor_type:
        extra += " AND sensor_type = ?"
        params.append(sensor_type)
    if xdr_email_only:
        placeholders = ",".join(["?"] * len(XDR_EMAIL_RULES))
        extra += f" AND rule IN ({placeholders})"
        params.extend(sorted(XDR_EMAIL_RULES))
    return load_indexed_raw_rows("detection_events", start_date, end_date, extra, tuple(params))


def load_endpoint_detections_by_range(start_date, end_date):
    return load_indexed_detections_by_range(start_date, end_date, sensor_type="endpoint")


def load_xdr_email_detections_by_range(start_date, end_date):
    return load_indexed_detections_by_range(start_date, end_date, sensor_type="email", xdr_email_only=True)


def load_detections_by_range(start_date: str, end_date: str):
    try:
        rows = load_indexed_detections_by_range(start_date, end_date)
        log.info(f"Loaded detections from SQLite index {start_date} ~ {end_date} : {len(rows)}")
        return rows
    except Exception as e:
        log.warning(f"SQLite detections index load failed, fallback to JSON: {e}")
        return load_detections_by_range_json(start_date, end_date)


def load_emails_by_range(start_date: str, end_date: str):
    try:
        sync_app_cache_range("emails", start_date, end_date)
        rows = load_indexed_raw_rows("email_events", start_date, end_date)
        log.info(f"Loaded emails from SQLite index {start_date} ~ {end_date} : {len(rows)}")
        return rows
    except Exception as e:
        log.warning(f"SQLite emails index load failed, fallback to JSON: {e}")
        return load_emails_by_range_json(start_date, end_date)


def load_dlp_by_range(start_date: str, end_date: str):
    try:
        sync_app_cache_range("dlp", start_date, end_date)
        rows = load_indexed_raw_rows("dlp_events", start_date, end_date)
        log.info(f"Loaded DLP from SQLite index {start_date} ~ {end_date} : {len(rows)}")
        return rows
    except Exception as e:
        log.warning(f"SQLite DLP index load failed, fallback to JSON: {e}")
        return load_dlp_by_range_json(start_date, end_date)


def load_dlp_by_range_json(start_date: str, end_date: str):
    results = []

    current = datetime.strptime(start_date, "%Y-%m-%d")
    end = datetime.strptime(end_date, "%Y-%m-%d")

    while current <= end:
        file_path = os.path.join(
            DLP_DAY_DIR,
            f"{current.strftime('%Y-%m-%d')}.jsonl"
        )

        if os.path.exists(file_path):
            try:
                results.extend(load_jsonl(file_path))
            except Exception as e:
                log.warning(f"Failed to load {file_path}: {e}")

        current += timedelta(days=1)

    log.info(f"Loaded DLP from {start_date} ~ {end_date} : {len(results)}")
    return results

