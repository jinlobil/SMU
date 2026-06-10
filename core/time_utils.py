# -*- coding: utf-8 -*-
"""Time conversion helpers shared by Sophos, DLP, reports, exports, and storage."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta


def kst_time(iso):
    if not iso:
        return "None"
    try:
        dt = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        return dt.astimezone(timezone(timedelta(hours=9))).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(iso)


def iso_to_kst_dt(iso):
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        kst_dt = dt.astimezone(timezone(timedelta(hours=9)))
        return kst_dt.replace(tzinfo=None)
    except Exception:
        return None


def dlp_time_to_dt(value):
    if not value:
        return None
    try:
        return datetime.strptime(str(value).strip(), "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def combine_date_time(date_edit, time_edit):
    d = date_edit.date().toPyDate()
    t = time_edit.time().toPyTime()
    return datetime.combine(d, t)


def kst_date_range_to_utc_iso(start_date: str, end_date: str):
    start_dt = datetime.strptime(start_date, "%Y-%m-%d").replace(
        hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone(timedelta(hours=9))
    )
    end_dt = datetime.strptime(end_date, "%Y-%m-%d").replace(
        hour=23, minute=59, second=59, microsecond=0, tzinfo=timezone(timedelta(hours=9))
    )
    return (
        start_dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        end_dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    )


def unix_ms_to_kst(unix_ms):
    try:
        sec = int(unix_ms) // 1000
        dt = datetime.fromtimestamp(sec, tz=timezone.utc)
        return dt.astimezone(timezone(timedelta(hours=9))).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "None"


def day_key_from_iso(iso_str):
    """ISO time -> 'YYYY-MM-DD' using KST."""
    if not iso_str:
        return None
    try:
        dt = datetime.fromisoformat(str(iso_str).replace("Z", "+00:00"))
        kst = dt.astimezone(timezone(timedelta(hours=9)))
        return kst.strftime("%Y-%m-%d")
    except Exception:
        return None
