import json
import os
import threading
import calendar
from collections import Counter
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from backend.services.endpoints import load_json_list
from backend.services.event_list_index import EventListIndex


SERIES_NAMES = ("Detection - XDR", "Email - XDR", "Inbound Mail", "Outbound Mail", "File")
KIND_TO_SERIES = {
    "detections": "Detection - XDR",
    "xdr": "Email - XDR",
    "inbound": "Inbound Mail",
    "outbound": "Outbound Mail",
    "dlp": "File",
}
EVENT_KINDS = tuple(KIND_TO_SERIES.keys())
DASHBOARD_CACHE_VERSION = 3


class DashboardService:
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.event_index = EventListIndex(project_root)
        self.cache_path = project_root / "cache/index/web_dashboard_summary.json"
        self._cache: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._build_lock = threading.Lock()
        self._load_cache()

    def _load_cache(self) -> None:
        if not self.cache_path.exists():
            return
        try:
            payload = json.loads(self.cache_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                self._cache = payload
        except (OSError, json.JSONDecodeError):
            self._cache = {}

    def _save_cache(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.cache_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self._cache, ensure_ascii=False), encoding="utf-8")
        os.replace(temporary, self.cache_path)

    def fingerprint(self) -> str:
        paths = [
            self.project_root / "cache/endpoints.json",
            self.project_root / "cache/user_groups.json",
            self.event_index.path,
        ]
        return "|".join(
            f"{path.relative_to(self.project_root)}:{path.stat().st_mtime_ns}:{path.stat().st_size}"
            for path in sorted(paths)
            if path.exists()
        )

    def default_range(self) -> tuple[date, date]:
        bounds = self.event_index.date_bounds()
        end = bounds[1] if bounds else date.today()
        return end - timedelta(days=6), end

    def warm_default(self) -> None:
        start, end = self.default_range()
        self.summary(start, end)

    def _normalize_range(self, start: date | None, end: date | None) -> tuple[date, date]:
        if start is None or end is None:
            start, end = self.default_range()
        if start > end:
            raise ValueError("start date must not be after end date")
        if (end - start).days > 30:
            raise ValueError("dashboard range must not exceed 31 days")
        return start, end

    @staticmethod
    def percentage(current: int, comparison: int) -> float | None:
        if comparison == 0:
            return None if current else 0.0
        return round((current - comparison) / comparison * 100, 1)

    @staticmethod
    def previous_month_day(value: date) -> date:
        year, month = (value.year - 1, 12) if value.month == 1 else (value.year, value.month - 1)
        return date(year, month, min(value.day, calendar.monthrange(year, month)[1]))

    @staticmethod
    def _range_payload(start: date, end: date) -> dict[str, str]:
        return {"start": start.isoformat(), "end": end.isoformat()}

    @staticmethod
    def _counter(rows: list[dict[str, str]], field: str) -> Counter[str]:
        return Counter(value for row in rows if (value := str(row.get(field, "None") or "None")) != "None")

    @staticmethod
    def _top(counter: Counter[str], limit: int = 6) -> list[tuple[str, int]]:
        return counter.most_common(limit)

    def _totals_for_counts(self, counts: dict[str, int]) -> dict[str, int]:
        return {series: int(counts.get(kind, 0)) for kind, series in KIND_TO_SERIES.items()}

    def folder_usage(self) -> dict[str, int]:
        result = {}
        for label, name in (("Logs", "logs"), ("Cache", "cache"), ("Exports", "exports"), ("Reports", "reports"), ("Env", "env")):
            directory = self.project_root / name
            result[label] = sum(path.stat().st_size for path in directory.rglob("*") if path.is_file()) if directory.exists() else 0
        return result

    def assets(self, start: date | None = None, end: date | None = None) -> dict[str, Any]:
        start, end = self._normalize_range(start, end)
        endpoints = load_json_list(self.project_root / "cache/endpoints.json")
        organizations = load_json_list(self.project_root / "cache/user_groups.json")
        endpoint_counts = Counter(str(item.get("type", "computer") or "computer").lower() for item in endpoints)
        users = {
            str(user.get("name", "") if isinstance(user, dict) else user).strip()
            for organization in organizations
            for user in (organization.get("users", []) if isinstance(organization.get("users"), list) else [])
            if str(user.get("name", "") if isinstance(user, dict) else user).strip()
        }
        return {
            "range": self._range_payload(start, end),
            "endpoints": {"pc": endpoint_counts["computer"], "server": endpoint_counts["server"], "total": len(endpoints)},
            "organization": {"departments": len(organizations), "users": len(users)},
            "folderUsage": self.folder_usage(),
        }

    def mix_trend(self, start: date | None = None, end: date | None = None) -> dict[str, Any]:
        start, end = self._normalize_range(start, end)
        duration = (end - start).days + 1
        yesterday = end - timedelta(days=1)
        previous_month = self.previous_month_day(end)
        dates = [(start + timedelta(days=index)).isoformat() for index in range(duration)]
        totals = self._totals_for_counts(self.event_index.count_by_kind(start, end, list(EVENT_KINDS)))
        today_totals = self._totals_for_counts(self.event_index.count_by_kind(end, end, list(EVENT_KINDS)))
        yesterday_totals = self._totals_for_counts(self.event_index.count_by_kind(yesterday, yesterday, list(EVENT_KINDS)))
        previous_month_totals = self._totals_for_counts(self.event_index.count_by_kind(previous_month, previous_month, list(EVENT_KINDS)))
        daily = self.event_index.daily_counts(start, end, list(EVENT_KINDS))
        series = {
            series_name: [daily.get(kind, {}).get(day, 0) for day in dates]
            for kind, series_name in KIND_TO_SERIES.items()
        }
        return {
            "range": self._range_payload(start, end),
            "comparisonRange": {"day": yesterday.isoformat(), "month": previous_month.isoformat()},
            "totals": totals,
            "comparison": {
                name: {
                    "day": self.percentage(today_totals[name], yesterday_totals[name]),
                    "month": self.percentage(today_totals[name], previous_month_totals[name]),
                }
                for name in SERIES_NAMES
            },
            "trend": {"dates": dates, "series": series},
            "cache": "indexed",
        }

    def top_detection(self, start: date | None = None, end: date | None = None) -> dict[str, Any]:
        start, end = self._normalize_range(start, end)
        rows = self.event_index.rows_for_kind("detections", start, end)
        counters = {
            "files": self._counter(rows, "file"),
            "hashes": self._counter(rows, "sha256"),
            "hosts": self._counter(rows, "hostname"),
            "rules": self._counter(rows, "rule"),
        }
        return {
            "range": self._range_payload(start, end),
            "top": {name: self._top(counter) for name, counter in counters.items()},
            "summary": {
                "detection": [
                    ["Top Host", self._top(counters["hosts"], 1)],
                    ["Top Rule", self._top(counters["rules"], 1)],
                    ["Top File", self._top(counters["files"], 1)],
                ]
            },
        }

    def top_mail(self, start: date | None = None, end: date | None = None) -> dict[str, Any]:
        start, end = self._normalize_range(start, end)
        xdr_rows = self.event_index.rows_for_kind("xdr", start, end)
        inbound_rows = self.event_index.rows_for_kind("inbound", start, end)
        senders = self._counter(inbound_rows, "senderIp")
        return {
            "range": self._range_payload(start, end),
            "top": {"senders": self._top(senders)},
            "summary": {
                "xdr": [
                    ["Top Rule", self._top(self._counter(xdr_rows, "rule"), 1)],
                    ["Top From", self._top(self._counter(xdr_rows, "from"), 1)],
                    ["Top Sender IP", self._top(self._counter(xdr_rows, "senderIp"), 1)],
                ],
                "inbound": [
                    ["Top Sender IP", self._top(senders, 1)],
                    ["Top Reason", self._top(self._counter(inbound_rows, "reason"), 1)],
                    ["Top To", self._top(self._counter(inbound_rows, "to"), 1)],
                ],
            },
        }

    def top_file(self, start: date | None = None, end: date | None = None) -> dict[str, Any]:
        start, end = self._normalize_range(start, end)
        rows = self.event_index.rows_for_kind("dlp", start, end)
        return {
            "range": self._range_payload(start, end),
            "summary": {
                "file": [
                    ["Top Machine", self._top(self._counter(rows, "computer"), 1)],
                    ["Top Source", self._top(self._counter(rows, "source"), 1)],
                    ["Top Destination", self._top(self._counter(rows, "destination"), 1)],
                ]
            },
        }

    def summary(self, start: date | None = None, end: date | None = None, refresh: bool = False) -> dict[str, Any]:
        start, end = self._normalize_range(start, end)
        fingerprint = self.fingerprint()
        key = f"{start.isoformat()}:{end.isoformat()}"
        with self._lock:
            cached = self._cache.get(key)
            if not refresh and cached and cached.get("version") == DASHBOARD_CACHE_VERSION and cached.get("fingerprint") == fingerprint:
                return {**cached["data"], "cache": "pre-aggregated"}

        with self._build_lock:
            with self._lock:
                cached = self._cache.get(key)
                if not refresh and cached and cached.get("version") == DASHBOARD_CACHE_VERSION and cached.get("fingerprint") == fingerprint:
                    return {**cached["data"], "cache": "pre-aggregated"}

            assets = self.assets(start, end)
            mix_trend = self.mix_trend(start, end)
            top_detection = self.top_detection(start, end)
            top_mail = self.top_mail(start, end)
            top_file = self.top_file(start, end)
            data = {
                "range": self._range_payload(start, end),
                "comparisonRange": mix_trend["comparisonRange"],
                "endpoints": assets["endpoints"],
                "organization": assets["organization"],
                "folderUsage": assets["folderUsage"],
                "totals": mix_trend["totals"],
                "comparison": mix_trend["comparison"],
                "trend": mix_trend["trend"],
                "top": {
                    **top_detection["top"],
                    **top_mail["top"],
                },
                "summary": {
                    **top_detection["summary"],
                    **top_mail["summary"],
                    **top_file["summary"],
                },
            }
            with self._lock:
                self._cache[key] = {"version": DASHBOARD_CACHE_VERSION, "fingerprint": fingerprint, "data": data}
                self._save_cache()
            return {**data, "cache": "freshly-aggregated"}
