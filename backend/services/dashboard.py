import json
import os
import threading
from collections import Counter, defaultdict
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from backend.services.detections import DetectionService
from backend.services.email_security import EmailSecurityService
from backend.services.endpoints import load_json_list
from backend.services.timeline import TimelineService
from backend.services.transfers import TransferService


SERIES_NAMES = ("Detection - XDR", "Email - XDR", "Inbound Mail", "Outbound Mail", "File")


class DashboardService:
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.detections = DetectionService(project_root)
        self.email = EmailSecurityService(project_root)
        self.transfers = TransferService(project_root)
        self.timeline = TimelineService(project_root)
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
        ]
        for name in ("detections", "emails", "mailscreen", "dlp"):
            directory = self.project_root / "cache" / name
            if directory.exists():
                paths.extend(path for path in directory.iterdir() if path.is_file())
        return "|".join(
            f"{path.relative_to(self.project_root)}:{path.stat().st_mtime_ns}:{path.stat().st_size}"
            for path in sorted(paths)
            if path.exists()
        )

    def default_range(self) -> tuple[date, date]:
        bounds = self.timeline.date_bounds()
        end = bounds[1] if bounds else date.today()
        return end - timedelta(days=6), end

    def warm_default(self) -> None:
        start, end = self.default_range()
        self.summary(start, end)

    @staticmethod
    def percentage(current: int, comparison: int) -> float | None:
        if comparison == 0:
            return None if current else 0.0
        return round((current - comparison) / comparison * 100, 1)

    def _rows(self, start: date, end: date) -> dict[str, list[tuple]]:
        return {
            "Detection - XDR": self.detections._events(start, end)[0],
            "Email - XDR": self.email._collect_xdr(start, end)[0],
            "Inbound Mail": self.email._collect_inbound(start, end)[0],
            "Outbound Mail": self.transfers._collect_outbound(start, end)[0],
            "File": self.transfers._collect_dlp(start, end)[0],
        }

    @staticmethod
    def _totals(rows: dict[str, list[tuple]]) -> dict[str, int]:
        return {name: len(rows[name]) for name in SERIES_NAMES}

    def folder_usage(self) -> dict[str, int]:
        result = {}
        for label, name in (("Logs", "logs"), ("Cache", "cache"), ("Exports", "exports"), ("Reports", "reports"), ("Env", "env")):
            directory = self.project_root / name
            result[label] = sum(path.stat().st_size for path in directory.rglob("*") if path.is_file()) if directory.exists() else 0
        return result

    def summary(self, start: date | None = None, end: date | None = None, refresh: bool = False) -> dict[str, Any]:
        if start is None or end is None:
            start, end = self.default_range()
        if start > end:
            raise ValueError("start date must not be after end date")
        if (end - start).days > 30:
            raise ValueError("dashboard range must not exceed 31 days")
        fingerprint = self.fingerprint()
        key = f"{start.isoformat()}:{end.isoformat()}"
        with self._lock:
            cached = self._cache.get(key)
            if not refresh and cached and cached.get("fingerprint") == fingerprint:
                return {**cached["data"], "cache": "pre-aggregated"}

        with self._build_lock:
            with self._lock:
                cached = self._cache.get(key)
                if not refresh and cached and cached.get("fingerprint") == fingerprint:
                    return {**cached["data"], "cache": "pre-aggregated"}

            rows = self._rows(start, end)
            duration = (end - start).days + 1
            previous_end = start - timedelta(days=1)
            previous_start = previous_end - timedelta(days=duration - 1)
            year_start, year_end = start - timedelta(days=365), end - timedelta(days=365)
            previous_totals = self._totals(self._rows(previous_start, previous_end))
            year_totals = self._totals(self._rows(year_start, year_end))
            totals = self._totals(rows)

            endpoints = load_json_list(self.project_root / "cache/endpoints.json")
            organizations = load_json_list(self.project_root / "cache/user_groups.json")
            endpoint_counts = Counter(str(item.get("type", "computer") or "computer").lower() for item in endpoints)
            users = {
                str(user.get("name", "") if isinstance(user, dict) else user).strip()
                for organization in organizations
                for user in (organization.get("users", []) if isinstance(organization.get("users"), list) else [])
                if str(user.get("name", "") if isinstance(user, dict) else user).strip()
            }
            dates = [(start + timedelta(days=index)).isoformat() for index in range(duration)]
            series: dict[str, dict[str, int]] = {name: defaultdict(int) for name in SERIES_NAMES}
            time_fields = {"Detection - XDR": "time", "Email - XDR": "time", "Inbound Mail": "received", "Outbound Mail": "date", "File": "time"}
            for name, source_rows in rows.items():
                for _record_id, _raw, row in source_rows:
                    series[name][str(row[time_fields[name]])[:10]] += 1

            detections = rows["Detection - XDR"]
            xdr = rows["Email - XDR"]
            inbound = rows["Inbound Mail"]
            files = rows["File"]
            counters = {
                "files": Counter(row["file"] for _id, _raw, row in detections if row["file"] != "None"),
                "hashes": Counter(row["sha256"] for _id, _raw, row in detections if row["sha256"] != "None"),
                "hosts": Counter(row["hostname"] for _id, _raw, row in detections if row["hostname"] != "None"),
                "rules": Counter(row["rule"] for _id, _raw, row in detections if row["rule"] != "None"),
                "senders": Counter(row["senderIp"] for _id, _raw, row in inbound if row["senderIp"] != "None"),
            }
            summary = {
                "detection": [["Top Host", counters["hosts"].most_common(1)], ["Top Rule", counters["rules"].most_common(1)], ["Top File", counters["files"].most_common(1)]],
                "xdr": [["Top Rule", Counter(row["rule"] for _id, _raw, row in xdr).most_common(1)], ["Top From", Counter(row["from"] for _id, _raw, row in xdr).most_common(1)], ["Top Sender IP", Counter(row["senderIp"] for _id, _raw, row in xdr).most_common(1)]],
                "inbound": [["Top Sender IP", counters["senders"].most_common(1)], ["Top Reason", Counter(row["reason"] for _id, _raw, row in inbound).most_common(1)], ["Top To", Counter(row["to"] for _id, _raw, row in inbound).most_common(1)]],
                "file": [["Top Machine", Counter(row["computer"] for _id, _raw, row in files).most_common(1)], ["Top Source", Counter(row["source"] for _id, _raw, row in files).most_common(1)], ["Top Destination", Counter(row["destination"] for _id, _raw, row in files).most_common(1)]],
            }
            data = {
                "range": {"start": start.isoformat(), "end": end.isoformat()},
                "comparisonRange": {"start": previous_start.isoformat(), "end": previous_end.isoformat()},
                "endpoints": {"pc": endpoint_counts["computer"], "server": endpoint_counts["server"], "total": len(endpoints)},
                "organization": {"departments": len(organizations), "users": len(users)},
                "folderUsage": self.folder_usage(), "totals": totals,
                "comparison": {name: {"previous": self.percentage(totals[name], previous_totals[name]), "year": self.percentage(totals[name], year_totals[name])} for name in SERIES_NAMES},
                "trend": {"dates": dates, "series": {name: [values[day] for day in dates] for name, values in series.items()}},
                "top": {name: counter.most_common(6) for name, counter in counters.items()},
                "summary": summary,
            }
            with self._lock:
                self._cache[key] = {"fingerprint": fingerprint, "data": data}
                self._save_cache()
            return {**data, "cache": "freshly-aggregated"}
