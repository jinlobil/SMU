import json
import logging
from datetime import datetime, timedelta
from pathlib import Path


class SystemMetricsService:
    BUCKET_SECONDS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}

    def __init__(self, root: Path, interval_seconds: int = 5, retention_days: int = 30, autostart: bool = True):
        self.directory = root / "runtime/system_metrics"
        self.interval_seconds = interval_seconds
        self.retention_days = retention_days
        self.log = logging.getLogger("smu.web.system_metrics")

    def current(self) -> dict:
        collector = self._read_json(self.directory / "collector_status.json")
        watchdog = self._read_json(self.directory / "watchdog_status.json")
        return {
            "collector": {
                "running": collector.get("status") == "running",
                "intervalSeconds": self.interval_seconds,
                "retentionDays": self.retention_days,
                "lastError": collector.get("lastError"),
            },
            "sample": collector.get("sample"),
            "processes": watchdog or {"watchdog": {"status": "missing"}, "collector": collector},
        }

    @staticmethod
    def _read_json(path: Path) -> dict:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    @staticmethod
    def _parse(value: str) -> datetime:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone() if parsed.tzinfo else parsed.astimezone()

    def history(self, start: str, end: str, bucket: str) -> dict:
        if bucket not in self.BUCKET_SECONDS:
            raise ValueError("bucket은 second, minute, hour, day 중 하나여야 합니다.")
        start_at, end_at = self._parse(start), self._parse(end)
        if start_at > end_at:
            raise ValueError("시작 시간이 종료 시간보다 늦을 수 없습니다.")
        if end_at - start_at > timedelta(days=366):
            raise ValueError("조회 기간은 최대 366일입니다.")

        rows: list[dict] = []
        day = start_at.date()
        while day <= end_at.date():
            path = self.directory / f"{day.isoformat()}.jsonl"
            if path.exists():
                try:
                    lines = path.read_text(encoding="utf-8").splitlines()
                except PermissionError:
                    lines = []
                for line in lines:
                    try:
                        row = json.loads(line)
                        timestamp = self._parse(row["timestamp"])
                        if start_at <= timestamp <= end_at:
                            rows.append({**row, "_time": timestamp})
                    except (ValueError, KeyError, json.JSONDecodeError):
                        self.log.warning("Skipping invalid system metrics row in %s", path)
            day += timedelta(days=1)

        grouped: dict[datetime, list[dict]] = {}
        for row in rows:
            timestamp = row["_time"]
            if bucket == "second":
                key = timestamp.replace(microsecond=0)
            elif bucket == "minute":
                key = timestamp.replace(second=0, microsecond=0)
            elif bucket == "hour":
                key = timestamp.replace(minute=0, second=0, microsecond=0)
            else:
                key = timestamp.replace(hour=0, minute=0, second=0, microsecond=0)
            grouped.setdefault(key, []).append(row)

        points = []
        for key, values in sorted(grouped.items()):
            cpu = [float(row["cpuPercent"]) for row in values]
            memory = [float(row["memoryPercent"]) for row in values]
            latest = values[-1]
            points.append({
                "timestamp": key.isoformat(timespec="seconds"),
                "cpu": {"average": round(sum(cpu) / len(cpu), 1), "minimum": min(cpu), "maximum": max(cpu)},
                "memory": {"average": round(sum(memory) / len(memory), 1), "minimum": min(memory), "maximum": max(memory)},
                "memoryUsedBytes": latest["memoryUsedBytes"],
                "memoryTotalBytes": latest["memoryTotalBytes"],
                "samples": len(values),
            })
        return {"start": start_at.isoformat(), "end": end_at.isoformat(), "bucket": bucket, "points": points}
