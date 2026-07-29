import json
import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path

import psutil


class SystemMetricsService:
    BUCKET_SECONDS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}

    def __init__(self, root: Path, interval_seconds: int = 5, retention_days: int = 30, autostart: bool = True):
        self.directory = root / "runtime/system_metrics"
        self.interval_seconds = interval_seconds
        self.retention_days = retention_days
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.log = logging.getLogger("smu.web.system_metrics")
        self.latest: dict | None = None
        self.last_error: str | None = None
        psutil.cpu_percent(interval=None)
        if autostart:
            threading.Thread(target=self._loop, daemon=True, name="smu-system-metrics").start()

    def _sample(self) -> dict:
        memory = psutil.virtual_memory()
        return {
            "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
            "cpuPercent": round(float(psutil.cpu_percent(interval=None)), 1),
            "memoryPercent": round(float(memory.percent), 1),
            "memoryUsedBytes": int(memory.used),
            "memoryAvailableBytes": int(memory.available),
            "memoryTotalBytes": int(memory.total),
        }

    def collect(self) -> dict:
        sample = self._sample()
        moment = datetime.fromisoformat(sample["timestamp"])
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / f"{moment.date().isoformat()}.jsonl"
        with self.lock:
            with path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(sample, ensure_ascii=False, separators=(",", ":")) + "\n")
            self.latest = sample
            self.last_error = None
        return sample

    def _cleanup(self) -> None:
        cutoff = datetime.now().date() - timedelta(days=self.retention_days)
        for path in self.directory.glob("*.jsonl"):
            try:
                if datetime.strptime(path.stem, "%Y-%m-%d").date() < cutoff:
                    path.unlink()
            except (ValueError, OSError):
                self.log.warning("Unable to inspect system metrics file: %s", path, exc_info=True)

    def _loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                sample = self.collect()
                if sample["timestamp"][:10] != getattr(self, "_cleanup_date", None):
                    self._cleanup()
                    self._cleanup_date = sample["timestamp"][:10]
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {exc}"
                self.log.exception("System metrics collection failed")
            self.stop_event.wait(self.interval_seconds)

    def current(self) -> dict:
        with self.lock:
            sample = dict(self.latest) if self.latest else None
        return {
            "collector": {
                "running": not self.stop_event.is_set(),
                "intervalSeconds": self.interval_seconds,
                "retentionDays": self.retention_days,
                "lastError": self.last_error,
            },
            "sample": sample,
        }

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
        with self.lock:
            while day <= end_at.date():
                path = self.directory / f"{day.isoformat()}.jsonl"
                if path.exists():
                    for line in path.read_text(encoding="utf-8").splitlines():
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
