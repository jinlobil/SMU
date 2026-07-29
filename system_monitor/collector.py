import argparse
import json
import logging
import os
import signal
import threading
from datetime import datetime, timedelta
from pathlib import Path

import psutil


def acquire_singleton(path: Path):
    """Hold an OS file lock for the Collector lifetime to prevent duplicate writers."""
    path.parent.mkdir(parents=True, exist_ok=True)
    stream = path.open("a+b")
    stream.seek(0)
    if stream.tell() == 0 and path.stat().st_size == 0:
        stream.write(b"0")
        stream.flush()
    stream.seek(0)
    try:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        stream.close()
        return None
    return stream


def atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, path)


class HardwareCollector:
    def __init__(self, root: Path, interval: int = 5, retention_days: int = 30):
        self.directory = root / "runtime/system_metrics"
        self.status_path = self.directory / "collector_status.json"
        self.interval = interval
        self.retention_days = retention_days
        self.stop = threading.Event()
        self.started_at = datetime.now().astimezone().isoformat(timespec="seconds")
        self.instance_id = f"{os.getpid()}-{datetime.now().timestamp()}"
        self.sample_count = 0
        self.log = logging.getLogger("smu.hardware.collector")

    def _sample(self) -> dict:
        memory = psutil.virtual_memory()
        return {"timestamp": datetime.now().astimezone().isoformat(timespec="seconds"), "cpuPercent": round(float(psutil.cpu_percent(interval=None)), 1), "memoryPercent": round(float(memory.percent), 1), "memoryUsedBytes": int(memory.used), "memoryAvailableBytes": int(memory.available), "memoryTotalBytes": int(memory.total)}

    def _status(self, status: str, sample: dict | None = None, error: str | None = None) -> None:
        atomic_json(self.status_path, {"status": status, "pid": os.getpid(), "instanceId": self.instance_id, "startedAt": self.started_at, "lastSampleAt": sample.get("timestamp") if sample else None, "intervalSeconds": self.interval, "sampleCount": self.sample_count, "lastError": error, "sample": sample})

    def _cleanup(self) -> None:
        cutoff = datetime.now().date() - timedelta(days=self.retention_days)
        for path in self.directory.glob("*.jsonl"):
            try:
                if datetime.strptime(path.stem, "%Y-%m-%d").date() < cutoff:
                    path.unlink()
            except (ValueError, OSError):
                self.log.warning("Unable to clean metrics file %s", path, exc_info=True)

    def run(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        psutil.cpu_percent(interval=None)
        self._status("starting")
        cleanup_date = None
        while not self.stop.is_set():
            try:
                sample = self._sample()
                with (self.directory / f"{sample['timestamp'][:10]}.jsonl").open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(sample, ensure_ascii=False, separators=(",", ":")) + "\n")
                    stream.flush()
                self.sample_count += 1
                self._status("running", sample)
                if cleanup_date != sample["timestamp"][:10]:
                    self._cleanup()
                    cleanup_date = sample["timestamp"][:10]
            except Exception as exc:
                self.log.exception("Hardware collection failed")
                self._status("error", error=f"{type(exc).__name__}: {exc}")
            self.stop.wait(self.interval)
        self._status("stopped")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    (args.root / "runtime/logs").mkdir(parents=True, exist_ok=True)
    logging.basicConfig(filename=args.root / "runtime/logs/hardware_collector.log", level=logging.INFO, encoding="utf-8")
    singleton = acquire_singleton(args.root / "runtime/system_metrics/collector.lock")
    if singleton is None:
        logging.info("Collector already running; duplicate process exiting")
        return 0
    collector = HardwareCollector(args.root)
    signal.signal(signal.SIGTERM, lambda *_: collector.stop.set())
    signal.signal(signal.SIGINT, lambda *_: collector.stop.set())
    collector.run()
    singleton.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
