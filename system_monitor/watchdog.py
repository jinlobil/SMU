import argparse
import json
import logging
import os
import subprocess
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from system_monitor.collector import atomic_json


def process_alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def detached_flags() -> int:
    if os.name != "nt":
        return 0
    return subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW


class HardwareWatchdog:
    def __init__(self, root: Path):
        self.root = root
        self.directory = root / "runtime/system_metrics"
        self.collector_status = self.directory / "collector_status.json"
        self.status_path = self.directory / "watchdog_status.json"
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.collector: subprocess.Popen | None = None
        self.restart_count = 0
        self.started_at = datetime.now().astimezone().isoformat(timespec="seconds")
        self.log = logging.getLogger("smu.hardware.watchdog")

    def read_collector(self) -> dict:
        try:
            return json.loads(self.collector_status.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"status": "missing", "pid": None, "lastSampleAt": None, "lastError": None}

    def _start_collector(self) -> None:
        log_path = self.root / "runtime/logs/hardware_collector_process.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        stream = log_path.open("a", encoding="utf-8")
        self.collector = subprocess.Popen([sys.executable, "-m", "system_monitor.collector", "--root", str(self.root)], cwd=self.root, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT, creationflags=detached_flags(), close_fds=True, start_new_session=os.name != "nt")
        self.log.info("Collector started pid=%s", self.collector.pid)

    def _wait_for_collector(self, pid: int, timeout: float = 10) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.read_collector()
            if status.get("pid") == pid and status.get("status") == "running":
                return status
            time.sleep(0.2)
        raise RuntimeError(f"Collector pid={pid} did not publish a healthy heartbeat")

    def restart_collector(self) -> dict:
        with self.lock:
            status = self.read_collector()
            pid = status.get("pid")
            if process_alive(pid):
                try:
                    os.kill(int(pid), signal_value())
                except OSError:
                    pass
                for _ in range(30):
                    if not process_alive(pid):
                        break
                    time.sleep(0.1)
            self._start_collector()
            self.restart_count += 1
            status = self._wait_for_collector(self.collector.pid)
            return {"accepted": True, "pid": self.collector.pid, "status": status}

    def ensure_collector(self) -> None:
        status = self.read_collector()
        pid = status.get("pid")
        stale = True
        try:
            sampled = datetime.fromisoformat(status.get("lastSampleAt") or "")
            stale = (datetime.now().astimezone() - sampled.astimezone()).total_seconds() > 20
        except ValueError:
            pass
        if not process_alive(pid) or stale:
            self.log.warning("Collector unavailable pid=%s stale=%s; restarting", pid, stale)
            self.restart_collector()

    def snapshot(self) -> dict:
        collector = self.read_collector()
        return {"watchdog": {"status": "running", "pid": os.getpid(), "startedAt": self.started_at, "lastCheckAt": datetime.now().astimezone().isoformat(timespec="seconds"), "restartCount": self.restart_count, "lastError": None}, "collector": collector}

    def loop(self) -> None:
        while not self.stop.wait(5):
            try:
                self.ensure_collector()
                atomic_json(self.status_path, self.snapshot())
            except Exception:
                self.log.exception("Watchdog check failed")


def signal_value() -> int:
    import signal
    return signal.SIGTERM


def handler_for(watchdog: HardwareWatchdog):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, payload: dict):
            body = json.dumps(payload).encode()
            self.send_response(status); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        def do_GET(self):
            self._send(200, watchdog.snapshot()) if self.path in {"/health", "/status"} else self._send(404, {"error": "not found"})
        def do_POST(self):
            if self.path == "/collector/restart": self._send(202, watchdog.restart_collector())
            elif self.path == "/shutdown": self._send(202, {"accepted": True}); threading.Thread(target=watchdog.stop.set, daemon=True).start()
            else: self._send(404, {"error": "not found"})
        def log_message(self, *_): pass
    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--root", type=Path, required=True); args = parser.parse_args()
    (args.root / "runtime/logs").mkdir(parents=True, exist_ok=True)
    logging.basicConfig(filename=args.root / "runtime/logs/hardware_watchdog.log", level=logging.INFO, encoding="utf-8")
    watchdog = HardwareWatchdog(args.root)
    watchdog.ensure_collector()
    server = ThreadingHTTPServer(("127.0.0.1", 8766), handler_for(watchdog)); server.timeout = 1
    threading.Thread(target=watchdog.loop, daemon=True).start()
    while not watchdog.stop.is_set(): server.handle_request()
    server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
