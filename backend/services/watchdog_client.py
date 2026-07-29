import json
import logging
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path


class WatchdogManager:
    def __init__(self, root: Path, port: int = 8766):
        self.root = root
        self.url = f"http://127.0.0.1:{port}"
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.log = logging.getLogger("smu.web.watchdog_manager")

    def request(self, path: str, method: str = "GET", timeout: float = 2) -> dict:
        request = urllib.request.Request(self.url + path, method=method)
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())

    def status(self) -> dict:
        try:
            return self.request("/status")
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            return {"watchdog": {"status": "missing"}, "collector": {"status": "unknown"}}

    def _spawn(self) -> None:
        log_path = self.root / "runtime/logs/hardware_watchdog_process.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        stream = log_path.open("a", encoding="utf-8")
        flags = 0
        if os.name == "nt":
            flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
        process = subprocess.Popen([sys.executable, "-m", "system_monitor.watchdog", "--root", str(self.root)], cwd=self.root, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT, creationflags=flags, close_fds=True, start_new_session=os.name != "nt")
        self.log.warning("Watchdog process launched pid=%s", process.pid)

    def ensure(self) -> bool:
        if self.status()["watchdog"].get("status") == "running":
            return True
        with self.lock:
            if self.status()["watchdog"].get("status") == "running":
                return True
            self._spawn()
            for _ in range(20):
                time.sleep(0.25)
                if self.status()["watchdog"].get("status") == "running":
                    return True
        return False

    def restart_collector(self) -> dict:
        self.ensure()
        return self.request("/collector/restart", "POST", timeout=10)

    def restart_watchdog(self) -> dict:
        with self.lock:
            try:
                self.request("/shutdown", "POST")
            except OSError:
                pass
            for _ in range(20):
                time.sleep(0.25)
                if self.status()["watchdog"].get("status") != "running":
                    break
            self._spawn()
            for _ in range(40):
                time.sleep(0.25)
                status = self.status()
                if status["watchdog"].get("status") == "running":
                    return {"accepted": True, "status": status}
        raise RuntimeError("Watchdog did not restart")

    def loop(self) -> None:
        while not self.stop.is_set():
            try:
                self.ensure()
            except Exception:
                self.log.exception("Watchdog health check failed")
            self.stop.wait(10)

    def start(self) -> None:
        threading.Thread(target=self.loop, daemon=True, name="smu-watchdog-manager").start()
