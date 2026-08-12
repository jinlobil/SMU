import json
import logging
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlencode
from datetime import date
from pathlib import Path
from system_monitor.logging_utils import dated_process_log


class WatchdogManager:
    def __init__(self, root: Path, port: int = 8766):
        self.root = root
        self.url = f"http://127.0.0.1:{port}"
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.job_states: dict[str, str] = {}
        self.log = logging.getLogger("smu.web.watchdog_manager")
        self.job_events = logging.getLogger("smu.job.events")

    def _report_job_state(self, job: dict | None, kind: str) -> dict | None:
        if not job or not job.get("id"):
            return job
        job_id, status = str(job["id"]), str(job.get("status", "unknown"))
        if self.job_states.get(job_id) == status:
            return job
        self.job_states[job_id] = status
        if status == "failed":
            self.job_events.warning("%s job failed job_id=%s", kind, job_id)
        elif status in {"queued", "running", "completed"}:
            self.job_events.info("%s job %s job_id=%s", kind, status, job_id)
        return job

    def request(self, path: str, method: str = "GET", timeout: float = 2) -> dict:
        request = urllib.request.Request(self.url + path, method=method)
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())

    def status(self) -> dict:
        try:
            return self.request("/status")
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            return {"watchdog": {"status": "missing"}, "collector": {"status": "unknown"}, "fetcher": {"status": "unknown"}, "indexer": {"status": "unknown"}, "laborer": {"status": "unknown"}}

    def _spawn(self) -> None:
        log_path = dated_process_log(self.root / "runtime/logs", "hardware_watchdog_process")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        stream = log_path.open("a", encoding="utf-8")
        flags = 0
        if os.name == "nt":
            flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
        process = subprocess.Popen([sys.executable, "-m", "system_monitor.watchdog", "--root", str(self.root)], cwd=self.root, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT, creationflags=flags, close_fds=True, start_new_session=os.name != "nt")
        self.log.warning("Watchdog process launched pid=%s", process.pid)

    def ensure(self) -> bool:
        current = self.status()
        if current["watchdog"].get("status") == "running" and "indexer" in current and "fetcher" in current and "laborer" in current:
            return True
        with self.lock:
            current = self.status()
            if current["watchdog"].get("status") == "running" and ("indexer" not in current or "fetcher" not in current or "laborer" not in current):
                # Replace a detached watchdog left by a previous application
                # version so the current Fetcher/Indexer control API is available.
                try:
                    self.request("/shutdown", "POST")
                except OSError:
                    pass
                for _ in range(20):
                    time.sleep(0.25)
                    if self.status()["watchdog"].get("status") != "running":
                        break
            elif current["watchdog"].get("status") == "running":
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

    def restart_indexer(self) -> dict:
        self.ensure()
        return self.request("/indexer/restart", "POST", timeout=20)

    def restart_fetcher(self) -> dict:
        self.ensure()
        return self.request("/fetcher/restart", "POST", timeout=20)

    def restart_laborer(self) -> dict:
        self.ensure()
        return self.request("/laborer/restart", "POST", timeout=20)

    def start_fetch_job(self, targets: list[str], start: date | None = None, end: date | None = None, chain_index: bool = False) -> dict:
        self.ensure()
        query = f"targets={','.join(targets)}"
        if start is not None and end is not None: query += f"&start={start.isoformat()}&end={end.isoformat()}"
        if chain_index: query += "&chain_index=1"
        return self._report_job_state(self.request(f"/fetcher/jobs?{query}", "POST", timeout=20), "Fetcher")

    def fetch_job(self, job_id: str) -> dict | None:
        try: return self._report_job_state(self.request(f"/fetcher/jobs/{job_id}", timeout=10), "Fetcher")
        except urllib.error.HTTPError as exc:
            if exc.code == 404: return None
            raise

    def wait_for_fetch_job(self, job: dict, progress, wait_for_index: bool = False) -> dict:
        while not self.stop.is_set():
            current = self.fetch_job(job["id"])
            if current is None: raise RuntimeError(f"Fetcher job disappeared: {job['id']}")
            progress(current.get("message", "수집 중"))
            if current.get("status") == "completed":
                result = current.get("result") or {}
                if wait_for_index and result.get("indexJob"):
                    result["index"] = self._wait_for_index_job(result["indexJob"], progress)
                return result
            if current.get("status") == "failed": raise RuntimeError((current.get("error") or {}).get("message", "Fetcher job failed"))
            time.sleep(0.8)
        raise RuntimeError("Fetcher wait interrupted")

    def start_index_job(self, start: date | None = None, end: date | None = None, force_full: bool = False, scope: str | None = None) -> dict:
        self.ensure()
        path = "/indexer/jobs"
        if start is not None and end is not None:
            path += f"?start={start.isoformat()}&end={end.isoformat()}"
        elif force_full:
            path += "?force=1"
        if scope:
            path += ("&" if "?" in path else "?") + f"scope={scope}"
        try:
            return self._report_job_state(self.request(path, "POST", timeout=20), "Indexer")
        except urllib.error.HTTPError as exc:
            # A watchdog from an older application version may still own the
            # fixed port after an update. Replace it once, then retry.
            if exc.code != 404:
                raise
            self.restart_watchdog()
            return self._report_job_state(self.request(path, "POST", timeout=20), "Indexer")

    def index_job(self, job_id: str) -> dict | None:
        try:
            return self._report_job_state(self.request(f"/indexer/jobs/{job_id}", timeout=10), "Indexer")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise


    def start_laborer_job(self, job_type: str, **payload) -> dict:
        self.ensure()
        # Keep structured values (selected export columns/report sections) intact
        # while the request is proxied through the watchdog and on to Laborer.
        job_payload = {key: value for key, value in payload.items() if value is not None}
        query = urlencode({"type": job_type, **job_payload}, doseq=True)
        return self._report_job_state(self.request(f"/laborer/jobs?{query}", "POST", timeout=20), "Laborer")

    def laborer_job(self, job_id: str) -> dict | None:
        try:
            return self._report_job_state(self.request(f"/laborer/jobs/{job_id}", timeout=10), "Laborer")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise

    def rebuild_all(self, progress) -> dict:
        """Scheduler-compatible blocking facade over the independent Indexer."""
        return self._wait_for_index_job(self.start_index_job(force_full=True), progress)

    def rebuild_smart(self, progress) -> dict:
        return self._wait_for_index_job(self.start_index_job(), progress)

    def rebuild_range(self, start: date, end: date, progress) -> dict:
        return self._wait_for_index_job(self.start_index_job(start, end), progress)

    def _wait_for_index_job(self, job: dict, progress) -> dict:
        while not self.stop.is_set():
            current = self.index_job(job["id"])
            if current is None: raise RuntimeError(f"Indexer job disappeared: {job['id']}")
            progress(current.get("message", "인덱싱 중"))
            if current.get("status") == "completed": return current.get("result") or {}
            if current.get("status") == "failed": raise RuntimeError((current.get("error") or {}).get("message", "Indexer job failed"))
            time.sleep(0.8)
        raise RuntimeError("Indexer wait interrupted")

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
