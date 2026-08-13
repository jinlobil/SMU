import argparse
import json
import logging
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import psutil

from system_monitor.collector import atomic_json
from system_monitor.logging_utils import configure_agent_logging, dated_process_log


def process_alive(pid: int | None) -> bool:
    if not pid:
        return False
    return psutil.pid_exists(int(pid))


def terminate_process(pid: int) -> None:
    try:
        process = psutil.Process(int(pid))
        process.terminate()
        try:
            process.wait(timeout=3)
        except psutil.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
        return


def detached_flags() -> int:
    if os.name != "nt":
        return 0
    return subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW


class HardwareWatchdog:
    def __init__(self, root: Path):
        self.root = root
        self.directory = root / "runtime/system_metrics"
        self.collector_status = self.directory / "collector_status.json"
        self.status_path = self.directory / "watchdog_status.json"
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.collector: subprocess.Popen | None = None
        self.indexer: subprocess.Popen | None = None
        self.fetcher: subprocess.Popen | None = None
        self.laborer: subprocess.Popen | None = None
        self.learner: subprocess.Popen | None = None
        self.restart_count = 0
        self.indexer_restart_count = 0
        self.fetcher_restart_count = 0
        self.laborer_restart_count = 0
        self.learner_restart_count = 0
        self.started_at = datetime.now().astimezone().isoformat(timespec="seconds")
        self.log = logging.getLogger("smu.hardware.watchdog")

    def read_collector(self) -> dict:
        try:
            return json.loads(self.collector_status.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"status": "missing", "pid": None, "lastSampleAt": None, "lastError": None}

    def _start_collector(self) -> None:
        log_path = dated_process_log(self.root / "runtime/logs", "hardware_collector_process")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        stream = log_path.open("a", encoding="utf-8")
        self.collector = subprocess.Popen([sys.executable, "-m", "system_monitor.collector", "--root", str(self.root)], cwd=self.root, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT, creationflags=detached_flags(), close_fds=True, start_new_session=os.name != "nt")
        self.log.info("Collector started pid=%s", self.collector.pid)

    def _wait_for_collector(self, pid: int, timeout: float = 10) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.read_collector()
            if status.get("status") == "running" and process_alive(status.get("pid")):
                return status
            time.sleep(0.2)
        raise RuntimeError(f"Collector pid={pid} did not publish a healthy heartbeat")

    def restart_collector(self) -> dict:
        with self.lock:
            status = self.read_collector()
            pid = status.get("pid")
            if pid:
                terminate_process(int(pid))
            self._start_collector()
            self.restart_count += 1
            status = self._wait_for_collector(self.collector.pid)
            return {"accepted": True, "pid": self.collector.pid, "status": status}

    def _indexer_request(self, path: str, method: str = "GET", timeout: float = 3) -> dict:
        request = urllib.request.Request("http://127.0.0.1:8767" + path, method=method)
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())

    def read_indexer(self) -> dict:
        try:
            status = self._indexer_request("/health")
            heartbeat = datetime.fromisoformat(status.get("lastHeartbeatAt") or "")
            if (datetime.now().astimezone() - heartbeat.astimezone()).total_seconds() <= 10:
                return status
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError):
            pass
        return {"status": "missing", "pid": None, "startedAt": None, "lastHeartbeatAt": None, "currentJobId": None, "lastError": None}

    def _start_indexer(self) -> None:
        log_path = dated_process_log(self.root / "runtime/logs", "indexer_process")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        stream = log_path.open("a", encoding="utf-8")
        self.indexer = subprocess.Popen([sys.executable, "-m", "system_monitor.indexer", "--root", str(self.root)], cwd=self.root, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT, creationflags=detached_flags(), close_fds=True, start_new_session=os.name != "nt")
        self.log.info("Indexer started pid=%s", self.indexer.pid)

    def _fetcher_request(self, path: str, method: str = "GET", timeout: float = 3) -> dict:
        request = urllib.request.Request("http://127.0.0.1:8768" + path, method=method)
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())

    def _laborer_request(self, path: str, method: str = "GET", timeout: float = 3) -> dict:
        request = urllib.request.Request("http://127.0.0.1:8769" + path, method=method)
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())

    def _learner_request(self, path: str, method: str = "GET", timeout: float = 3) -> dict:
        request = urllib.request.Request("http://127.0.0.1:8770" + path, method=method)
        with urllib.request.urlopen(request, timeout=timeout) as response: return json.loads(response.read())

    def read_learner(self) -> dict:
        try:
            status=self._learner_request("/health");heartbeat=datetime.fromisoformat(status.get("lastHeartbeatAt") or "")
            if (datetime.now().astimezone()-heartbeat.astimezone()).total_seconds()<=10:return status
        except (OSError,ValueError,json.JSONDecodeError,urllib.error.URLError): pass
        return {"status":"missing","pid":None,"startedAt":None,"lastHeartbeatAt":None,"currentJobId":None,"lastError":None}

    def start_learner(self) -> None:
        log_path=dated_process_log(self.root/"runtime/logs","learner_process");log_path.parent.mkdir(parents=True,exist_ok=True);stream=log_path.open("a",encoding="utf-8")
        self.learner=subprocess.Popen([sys.executable,"-m","system_monitor.learner","--root",str(self.root)],cwd=self.root,stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,creationflags=detached_flags(),close_fds=True,start_new_session=os.name!="nt")

    def ensure_learner(self) -> dict:
        status=self.read_learner()
        return status if status.get("status")=="running" else self.restart_learner()["status"]

    def restart_learner(self) -> dict:
        with self.lock:
            status=self.read_learner()
            if status.get("pid"):terminate_process(int(status["pid"]))
            self.start_learner();self.learner_restart_count+=1;deadline=time.monotonic()+15
            while time.monotonic()<deadline:
                status=self.read_learner()
                if status.get("status")=="running":return {"accepted":True,"pid":status.get("pid"),"status":status}
                time.sleep(.25)
        raise RuntimeError("Learner did not publish a healthy heartbeat")

    def submit_learner_job(self, query: str) -> dict:
        self.ensure_learner();return self._learner_request("/jobs"+(f"?{query}" if query else ""),"POST",10)

    def learner_job(self, job_id: str) -> dict:
        self.ensure_learner();return self._learner_request(f"/jobs/{job_id}",timeout=5)

    def cancel_learner_job(self, job_id: str) -> dict:
        self.ensure_learner();return self._learner_request(f"/jobs/{job_id}/cancel","POST",timeout=5)

    def read_laborer(self) -> dict:
        try:
            status = self._laborer_request("/health")
            heartbeat = datetime.fromisoformat(status.get("lastHeartbeatAt") or "")
            if (datetime.now().astimezone() - heartbeat.astimezone()).total_seconds() <= 10:
                return status
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError):
            pass
        return {"status": "missing", "pid": None, "startedAt": None, "lastHeartbeatAt": None, "currentJobId": None, "lastError": None}

    def _start_laborer(self) -> None:
        log_path = dated_process_log(self.root / "runtime/logs", "laborer_process")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        stream = log_path.open("a", encoding="utf-8")
        self.laborer = subprocess.Popen([sys.executable, "-m", "system_monitor.laborer", "--root", str(self.root)], cwd=self.root, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT, creationflags=detached_flags(), close_fds=True, start_new_session=os.name != "nt")
        self.log.info("Laborer started pid=%s", self.laborer.pid)

    def ensure_laborer(self) -> dict:
        status = self.read_laborer()
        if status.get("status") == "running": return status
        self.log.warning("Laborer health check failed; restarting before command")
        return self.restart_laborer()["status"]

    def restart_laborer(self) -> dict:
        with self.lock:
            status = self.read_laborer()
            if status.get("pid"): terminate_process(int(status["pid"]))
            self._start_laborer(); self.laborer_restart_count += 1
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                status = self.read_laborer()
                if status.get("status") == "running": return {"accepted": True, "pid": status.get("pid"), "status": status}
                time.sleep(0.25)
        raise RuntimeError("Laborer did not publish a healthy heartbeat")

    def submit_laborer_job(self, query: str) -> dict:
        self.ensure_laborer()
        return self._laborer_request("/jobs" + (f"?{query}" if query else ""), "POST", timeout=10)

    def laborer_job(self, job_id: str) -> dict:
        self.ensure_laborer()
        return self._laborer_request(f"/jobs/{job_id}", timeout=5)

    def read_fetcher(self) -> dict:
        try:
            status = self._fetcher_request("/health")
            heartbeat = datetime.fromisoformat(status.get("lastHeartbeatAt") or "")
            if (datetime.now().astimezone() - heartbeat.astimezone()).total_seconds() <= 10:
                return status
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError):
            pass
        return {"status": "missing", "pid": None, "startedAt": None, "lastHeartbeatAt": None, "currentJobId": None, "lastError": None}

    def _start_fetcher(self) -> None:
        log_path = dated_process_log(self.root / "runtime/logs", "fetcher_process")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        stream = log_path.open("a", encoding="utf-8")
        self.fetcher = subprocess.Popen([sys.executable, "-m", "system_monitor.fetcher", "--root", str(self.root)], cwd=self.root, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT, creationflags=detached_flags(), close_fds=True, start_new_session=os.name != "nt")
        self.log.info("Fetcher started pid=%s", self.fetcher.pid)

    def ensure_fetcher(self) -> dict:
        status = self.read_fetcher()
        if status.get("status") == "running": return status
        self.log.warning("Fetcher health check failed; restarting before command")
        return self.restart_fetcher()["status"]

    def restart_fetcher(self) -> dict:
        with self.lock:
            status = self.read_fetcher()
            if status.get("pid"): terminate_process(int(status["pid"]))
            self._start_fetcher(); self.fetcher_restart_count += 1
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                status = self.read_fetcher()
                if status.get("status") == "running": return {"accepted": True, "pid": status.get("pid"), "status": status}
                time.sleep(0.25)
        raise RuntimeError("Fetcher did not publish a healthy heartbeat")

    def submit_fetch_job(self, query: str) -> dict:
        self.ensure_fetcher()
        return self._fetcher_request("/jobs" + (f"?{query}" if query else ""), "POST", timeout=10)

    def fetch_job(self, job_id: str) -> dict:
        self.ensure_fetcher()
        return self._fetcher_request(f"/jobs/{job_id}", timeout=5)

    def ensure_indexer(self) -> dict:
        """Probe the Indexer before every command and recover it when unavailable."""
        status = self.read_indexer()
        if status.get("status") == "running":
            return status
        self.log.warning("Indexer health check failed; restarting before command")
        return self.restart_indexer()["status"]

    def restart_indexer(self) -> dict:
        with self.lock:
            status = self.read_indexer()
            if status.get("pid"):
                terminate_process(int(status["pid"]))
            self._start_indexer()
            self.indexer_restart_count += 1
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                status = self.read_indexer()
                if status.get("status") == "running":
                    return {"accepted": True, "pid": status.get("pid"), "status": status}
                time.sleep(0.25)
        raise RuntimeError("Indexer did not publish a healthy heartbeat")

    def submit_index_job(self, query: str = "") -> dict:
        path = "/jobs" + (f"?{query}" if query else "")
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                self.ensure_indexer()
                return self._indexer_request(path, "POST", timeout=10)
            except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
                last_error = exc
                self.log.warning("Indexer submission failed attempt=%s path=%s error=%s", attempt + 1, path, exc)
                if attempt < 2:
                    time.sleep(0.5 * (attempt + 1))
        raise RuntimeError(f"Indexer command failed after health check: {last_error}")

    def index_job(self, job_id: str) -> dict:
        self.ensure_indexer()
        return self._indexer_request(f"/jobs/{job_id}", timeout=5)

    def ensure_collector(self) -> None:
        status = self.read_collector()
        pid = status.get("pid")
        alive = process_alive(pid)
        stale = True
        try:
            sampled = datetime.fromisoformat(status.get("lastSampleAt") or "")
            stale = (datetime.now().astimezone() - sampled.astimezone()).total_seconds() > 20
        except ValueError:
            pass
        # A fresh heartbeat is stronger evidence than a Windows PID probe. Some
        # restricted sessions cannot open another process to verify its PID,
        # which previously caused a healthy Collector to restart every 5s.
        if stale:
            self.log.warning("Collector heartbeat stale pid=%s process_alive=%s; restarting", pid, alive)
            self.restart_collector()

    def snapshot(self) -> dict:
        collector = {**self.read_collector(), "restartCount": self.restart_count}
        indexer = {**self.read_indexer(), "restartCount": self.indexer_restart_count}
        fetcher = {**self.read_fetcher(), "restartCount": self.fetcher_restart_count}
        laborer = {**self.read_laborer(), "restartCount": self.laborer_restart_count}
        learner = {**self.read_learner(), "restartCount": self.learner_restart_count}
        return {"watchdog": {"status": "running", "pid": os.getpid(), "startedAt": self.started_at, "lastCheckAt": datetime.now().astimezone().isoformat(timespec="seconds"), "lastError": None}, "collector": collector, "fetcher": fetcher, "indexer": indexer, "laborer": laborer, "learner": learner}

    def loop(self) -> None:
        while not self.stop.is_set():
            for name, ensure in (("collector",self.ensure_collector),("fetcher",self.ensure_fetcher),("indexer",self.ensure_indexer),("laborer",self.ensure_laborer),("learner",self.ensure_learner)):
                try:
                    ensure()
                except Exception:
                    # One unavailable worker must never prevent health checks or
                    # recovery of the remaining workers.
                    self.log.exception("Watchdog %s health check failed", name)
            try:
                atomic_json(self.status_path, self.snapshot())
            except Exception:
                self.log.exception("Watchdog status write failed")
            self.stop.wait(5)


def signal_value() -> int:
    import signal
    return signal.SIGTERM


def handler_for(watchdog: HardwareWatchdog):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, payload: dict):
            body = json.dumps(payload).encode()
            self.send_response(status); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        def do_GET(self):
            if self.path in {"/health", "/status"}: self._send(200, watchdog.snapshot())
            elif self.path.startswith("/indexer/jobs/"):
                try: self._send(200, watchdog.index_job(self.path.removeprefix("/indexer/jobs/")))
                except urllib.error.HTTPError as exc: self._send(exc.code, {"error": "job not found"})
                except Exception as exc: self._send(503, {"error": f"{type(exc).__name__}: {exc}"})
            elif self.path.startswith("/fetcher/jobs/"):
                try: self._send(200, watchdog.fetch_job(self.path.removeprefix("/fetcher/jobs/")))
                except urllib.error.HTTPError as exc: self._send(exc.code, {"error": "job not found"})
                except Exception as exc: self._send(503, {"error": f"{type(exc).__name__}: {exc}"})
            elif self.path.startswith("/learner/jobs/"):
                try: self._send(200, watchdog.learner_job(self.path.removeprefix("/learner/jobs/")))
                except urllib.error.HTTPError as exc: self._send(exc.code, {"error":"job not found"})
                except Exception as exc: self._send(503,{"error":f"{type(exc).__name__}: {exc}"})
            elif self.path.startswith("/laborer/jobs/"):
                try: self._send(200, watchdog.laborer_job(self.path.removeprefix("/laborer/jobs/")))
                except urllib.error.HTTPError as exc: self._send(exc.code, {"error": "job not found"})
                except Exception as exc: self._send(503, {"error": f"{type(exc).__name__}: {exc}"})
            else: self._send(404, {"error": "not found"})
        def do_POST(self):
            if self.path == "/collector/restart":
                try: self._send(202, watchdog.restart_collector())
                except Exception as exc: self._send(503, {"accepted": False, "error": f"{type(exc).__name__}: {exc}"})
            elif self.path == "/indexer/restart":
                try: self._send(202, watchdog.restart_indexer())
                except Exception as exc: self._send(503, {"accepted": False, "error": f"{type(exc).__name__}: {exc}"})
            elif self.path == "/fetcher/restart":
                try: self._send(202, watchdog.restart_fetcher())
                except Exception as exc: self._send(503, {"accepted": False, "error": f"{type(exc).__name__}: {exc}"})
            elif self.path == "/learner/restart":
                try: self._send(202,watchdog.restart_learner())
                except Exception as exc: self._send(503,{"accepted":False,"error":f"{type(exc).__name__}: {exc}"})
            elif self.path == "/laborer/restart":
                try: self._send(202, watchdog.restart_laborer())
                except Exception as exc: self._send(503, {"accepted": False, "error": f"{type(exc).__name__}: {exc}"})
            elif self.path.startswith("/fetcher/completed"):
                try:
                    job_id = (dict(item.split("=", 1) for item in urlparse(self.path).query.split("&") if "=" in item).get("job_id"))
                    self._send(202, watchdog.submit_index_job(f"source_fetch_job={job_id or ''}"))
                except Exception as exc: self._send(503, {"accepted": False, "error": f"{type(exc).__name__}: {exc}"})
            elif self.path.startswith("/fetcher/jobs"):
                try: self._send(202, watchdog.submit_fetch_job(urlparse(self.path).query))
                except Exception as exc: self._send(503, {"accepted": False, "error": f"{type(exc).__name__}: {exc}"})
            elif self.path.startswith("/indexer/jobs"):
                try: self._send(202, watchdog.submit_index_job(urlparse(self.path).query))
                except Exception as exc: self._send(503, {"accepted": False, "error": f"{type(exc).__name__}: {exc}"})
            elif self.path.startswith("/learner/jobs/") and self.path.endswith("/cancel"):
                job_id=urlparse(self.path).path.removeprefix("/learner/jobs/").removesuffix("/cancel")
                try: self._send(202,watchdog.cancel_learner_job(job_id))
                except urllib.error.HTTPError as exc:
                    try: payload=json.loads(exc.read())
                    except Exception: payload={"error":str(exc)}
                    self._send(exc.code,payload)
                except Exception as exc:self._send(503,{"accepted":False,"error":f"{type(exc).__name__}: {exc}"})
            elif self.path.startswith("/learner/jobs"):
                try: self._send(202,watchdog.submit_learner_job(urlparse(self.path).query))
                except urllib.error.HTTPError as exc:
                    try: payload=json.loads(exc.read())
                    except Exception: payload={"error":str(exc)}
                    self._send(exc.code,payload)
                except Exception as exc: self._send(503,{"accepted":False,"error":f"{type(exc).__name__}: {exc}"})
            elif self.path.startswith("/laborer/jobs"):
                try: self._send(202, watchdog.submit_laborer_job(urlparse(self.path).query))
                except Exception as exc: self._send(503, {"accepted": False, "error": f"{type(exc).__name__}: {exc}"})
            elif self.path == "/shutdown": self._send(202, {"accepted": True}); threading.Thread(target=watchdog.stop.set, daemon=True).start()
            else: self._send(404, {"error": "not found"})
        def log_message(self, *_): pass
    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--root", type=Path, required=True); args = parser.parse_args()
    (args.root / "runtime/logs").mkdir(parents=True, exist_ok=True)
    configure_agent_logging(args.root / "runtime/logs/hardware_watchdog.log", retention_days=60)
    watchdog = HardwareWatchdog(args.root)
    server = ThreadingHTTPServer(("127.0.0.1", 8766), handler_for(watchdog)); server.timeout = 1
    threading.Thread(target=watchdog.loop, daemon=True).start()
    while not watchdog.stop.is_set(): server.handle_request()
    server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
