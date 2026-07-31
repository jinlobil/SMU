import argparse
import json
import logging
import os
import signal
import sqlite3
import threading
import time
import traceback
import urllib.error
import urllib.request
import uuid
from datetime import date, datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from backend.services.refresh import RefreshService
from system_monitor.collector import acquire_singleton, atomic_json


TARGETS = {"detections", "inbound", "dlp", "outbound", "endpoints", "organizations", "users"}


class FetcherAgent:
    """Persistent collection worker used by both Cache Data and the scheduler."""

    def __init__(self, root: Path, watchdog_url: str = "http://127.0.0.1:8766"):
        self.root = root
        self.directory = root / "runtime/fetcher"
        self.database = self.directory / "jobs.db"
        self.status_path = self.directory / "fetcher_status.json"
        self.watchdog_url = watchdog_url
        self.stop = threading.Event()
        self.wake = threading.Event()
        self.job_lock = threading.Lock()
        self.current_job_id: str | None = None
        self.started_at = datetime.now().astimezone().isoformat(timespec="seconds")
        self.log = logging.getLogger("smu.fetcher.agent")
        self.directory.mkdir(parents=True, exist_ok=True)
        self._initialize_database()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def _initialize_database(self) -> None:
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, status TEXT NOT NULL, message TEXT NOT NULL, targets TEXT NOT NULL, range_start TEXT, range_end TEXT, chain_index INTEGER NOT NULL, result TEXT, error TEXT, created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT)")
            db.execute("UPDATE jobs SET status='queued', message='Fetcher 재시작 후 수집 작업 복구 중', started_at=NULL WHERE status='running'")

    def submit(self, targets: list[str], range_start: str | None, range_end: str | None, chain_index: bool = False) -> dict:
        selected = list(dict.fromkeys(target for target in targets if target in TARGETS))
        if not selected:
            raise ValueError("수집 대상이 없습니다")
        if (range_start is None) != (range_end is None):
            raise ValueError("수집 시작일과 종료일을 모두 지정해야 합니다")
        if range_start and date.fromisoformat(range_start) > date.fromisoformat(range_end or ""):
            raise ValueError("수집 시작일은 종료일보다 늦을 수 없습니다")
        encoded = json.dumps(selected, ensure_ascii=False)
        with self.job_lock, self._connect() as db:
            active = db.execute("SELECT * FROM jobs WHERE status IN ('queued','running') AND targets=? AND COALESCE(range_start,'')=COALESCE(?,'') AND COALESCE(range_end,'')=COALESCE(?,'') AND chain_index=? ORDER BY created_at LIMIT 1", (encoded, range_start, range_end, int(chain_index))).fetchone()
            if active:
                return self._public(active)
            job_id = str(uuid.uuid4())
            db.execute("INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (job_id, "queued", "수집 대기 중", encoded, range_start, range_end, int(chain_index), None, None, self._now(), None, None))
            row = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        self.wake.set()
        return self._public(row)

    def get(self, job_id: str) -> dict | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return self._public(row) if row else None

    @staticmethod
    def _public(row: sqlite3.Row) -> dict:
        return {"id": row["id"], "type": "fetch", "status": row["status"], "message": row["message"], "targets": json.loads(row["targets"]), "result": json.loads(row["result"]) if row["result"] else None, "error": json.loads(row["error"]) if row["error"] else None, "createdAt": row["created_at"], "startedAt": row["started_at"], "finishedAt": row["finished_at"]}

    def _update(self, job_id: str, **fields) -> None:
        json_fields = {"result", "error"}
        with self._connect() as db:
            values = [json.dumps(value, ensure_ascii=False) if key in json_fields and value is not None else value for key, value in fields.items()]
            db.execute(f"UPDATE jobs SET {', '.join(f'{key}=?' for key in fields)} WHERE id=?", (*values, job_id))
        if "message" in fields:
            self.log.info("Fetcher progress job_id=%s %s", job_id, fields["message"])

    def snapshot(self) -> dict:
        return {"status": "running", "pid": os.getpid(), "startedAt": self.started_at, "lastHeartbeatAt": datetime.now().astimezone().isoformat(timespec="seconds"), "currentJobId": self.current_job_id, "lastError": None}

    def heartbeat_loop(self) -> None:
        while not self.stop.is_set():
            atomic_json(self.status_path, self.snapshot())
            self.stop.wait(2)

    def _collect(self, service: RefreshService, target: str, start: date, end: date, progress) -> dict:
        if target == "detections": return service.refresh_detections(start, end, progress)
        if target == "inbound": return service.refresh_inbound(start, end, progress)
        if target == "dlp": return service.refresh_dlp_range(start, end, progress)
        if target == "outbound": return service.refresh_outbound_range(start, end, progress)
        if target == "endpoints": return service.refresh_endpoints(progress)
        if target == "organizations": return service.refresh_organizations(progress)
        return service.refresh_users(progress)

    def _notify_watchdog(self, job_id: str) -> dict:
        last_error = ""
        for attempt in range(3):
            request = urllib.request.Request(f"{self.watchdog_url}/fetcher/completed?job_id={job_id}", method="POST")
            try:
                with urllib.request.urlopen(request, timeout=15) as response:
                    return json.loads(response.read())
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace")
                last_error = f"HTTP {exc.code}: {detail or exc.reason}"
            except (OSError, urllib.error.URLError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
            self.log.warning("Watchdog indexing notification failed attempt=%s job_id=%s error=%s", attempt + 1, job_id, last_error)
            if attempt < 2: time.sleep(0.8 * (attempt + 1))
        raise RuntimeError(f"Watchdog가 인덱싱 요청을 받지 못했습니다: {last_error}")

    def worker_loop(self) -> None:
        while not self.stop.is_set():
            with self._connect() as db:
                row = db.execute("SELECT * FROM jobs WHERE status='queued' ORDER BY created_at LIMIT 1").fetchone()
            if not row:
                self.wake.wait(1); self.wake.clear(); continue
            job_id = row["id"]; targets = json.loads(row["targets"])
            start = date.fromisoformat(row["range_start"]) if row["range_start"] else date.today()
            end = date.fromisoformat(row["range_end"]) if row["range_end"] else date.today()
            self.current_job_id = job_id
            self._update(job_id, status="running", message="수집 작업 시작", started_at=self._now())
            try:
                service = RefreshService(self.root); results = {}; failures = {}
                for number, target in enumerate(targets, 1):
                    prefix = f"FETCHING · {number}/{len(targets)} · {target}"
                    self._update(job_id, message=f"{prefix} · 준비 중")
                    try:
                        results[target] = {"status": "SUCCESS", "data": self._collect(service, target, start, end, lambda message, p=prefix: self._update(job_id, message=f"{p} · {message}"))}
                        self._update(job_id, message=f"{prefix} · 완료")
                    except Exception as exc:
                        failures[target] = f"{type(exc).__name__}: {exc}"
                        results[target] = {"status": "FAIL", "error": failures[target]}
                        self.log.exception("Fetch target failed job_id=%s target=%s", job_id, target)
                        self._update(job_id, message=f"{prefix} · 실패 · 다음 대상 계속")
                if row["chain_index"]:
                    self._update(job_id, message="수집 완료 · Watchdog에 스마트 인덱싱 요청 중")
                    results["indexJob"] = self._notify_watchdog(job_id)
                results["failures"] = failures
                if failures and not row["chain_index"]:
                    raise RuntimeError(" | ".join(f"{target}: {error}" for target, error in failures.items()))
                self._update(job_id, status="completed", message="수집 완료" if not failures else f"수집 완료 · {len(failures)}개 대상 실패", result=results, finished_at=self._now())
            except Exception as exc:
                self.log.exception("Fetch job failed job_id=%s", job_id)
                self._update(job_id, status="failed", message="수집 실패", error={"message": f"{type(exc).__name__}: {exc}", "traceback": traceback.format_exc()}, finished_at=self._now())
            finally:
                self.current_job_id = None


def handler_for(agent: FetcherAgent):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, payload: dict):
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status); self.send_header("Content-Type", "application/json; charset=utf-8"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        def do_GET(self):
            if self.path == "/health": self._send(200, agent.snapshot()); return
            if self.path.startswith("/jobs/"):
                job = agent.get(self.path.removeprefix("/jobs/")); self._send(200, job) if job else self._send(404, {"error": "job not found"}); return
            self._send(404, {"error": "not found"})
        def do_POST(self):
            parsed = urlparse(self.path)
            if parsed.path == "/jobs":
                query = parse_qs(parsed.query)
                try: self._send(202, agent.submit((query.get("targets") or [""])[0].split(","), (query.get("start") or [None])[0], (query.get("end") or [None])[0], (query.get("chain_index") or ["0"])[0] == "1"))
                except (ValueError, TypeError) as exc: self._send(400, {"error": str(exc)})
                return
            if parsed.path == "/shutdown": self._send(202, {"accepted": True}); threading.Thread(target=agent.stop.set, daemon=True).start(); return
            self._send(404, {"error": "not found"})
        def log_message(self, *_): pass
    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--root", type=Path, required=True); parser.add_argument("--port", type=int, default=8768); args = parser.parse_args()
    (args.root / "runtime/logs").mkdir(parents=True, exist_ok=True)
    logging.basicConfig(filename=args.root / "runtime/logs/fetcher.log", level=logging.INFO, encoding="utf-8", format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
    singleton = acquire_singleton(args.root / "runtime/fetcher/fetcher.lock")
    if singleton is None: return 0
    agent = FetcherAgent(args.root)
    signal.signal(signal.SIGTERM, lambda *_: agent.stop.set()); signal.signal(signal.SIGINT, lambda *_: agent.stop.set())
    threading.Thread(target=agent.heartbeat_loop, daemon=True, name="fetcher-heartbeat").start(); threading.Thread(target=agent.worker_loop, daemon=True, name="fetcher-worker").start()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler_for(agent)); server.timeout = 1
    while not agent.stop.is_set(): server.handle_request()
    server.server_close(); singleton.close(); return 0


if __name__ == "__main__":
    raise SystemExit(main())
