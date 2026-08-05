import argparse
import json
import logging
import os
import signal
import sqlite3
import threading
import time
import traceback
import uuid
from datetime import date, datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from backend.services.indexing import IndexService
from system_monitor.collector import acquire_singleton, atomic_json
from system_monitor.logging_utils import configure_agent_logging


class IndexerAgent:
    def __init__(self, root: Path):
        self.root = root
        self.directory = root / "runtime/indexer"
        self.database = self.directory / "jobs.db"
        self.status_path = self.directory / "indexer_status.json"
        self.stop = threading.Event()
        self.wake = threading.Event()
        self.job_lock = threading.Lock()
        self.started_at = datetime.now().astimezone().isoformat(timespec="seconds")
        self.current_job_id: str | None = None
        self.log = logging.getLogger("smu.indexer.agent")
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
            db.execute("CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, type TEXT NOT NULL, status TEXT NOT NULL, message TEXT NOT NULL, result TEXT, error TEXT, created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT, range_start TEXT, range_end TEXT, scope TEXT)")
            columns = {row[1] for row in db.execute("PRAGMA table_info(jobs)")}
            if "range_start" not in columns: db.execute("ALTER TABLE jobs ADD COLUMN range_start TEXT")
            if "range_end" not in columns: db.execute("ALTER TABLE jobs ADD COLUMN range_end TEXT")
            if "scope" not in columns: db.execute("ALTER TABLE jobs ADD COLUMN scope TEXT")
            # A terminated process cannot still own a running job. Requeue it so
            # the fresh agent rebuilds from the transactional staging tables.
            db.execute("UPDATE jobs SET status='queued', message='Indexer 재시작 후 작업 복구 중', started_at=NULL WHERE status='running'")

    def submit(self, range_start: str | None = None, range_end: str | None = None, force_full: bool = False, scope: str | None = None) -> dict:
        job_type = f"rebuild-{scope}-indexes" if scope else "rebuild-all-indexes" if force_full else "incremental-indexes" if range_start and range_end else "smart-indexes"
        with self.job_lock:
            with self._connect() as db:
                active = db.execute("SELECT * FROM jobs WHERE status IN ('queued','running') AND type=? AND COALESCE(range_start,'')=COALESCE(?,'') AND COALESCE(range_end,'')=COALESCE(?,'') AND COALESCE(scope,'')=COALESCE(?,'') ORDER BY created_at LIMIT 1", (job_type, range_start, range_end, scope)).fetchone()
                if active:
                    return self._public(active)
                job_id = str(uuid.uuid4())
                db.execute("INSERT INTO jobs (id,type,status,message,result,error,created_at,started_at,finished_at,range_start,range_end,scope) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (job_id, job_type, "queued", "대기 중", None, None, self._now(), None, None, range_start, range_end, scope))
                row = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        self.wake.set()
        return self._public(row)

    def get(self, job_id: str) -> dict | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return self._public(row) if row else None

    @staticmethod
    def _public(row: sqlite3.Row) -> dict:
        return {"id": row["id"], "type": row["type"], "status": row["status"], "message": row["message"], "result": json.loads(row["result"]) if row["result"] else None, "error": json.loads(row["error"]) if row["error"] else None, "createdAt": row["created_at"], "startedAt": row["started_at"], "finishedAt": row["finished_at"]}

    def _update(self, job_id: str, **fields) -> None:
        names = {"status": "status", "message": "message", "result": "result", "error": "error", "started_at": "started_at", "finished_at": "finished_at"}
        assignments, values = [], []
        for key, value in fields.items():
            assignments.append(f"{names[key]}=?")
            values.append(json.dumps(value, ensure_ascii=False) if key in {"result", "error"} and value is not None else value)
        with self._connect() as db:
            db.execute(f"UPDATE jobs SET {', '.join(assignments)} WHERE id=?", (*values, job_id))
        if "message" in fields:
            self.log.info("Indexer progress job_id=%s %s", job_id, fields["message"])

    def snapshot(self) -> dict:
        return {"status": "running", "pid": os.getpid(), "startedAt": self.started_at, "lastHeartbeatAt": datetime.now().astimezone().isoformat(timespec="seconds"), "currentJobId": self.current_job_id, "lastError": None}

    def heartbeat_loop(self) -> None:
        while not self.stop.is_set():
            atomic_json(self.status_path, self.snapshot())
            self.stop.wait(2)

    def worker_loop(self) -> None:
        while not self.stop.is_set():
            with self._connect() as db:
                row = db.execute("SELECT * FROM jobs WHERE status='queued' ORDER BY created_at LIMIT 1").fetchone()
            if not row:
                self.wake.wait(1)
                self.wake.clear()
                continue
            job_id = row["id"]
            self.current_job_id = job_id
            self._update(job_id, status="running", message="작업 시작", started_at=self._now())
            try:
                # Construct services per job so newly saved Content Management
                # rules are loaded without restarting the persistent agent.
                service = IndexService(self.root)
                callback = lambda message: self._update(job_id, message=str(message))
                if row["scope"]: result = service.rebuild_scope(row["scope"], callback)
                elif row["type"] == "rebuild-all-indexes": result = service.rebuild_all(callback)
                elif row["range_start"] and row["range_end"]: result = service.rebuild_range(date.fromisoformat(row["range_start"]), date.fromisoformat(row["range_end"]), callback)
                else: result = service.rebuild_smart(callback)
                self._update(job_id, status="completed", message="완료", result=result, finished_at=self._now())
            except Exception as exc:
                self.log.exception("Index job failed job_id=%s", job_id)
                self._update(job_id, status="failed", message="실패", error={"message": f"{type(exc).__name__}: {exc}", "traceback": traceback.format_exc()}, finished_at=self._now())
            finally:
                self.current_job_id = None


def handler_for(agent: IndexerAgent):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, payload: dict):
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status); self.send_header("Content-Type", "application/json; charset=utf-8"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        def do_GET(self):
            if self.path == "/health": self._send(200, agent.snapshot()); return
            if self.path.startswith("/jobs/"):
                job = agent.get(self.path.removeprefix("/jobs/"))
                self._send(200, job) if job else self._send(404, {"error": "job not found"})
                return
            self._send(404, {"error": "not found"})
        def do_POST(self):
            parsed = urlparse(self.path)
            if parsed.path == "/jobs":
                query = parse_qs(parsed.query)
                self._send(202, agent.submit((query.get("start") or [None])[0], (query.get("end") or [None])[0], (query.get("force") or ["0"])[0] == "1", (query.get("scope") or [None])[0])); return
            if self.path == "/shutdown": agent.stop.set(); self._send(202, {"accepted": True}); return
            self._send(404, {"error": "not found"})
        def log_message(self, *_): pass
    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--root", type=Path, required=True); parser.add_argument("--port", type=int, default=8767); args = parser.parse_args()
    (args.root / "runtime/logs").mkdir(parents=True, exist_ok=True)
    configure_agent_logging(args.root / "runtime/logs/indexer.log", retention_days=60)
    singleton = acquire_singleton(args.root / "runtime/indexer/indexer.lock")
    if singleton is None:
        logging.info("Indexer already running; duplicate process exiting")
        return 0
    agent = IndexerAgent(args.root)
    signal.signal(signal.SIGTERM, lambda *_: agent.stop.set()); signal.signal(signal.SIGINT, lambda *_: agent.stop.set())
    threading.Thread(target=agent.heartbeat_loop, daemon=True, name="indexer-heartbeat").start()
    threading.Thread(target=agent.worker_loop, daemon=True, name="indexer-worker").start()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler_for(agent)); server.timeout = 1
    while not agent.stop.is_set(): server.handle_request()
    server.server_close(); singleton.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
