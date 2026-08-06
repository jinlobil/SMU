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

from backend.services.detections import DetectionService
from backend.services.email_security import EmailSecurityService
from backend.services.index_maintenance import IndexMaintenanceService
from backend.services.report import ReportService
from backend.services.spreadsheet import write_xlsx
from backend.services.exporting import export_headers, normalize_export_columns, normalize_report_sections
from backend.services.transfers import TransferService
from system_monitor.collector import acquire_singleton, atomic_json
from system_monitor.logging_utils import configure_agent_logging


def decode_job_query(query: str) -> tuple[str, dict]:
    """Decode a job request without flattening list-valued configuration."""
    parsed = parse_qs(query)
    job_type = str(parsed.pop("type", [""])[0])
    structured = {"columns", "sections"}
    return job_type, {key: values if key in structured else values[0] for key, values in parsed.items()}


class LaborerAgent:
    def __init__(self, root: Path):
        self.root = root
        self.directory = root / "runtime/laborer"
        self.database = self.directory / "jobs.db"
        self.status_path = self.directory / "laborer_status.json"
        self.stop = threading.Event()
        self.wake = threading.Event()
        self.job_lock = threading.Lock()
        self.current_job_id: str | None = None
        self.started_at = datetime.now().astimezone().isoformat(timespec="seconds")
        self.log = logging.getLogger("smu.laborer.agent")
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
            db.execute("CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, type TEXT NOT NULL, status TEXT NOT NULL, message TEXT NOT NULL, payload TEXT NOT NULL, result TEXT, error TEXT, created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT)")
            db.execute("UPDATE jobs SET status='queued', message='Laborer 재시작 후 작업 복구 중', started_at=NULL WHERE status='running'")

    def submit(self, job_type: str, payload: dict) -> dict:
        if job_type not in {"vacuum", "export", "report"}:
            raise ValueError(f"지원하지 않는 Laborer 작업입니다: {job_type}")
        with self.job_lock:
            with self._connect() as db:
                job_id = str(uuid.uuid4())
                db.execute("INSERT INTO jobs (id,type,status,message,payload,result,error,created_at,started_at,finished_at) VALUES (?,?,?,?,?,?,?,?,?,?)", (job_id, job_type, "queued", "대기 중", json.dumps(payload, ensure_ascii=False), None, None, self._now(), None, None))
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
            self.log.info("Laborer progress job_id=%s %s", job_id, fields["message"])

    def snapshot(self) -> dict:
        return {"status": "running", "pid": os.getpid(), "startedAt": self.started_at, "lastHeartbeatAt": datetime.now().astimezone().isoformat(timespec="seconds"), "currentJobId": self.current_job_id, "lastError": None}

    def heartbeat_loop(self) -> None:
        while not self.stop.is_set():
            atomic_json(self.status_path, self.snapshot())
            self.stop.wait(2)

    def _export(self, payload: dict, progress) -> dict:
        kind, start, end = str(payload.get("kind", "")), date.fromisoformat(str(payload.get("start"))), date.fromisoformat(str(payload.get("end")))
        collectors = {"detections": DetectionService(self.root)._events, "xdr": EmailSecurityService(self.root)._collect_xdr, "inbound": EmailSecurityService(self.root)._collect_inbound, "outbound": TransferService(self.root)._collect_outbound, "dlp": TransferService(self.root)._collect_dlp}
        if kind not in collectors: raise ValueError("Unknown export type")
        progress(f"{kind} XLSX 데이터 준비 중")
        columns = normalize_export_columns(kind, payload.get("columns"))
        rows = [row for _record_id, _raw, row in collectors[kind](start, end)[0]]
        export_dir = self.root / "exports"; export_dir.mkdir(parents=True, exist_ok=True)
        path = export_dir / f"{kind}_{start}_{end}.xlsx"
        progress(f"{kind} XLSX 파일 생성 중 · {len(rows):,}건 · {len(columns):,}개 항목")
        write_xlsx(path, rows, columns=columns, headers=export_headers(kind))
        return {"filename": path.name, "path": str(path), "rows": len(rows), "columns": columns}

    def worker_loop(self) -> None:
        while not self.stop.is_set():
            with self._connect() as db:
                row = db.execute("SELECT * FROM jobs WHERE status='queued' ORDER BY created_at LIMIT 1").fetchone()
            if not row:
                self.wake.wait(1); self.wake.clear(); continue
            job_id = row["id"]; payload = json.loads(row["payload"])
            self.current_job_id = job_id
            self._update(job_id, status="running", message="작업 시작", started_at=self._now())
            try:
                callback = lambda message: self._update(job_id, message=str(message))
                if row["type"] == "vacuum": result = IndexMaintenanceService(self.root).vacuum(str(payload.get("target", "all")), callback)
                elif row["type"] == "report": result = ReportService(self.root).build(date.fromisoformat(str(payload.get("start"))), date.fromisoformat(str(payload.get("end"))), callback, normalize_report_sections(payload.get("sections")))
                elif row["type"] == "export": result = self._export(payload, callback)
                else: raise ValueError(f"Unknown laborer job type: {row['type']}")
                self._update(job_id, status="completed", message="완료", result=result, finished_at=self._now())
            except Exception as exc:
                self.log.exception("Laborer job failed job_id=%s", job_id)
                self._update(job_id, status="failed", message="실패", error={"message": f"{type(exc).__name__}: {exc}", "traceback": traceback.format_exc()}, finished_at=self._now())
            finally:
                self.current_job_id = None


def handler_for(agent: LaborerAgent):
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
                try:
                    job_type, payload = decode_job_query(parsed.query)
                    self._send(202, agent.submit(job_type, payload))
                except (ValueError, TypeError) as exc: self._send(400, {"error": str(exc)})
                return
            if parsed.path == "/shutdown": self._send(202, {"accepted": True}); threading.Thread(target=agent.stop.set, daemon=True).start(); return
            self._send(404, {"error": "not found"})
        def log_message(self, *_): pass
    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--root", type=Path, required=True); parser.add_argument("--port", type=int, default=8769); args = parser.parse_args()
    (args.root / "runtime/logs").mkdir(parents=True, exist_ok=True)
    configure_agent_logging(args.root / "runtime/logs/laborer.log", retention_days=60)
    singleton = acquire_singleton(args.root / "runtime/laborer/laborer.lock")
    if singleton is None: return 0
    agent = LaborerAgent(args.root)
    signal.signal(signal.SIGTERM, lambda *_: agent.stop.set()); signal.signal(signal.SIGINT, lambda *_: agent.stop.set())
    threading.Thread(target=agent.heartbeat_loop, daemon=True, name="laborer-heartbeat").start(); threading.Thread(target=agent.worker_loop, daemon=True, name="laborer-worker").start()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler_for(agent)); server.timeout = 1
    while not agent.stop.is_set(): server.handle_request()
    server.server_close(); singleton.close(); return 0


if __name__ == "__main__":
    raise SystemExit(main())
