from __future__ import annotations

import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from core.paths import BASE_DIR
from core.storage.sqlite_cache import (
    load_app_cache_single,
    load_dlp_by_range,
    load_emails_by_range,
    load_endpoint_detections_by_range,
    load_xdr_email_detections_by_range,
    sync_app_cache_all,
)
from web_backend.theme_store import ensure_color_env_file, save_color_env

Source = Literal["detections", "xdr-email", "emails", "dlp", "endpoints", "organizations", "users"]
DIST_DIR = Path(BASE_DIR) / "web_frontend" / "dist"


class ThemeUpdate(BaseModel):
    values: dict[str, str]


class JobState(BaseModel):
    id: str
    status: Literal["queued", "running", "completed", "failed"]
    message: str = ""
    result: Any = None


app = FastAPI(title="SMU Local API", version="1.0.0", docs_url="/api/docs")
_jobs: dict[str, JobState] = {}
_jobs_lock = threading.Lock()
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="smu-web")


def _range(start: date | None, end: date | None) -> tuple[str, str]:
    end = end or date.today()
    start = start or end - timedelta(days=6)
    if start > end:
        raise HTTPException(400, "시작일은 종료일보다 늦을 수 없습니다.")
    return start.isoformat(), end.isoformat()


def _rows(source: Source, start: str, end: str) -> list[dict[str, Any]]:
    if source == "detections":
        return load_endpoint_detections_by_range(start, end)
    if source == "xdr-email":
        return load_xdr_email_detections_by_range(start, end)
    if source == "emails":
        return load_emails_by_range(start, end)
    if source == "dlp":
        return load_dlp_by_range(start, end)
    file_source = {"endpoints": "endpoints", "organizations": "orgs", "users": "users"}[source]
    return load_app_cache_single(file_source) or []


def _text(row: dict[str, Any]) -> str:
    return json.dumps(row, ensure_ascii=False, default=str).lower()


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "local", "version": app.version}


@app.get("/api/overview")
def overview(start: date | None = None, end: date | None = None) -> dict[str, Any]:
    start_text, end_text = _range(start, end)
    sources = ("detections", "xdr-email", "emails", "dlp")
    data = {source: _rows(source, start_text, end_text) for source in sources}
    return {
        "range": {"start": start_text, "end": end_text},
        "metrics": {source: len(rows) for source, rows in data.items()},
        "recent": {source: rows[-5:][::-1] for source, rows in data.items()},
    }


@app.get("/api/records/{source}")
def records(
    source: Source,
    start: date | None = None,
    end: date | None = None,
    search: str = "",
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=10, le=500),
) -> dict[str, Any]:
    start_text, end_text = _range(start, end)
    rows = _rows(source, start_text, end_text)
    if search.strip():
        needle = search.strip().lower()
        rows = [row for row in rows if needle in _text(row)]
    total = len(rows)
    offset = (page - 1) * page_size
    return {
        "source": source,
        "range": {"start": start_text, "end": end_text},
        "page": page,
        "pageSize": page_size,
        "total": total,
        "items": rows[offset : offset + page_size],
    }


@app.get("/api/theme")
def get_theme() -> dict[str, str]:
    return ensure_color_env_file()


@app.put("/api/theme")
def update_theme(update: ThemeUpdate) -> dict[str, str]:
    current = ensure_color_env_file()
    current.update(update.values)
    save_color_env(current)
    return current


def _run_sync(job_id: str) -> None:
    with _jobs_lock:
        _jobs[job_id] = JobState(id=job_id, status="running", message="데이터 인덱싱 중")
    try:
        result = sync_app_cache_all()
        state = JobState(id=job_id, status="completed", message="인덱싱 완료", result=result)
    except Exception as exc:  # background boundary: expose a stable job result
        state = JobState(id=job_id, status="failed", message=str(exc))
    with _jobs_lock:
        _jobs[job_id] = state


@app.post("/api/jobs/reindex", response_model=JobState)
def reindex() -> JobState:
    job_id = uuid.uuid4().hex
    state = JobState(id=job_id, status="queued", message="인덱싱 대기 중")
    with _jobs_lock:
        _jobs[job_id] = state
    _executor.submit(_run_sync, job_id)
    return state


@app.get("/api/jobs/{job_id}", response_model=JobState)
def job(job_id: str) -> JobState:
    with _jobs_lock:
        state = _jobs.get(job_id)
    if state is None:
        raise HTTPException(404, "작업을 찾을 수 없습니다.")
    return state


if DIST_DIR.exists():
    assets = DIST_DIR / "assets"
    if assets.exists():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def frontend(path: str) -> FileResponse:
        candidate = (DIST_DIR / path).resolve()
        if path and candidate.is_file() and DIST_DIR.resolve() in candidate.parents:
            return FileResponse(candidate)
        return FileResponse(DIST_DIR / "index.html")
