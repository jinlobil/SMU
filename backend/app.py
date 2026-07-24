import logging
import csv
import json
import time
import uuid
from datetime import date

from fastapi import Body, FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse

from backend.config import WEB_ERROR_LOG
from backend.config import PROJECT_ROOT
from backend.logging_config import configure_logging
from backend.services.endpoints import EndpointService
from backend.services.organizations import OrganizationService
from backend.services.jobs import JobManager
from backend.services.refresh import RefreshService
from backend.services.detections import DetectionService
from backend.services.email_security import EmailSecurityService
from backend.services.transfers import TransferService
from backend.services.timeline import TimelineService
from backend.services.sensitive import SensitiveService
from backend.services.dashboard import DashboardService
from backend.services.firewall import FirewallService
from backend.services.easy_query import EasyQueryService
from backend.services.layout import LayoutService
from backend.services.settings import SchedulerService, ThemeService
from backend.services.report import ReportService
from backend.services.indexing import IndexService


configure_logging()
log = logging.getLogger("smu.web")
endpoint_service = EndpointService(PROJECT_ROOT)
organization_service = OrganizationService(PROJECT_ROOT)
refresh_service = RefreshService(PROJECT_ROOT)
job_manager = JobManager()
detection_service = DetectionService(PROJECT_ROOT)
email_security_service = EmailSecurityService(PROJECT_ROOT)
transfer_service = TransferService(PROJECT_ROOT)
timeline_service = TimelineService(PROJECT_ROOT)
sensitive_service = SensitiveService(PROJECT_ROOT)
dashboard_service = DashboardService(PROJECT_ROOT)
firewall_service = FirewallService(PROJECT_ROOT)
easy_query_service = EasyQueryService(PROJECT_ROOT)
layout_service = LayoutService(PROJECT_ROOT)
theme_service = ThemeService(PROJECT_ROOT)
scheduler_service = SchedulerService(PROJECT_ROOT, refresh_service)
report_service = ReportService(PROJECT_ROOT)
index_service = IndexService(PROJECT_ROOT)
try:
    dashboard_service.warm_default()
except Exception:
    log.exception("Dashboard startup pre-aggregation failed; the API will retry on demand")

app = FastAPI(
    title="SMU Local Web API",
    version="0.1.0",
    description="Local API used by the SMU JavaScript frontend.",
)


def error_response(request_id: str, code: str, message: str, status_code: int) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "success": False,
            "error": {
                "requestId": request_id,
                "code": code,
                "message": message,
            },
        },
        headers={"X-Request-ID": request_id},
    )


@app.middleware("http")
async def request_logging(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = request_id
    started = time.monotonic()
    try:
        response = await call_next(request)
    except Exception:
        elapsed_ms = (time.monotonic() - started) * 1000
        log.exception(
            "Unhandled request error request_id=%s method=%s path=%s elapsed_ms=%.1f",
            request_id,
            request.method,
            request.url.path,
            elapsed_ms,
        )
        return error_response(
            request_id,
            "INTERNAL_SERVER_ERROR",
            f"서버 오류가 저장되었습니다. 요청 ID: {request_id}",
            500,
        )

    elapsed_ms = (time.monotonic() - started) * 1000
    response.headers["X-Request-ID"] = request_id
    log.info(
        "request_id=%s method=%s path=%s status=%s elapsed_ms=%.1f",
        request_id,
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
    )
    return response


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    log.error(
        "Validation error request_id=%s path=%s errors=%s",
        request_id,
        request.url.path,
        exc.errors(),
    )
    return error_response(request_id, "VALIDATION_ERROR", "요청값을 확인해주세요.", 422)


@app.get("/api/health")
def health() -> dict:
    return {
        "success": True,
        "data": {
            "status": "ok",
            "service": "smu-local-web",
            "errorLog": str(WEB_ERROR_LOG),
        },
    }


@app.get("/api/dashboard")
def get_dashboard(start: date | None = None, end: date | None = None, refresh: bool = False) -> dict:
    try:
        data = dashboard_service.summary(start, end, refresh)
    except ValueError as exc:
        request_id = str(uuid.uuid4())
        return error_response(request_id, "INVALID_DASHBOARD_RANGE", str(exc), 400)
    return {"success": True, "data": data}


@app.get("/api/firewall/configuration")
def get_firewall_configuration() -> dict:
    return {"success": True, "data": {"firewalls": firewall_service.public_configurations()}}


@app.post("/api/jobs/firewall", status_code=202)
def start_firewall_job(payload: dict = Body()) -> dict:
    action = str(payload.get("action", "create")).lower()
    mode = str(payload.get("mode", "IP")).upper()
    firewalls = payload.get("firewalls", [])
    targets = payload.get("targets", [])
    try:
        if action == "create":
            firewall_service.targets(mode, targets)
            firewall_service.selected(firewalls, mode)
            task = lambda progress: firewall_service.execute(mode, targets, firewalls, progress)
        elif action == "groups":
            firewall_service.selected(firewalls, mode)
            task = lambda progress: firewall_service.groups(mode, firewalls, progress)
        else:
            raise ValueError("action must be create or groups")
    except ValueError as exc:
        request_id = str(uuid.uuid4())
        return error_response(request_id, "INVALID_FIREWALL_REQUEST", str(exc), 400)
    return {"success": True, "data": job_manager.create(f"firewall-{action.lower()}", task)}


@app.get("/api/easy-query/configuration")
def easy_query_configuration() -> dict:
    return {"success": True, "data": {"historyQueries": easy_query_service.history_queries()}}


@app.get("/api/easy-query/sessions")
def easy_query_sessions() -> dict:
    return {"success": True, "data": {"sessions": easy_query_service.sessions()}}


@app.delete("/api/easy-query/sessions/{session_id}")
def delete_easy_query_session(session_id: str) -> dict:
    if not easy_query_service.delete(session_id):
        return error_response(str(uuid.uuid4()), "SESSION_NOT_FOUND", "Session not found", 404)
    return {"success": True}


@app.post("/api/jobs/easy-query", status_code=202)
def start_easy_query(payload: dict = Body()) -> dict:
    mode = str(payload.get("mode", "Live"))
    if mode == "Live":
        task = lambda progress: easy_query_service.run_live(str(payload.get("endpoint", "")), str(payload.get("queryType", "Process")), str(payload.get("keyword", "")), progress)
    elif mode == "History":
        task = lambda progress: easy_query_service.run_history(str(payload.get("queryId", "")), str(payload.get("endpointId", "")), str(payload.get("start", "")), str(payload.get("end", "")), payload.get("variables", {}), progress)
    else:
        return error_response(str(uuid.uuid4()), "INVALID_EASY_QUERY", "mode must be Live or History", 400)
    return {"success": True, "data": job_manager.create(f"easy-query-{mode.lower()}", task)}


@app.get("/api/layout")
def get_layout() -> dict:
    return {"success": True, "data": {"layout": layout_service.load(), "candidates": layout_service.candidates()}}


@app.put("/api/layout")
def save_layout(payload: dict = Body()) -> dict:
    try:
        data = layout_service.save(payload)
    except ValueError as exc:
        return error_response(str(uuid.uuid4()), "INVALID_LAYOUT", str(exc), 400)
    return {"success": True, "data": {"layout": data}}


@app.get("/api/layout/image/{floor}")
def get_layout_image(floor: str):
    path = layout_service.image(floor)
    if not path.exists():
        return error_response(str(uuid.uuid4()), "LAYOUT_IMAGE_NOT_FOUND", str(path), 404)
    return FileResponse(path)


@app.get("/api/config/status")
def config_status() -> dict:
    sources = {}
    for name, relative in {"endpoints": "cache/endpoints.json", "organizations": "cache/user_groups.json", "detections": "cache/detections", "inbound": "cache/emails", "outbound": "cache/mailscreen", "dlp": "cache/dlp"}.items():
        path = PROJECT_ROOT / relative
        files = [path] if path.is_file() else list(path.glob("*")) if path.is_dir() else []
        sources[name] = {"exists": bool(files), "files": len(files), "bytes": sum(file.stat().st_size for file in files if file.is_file()), "latest": max((file.stat().st_mtime for file in files), default=None)}
    indexes = {}
    for name, relative in {"app": "cache/index/app_cache.db", "timeline": "cache/index/timeline_index.db", "dashboard": "cache/index/web_dashboard_summary.json"}.items():
        path = PROJECT_ROOT / relative
        indexes[name] = {"exists": path.exists(), "bytes": path.stat().st_size if path.exists() else 0}
    return {"success": True, "data": {"sources": sources, "indexes": indexes, "logs": str(PROJECT_ROOT / "runtime/logs")}}


@app.get("/api/config/scheduler")
def get_scheduler() -> dict:
    return {"success": True, "data": scheduler_service.get()}


@app.put("/api/config/scheduler")
def save_scheduler(payload: dict = Body()) -> dict:
    return {"success": True, "data": scheduler_service.save(payload)}


@app.get("/api/config/theme")
def get_theme() -> dict:
    return {"success": True, "data": theme_service.load()}


@app.put("/api/config/theme")
def save_theme(payload: dict = Body()) -> dict:
    try:
        data = theme_service.save(payload)
    except ValueError as exc:
        return error_response(str(uuid.uuid4()), "INVALID_THEME", str(exc), 400)
    return {"success": True, "data": data}


@app.post("/api/jobs/report", status_code=202)
def start_report(payload: dict = Body()) -> dict:
    try:
        start, end = date.fromisoformat(str(payload.get("start", ""))), date.fromisoformat(str(payload.get("end", "")))
        if start > end:
            raise ValueError("start date must not be after end date")
    except ValueError as exc:
        return error_response(str(uuid.uuid4()), "INVALID_REPORT_RANGE", str(exc), 400)
    return {"success": True, "data": job_manager.create("security-report", lambda progress: report_service.build(start, end, progress))}


@app.get("/api/config/report/{filename}")
def download_report(filename: str):
    path = PROJECT_ROOT / "reports" / Path(filename).name
    if not path.exists():
        return error_response(str(uuid.uuid4()), "REPORT_NOT_FOUND", "Report not found", 404)
    return FileResponse(path, filename=path.name, media_type="application/pdf")


@app.get("/api/config/export/{kind}")
def export_config_data(kind: str, start: date, end: date):
    collectors = {
        "detections": detection_service._events,
        "xdr": email_security_service._collect_xdr,
        "inbound": email_security_service._collect_inbound,
        "outbound": transfer_service._collect_outbound,
        "dlp": transfer_service._collect_dlp,
    }
    collector = collectors.get(kind)
    if collector is None:
        return error_response(str(uuid.uuid4()), "INVALID_EXPORT", "Unknown export type", 400)
    rows = [row for _record_id, _raw, row in collector(start, end)[0]]
    export_dir = PROJECT_ROOT / "exports"
    export_dir.mkdir(parents=True, exist_ok=True)
    path = export_dir / f"{kind}_{start}_{end}.csv"
    columns = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    return FileResponse(path, filename=path.name, media_type="text/csv")


@app.get("/api/endpoints")
def list_endpoints(
    query: str = "",
    field: str = "all",
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, alias="pageSize", ge=10, le=200),
    sort: str = "hostname",
    direction: str = "asc",
) -> dict:
    try:
        data = endpoint_service.list_endpoints(query, field, page, page_size, sort, direction)
    except ValueError as exc:
        request_id = str(uuid.uuid4())
        log.error("Endpoint query rejected request_id=%s error=%s", request_id, exc)
        return error_response(request_id, "INVALID_ENDPOINT_QUERY", str(exc), 400)
    return {"success": True, "data": data}


@app.get("/api/endpoints/{endpoint_id}")
def get_endpoint(endpoint_id: str) -> dict:
    data = endpoint_service.get_endpoint(endpoint_id)
    if data is None:
        request_id = str(uuid.uuid4())
        return error_response(request_id, "ENDPOINT_NOT_FOUND", f"Endpoint not found: {endpoint_id}", 404)
    return {"success": True, "data": data}


@app.get("/api/organizations")
def list_organizations(
    query: str = "",
    field: str = "all",
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, alias="pageSize", ge=10, le=200),
    sort: str = "deptCode",
    direction: str = "asc",
) -> dict:
    try:
        data = organization_service.list_organizations(query, field, page, page_size, sort, direction)
    except ValueError as exc:
        request_id = str(uuid.uuid4())
        log.error("Organization query rejected request_id=%s error=%s", request_id, exc)
        return error_response(request_id, "INVALID_ORGANIZATION_QUERY", str(exc), 400)
    return {"success": True, "data": data}


@app.post("/api/jobs/refresh/{target}", status_code=202)
def start_refresh(target: str, payload: dict | None = Body(default=None)) -> dict:
    payload = payload or {}
    tasks = {"endpoints": refresh_service.refresh_endpoints, "organizations": refresh_service.refresh_organizations, "users": refresh_service.refresh_users}
    if target in {"detections", "inbound"}:
        try:
            start = date.fromisoformat(str(payload.get("start", ""))); end = date.fromisoformat(str(payload.get("end", "")))
            if start > end: raise ValueError("start date must not be after end date")
        except ValueError as exc:
            request_id = str(uuid.uuid4()); return error_response(request_id, "INVALID_REFRESH_RANGE", str(exc), 400)
        tasks[target] = (lambda progress: refresh_service.refresh_detections(start, end, progress)) if target == "detections" else (lambda progress: refresh_service.refresh_inbound(start, end, progress))
    if target in {"dlp", "outbound"}:
        try:
            day = date.fromisoformat(str(payload.get("date", "")))
        except ValueError as exc:
            request_id = str(uuid.uuid4()); return error_response(request_id, "INVALID_REFRESH_DATE", str(exc), 400)
        tasks[target] = (lambda progress: refresh_service.refresh_dlp(day, progress)) if target == "dlp" else (lambda progress: refresh_service.refresh_outbound(day, progress))
    task = tasks.get(target)
    if task is None:
        request_id = str(uuid.uuid4())
        return error_response(request_id, "UNKNOWN_REFRESH_TARGET", f"Unknown refresh target: {target}", 404)
    return {"success": True, "data": job_manager.create(f"refresh-{target}", task)}


@app.post("/api/jobs/index", status_code=202)
def rebuild_indexes() -> dict:
    return {"success": True, "data": job_manager.create("rebuild-all-indexes", index_service.rebuild_all)}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str) -> dict:
    job = job_manager.get(job_id)
    if job is None:
        request_id = str(uuid.uuid4())
        return error_response(request_id, "JOB_NOT_FOUND", f"Job not found: {job_id}", 404)
    return {"success": True, "data": job}


@app.get("/api/detections")
def list_detections(
    start: date,
    end: date,
    conditions: str = "[]",
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, alias="pageSize", ge=10, le=200),
    sort: str = "time",
    direction: str = "desc",
) -> dict:
    try:
        parsed_conditions = json.loads(conditions)
        if not isinstance(parsed_conditions, list):
            raise ValueError("conditions must be a JSON list")
        data = detection_service.list_detections(start, end, parsed_conditions, page, page_size, sort, direction)
    except (ValueError, json.JSONDecodeError) as exc:
        request_id = str(uuid.uuid4())
        log.error("Detection query rejected request_id=%s error=%s", request_id, exc)
        return error_response(request_id, "INVALID_DETECTION_QUERY", str(exc), 400)
    return {"success": True, "data": data}


@app.get("/api/detections/{event_id}")
def get_detection(event_id: str, start: date, end: date) -> dict:
    data = detection_service.get_detection(event_id, start, end)
    if data is None:
        request_id = str(uuid.uuid4())
        return error_response(request_id, "DETECTION_NOT_FOUND", f"Detection not found: {event_id}", 404)
    return {"success": True, "data": data}


@app.get("/api/email-security/{kind}")
def list_email_security(kind: str, start: date, end: date, conditions: str = "[]", page: int = Query(default=1, ge=1), page_size: int = Query(default=50, alias="pageSize", ge=10, le=200), sort: str = "time", direction: str = "desc") -> dict:
    try:
        parsed = json.loads(conditions)
        if not isinstance(parsed, list): raise ValueError("conditions must be a list")
        data = email_security_service.list_records(kind, start, end, parsed, page, page_size, sort, direction)
    except (ValueError, json.JSONDecodeError) as exc:
        request_id = str(uuid.uuid4()); log.error("Email security query rejected request_id=%s error=%s", request_id, exc)
        return error_response(request_id, "INVALID_EMAIL_SECURITY_QUERY", str(exc), 400)
    return {"success": True, "data": data}


@app.get("/api/email-security/{kind}/{record_id}")
def get_email_security(kind: str, record_id: str, start: date, end: date) -> dict:
    data = email_security_service.get_record(kind, record_id, start, end)
    if data is None:
        request_id = str(uuid.uuid4()); return error_response(request_id, "EMAIL_SECURITY_RECORD_NOT_FOUND", "Record not found", 404)
    return {"success": True, "data": data}


@app.get("/api/transfers/{kind}")
def list_transfers(kind: str, start: date, end: date, conditions: str = "[]", page: int = Query(default=1, ge=1), page_size: int = Query(default=50, alias="pageSize", ge=10, le=200), sort: str = "date", direction: str = "desc") -> dict:
    try:
        parsed = json.loads(conditions)
        if not isinstance(parsed, list): raise ValueError("conditions must be a list")
        data = transfer_service.list_records(kind, start, end, parsed, page, page_size, sort, direction)
    except (ValueError, json.JSONDecodeError) as exc:
        request_id = str(uuid.uuid4()); log.error("Transfer query rejected request_id=%s error=%s", request_id, exc)
        return error_response(request_id, "INVALID_TRANSFER_QUERY", str(exc), 400)
    return {"success": True, "data": data}


@app.get("/api/transfers/{kind}/{record_id}")
def get_transfer(kind: str, record_id: str, start: date, end: date) -> dict:
    data = transfer_service.get_record(kind, record_id, start, end)
    if data is None:
        request_id = str(uuid.uuid4()); return error_response(request_id, "TRANSFER_RECORD_NOT_FOUND", "Record not found", 404)
    return {"success": True, "data": data}


@app.get("/api/timeline")
def search_timeline(user: str = "", keyword: str = "", sources: str = "Detection,XDR,Email,Outbound Mail,File", offset: int = Query(default=0, ge=0), limit: int = Query(default=250, ge=1, le=500)) -> dict:
    if not user.strip() and not keyword.strip():
        request_id = str(uuid.uuid4()); return error_response(request_id, "TIMELINE_SEARCH_REQUIRED", "User or keyword is required", 400)
    try:
        selected_sources = {source.strip() for source in sources.split(",") if source.strip()}
        if not selected_sources: raise ValueError("At least one source is required")
        data = timeline_service.search(user, keyword, selected_sources, offset, limit)
    except ValueError as exc:
        request_id = str(uuid.uuid4()); log.error("Timeline query rejected request_id=%s error=%s", request_id, exc)
        return error_response(request_id, "INVALID_TIMELINE_QUERY", str(exc), 400)
    return {"success": True, "data": data}


@app.get("/api/sensitive/{kind}")
def list_sensitive(kind: str, category: str = "전체", keyword: str = "", sources: str = "DLP,Outbound Mail", offset: int = Query(default=0, ge=0), limit: int = Query(default=500, ge=1, le=1000)) -> dict:
    try:
        data = sensitive_service.query(kind, category, keyword, {source.strip() for source in sources.split(",") if source.strip()}, offset, limit)
    except ValueError as exc:
        request_id = str(uuid.uuid4()); return error_response(request_id, "INVALID_SENSITIVE_QUERY", str(exc), 400)
    return {"success": True, "data": data}


@app.get("/api/sensitive/{kind}/{record_id}")
def get_sensitive(kind: str, record_id: str, sources: str = "DLP,Outbound Mail") -> dict:
    try:
        data = sensitive_service.detail(kind, record_id, {source.strip() for source in sources.split(",") if source.strip()})
    except ValueError as exc:
        request_id = str(uuid.uuid4())
        return error_response(request_id, "INVALID_SENSITIVE_QUERY", str(exc), 400)
    if data is None:
        request_id = str(uuid.uuid4()); return error_response(request_id, "SENSITIVE_RECORD_NOT_FOUND", "Record not found", 404)
    return {"success": True, "data": data}


@app.post("/api/client-errors", status_code=204)
def save_client_error(payload: dict = Body()) -> None:
    log.error(
        "Frontend error message=%s source=%s line=%s column=%s stack=%s",
        str(payload.get("message", ""))[:2000],
        str(payload.get("source", ""))[:1000],
        payload.get("line"),
        payload.get("column"),
        str(payload.get("stack", ""))[:8000],
    )
