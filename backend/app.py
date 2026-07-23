import logging
import json
import time
import uuid
from datetime import date

from fastapi import Body, FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

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
    tasks = {"endpoints": refresh_service.refresh_endpoints, "organizations": refresh_service.refresh_organizations}
    if target in {"detections", "inbound"}:
        try:
            start = date.fromisoformat(str(payload.get("start", ""))); end = date.fromisoformat(str(payload.get("end", "")))
            if start > end: raise ValueError("start date must not be after end date")
        except ValueError as exc:
            request_id = str(uuid.uuid4()); return error_response(request_id, "INVALID_REFRESH_RANGE", str(exc), 400)
        tasks[target] = (lambda progress: refresh_service.refresh_detections(start, end, progress)) if target == "detections" else (lambda progress: refresh_service.refresh_inbound(start, end, progress))
    task = tasks.get(target)
    if task is None:
        request_id = str(uuid.uuid4())
        return error_response(request_id, "UNKNOWN_REFRESH_TARGET", f"Unknown refresh target: {target}", 404)
    return {"success": True, "data": job_manager.create(f"refresh-{target}", task)}


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
