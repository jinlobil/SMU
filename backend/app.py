import logging
import json
import time
import uuid
import urllib.error
from contextlib import asynccontextmanager
from datetime import date
from pathlib import Path

from fastapi import Body, FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

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
from backend.services.firewall_detections import FirewallDetectionService
from backend.services.event_list_index import EventListIndex
from backend.services.easy_query import EasyQueryService
from backend.services.layout import LayoutService
from backend.services.settings import DEFAULT_THEME, SchedulerService, ThemePresetService, ThemeService
from backend.services.report import ReportService
from backend.services.system_metrics import SystemMetricsService
from backend.services.watchdog_client import WatchdogManager
from backend.services.spreadsheet import write_xlsx
from backend.services.integrations import IntegrationService
from backend.services.index_maintenance import IndexMaintenanceService
from backend.services.exceptions import ExceptionService
from backend.services.content import ContentService
from backend.services.learner.store import LearnerStore
from backend.services.learner import LearnerService
from backend.services.exporting import export_headers, normalize_export_columns, normalize_report_sections, schema_payload


configure_logging()
log = logging.getLogger("smu.web")
QUIET_POLL_PATHS = {
    "/api/health", "/api/config/status", "/api/config/scheduler",
    "/api/system-info/process-status", "/api/system-info/current",
    "/api/system-info/history",
}
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
firewall_detection_service = FirewallDetectionService(PROJECT_ROOT)
event_list_index = EventListIndex(PROJECT_ROOT)
easy_query_service = EasyQueryService(PROJECT_ROOT)
layout_service = LayoutService(PROJECT_ROOT)
theme_service = ThemeService(PROJECT_ROOT)
theme_preset_service = ThemePresetService(PROJECT_ROOT)
report_service = ReportService(PROJECT_ROOT)
system_metrics_service = SystemMetricsService(PROJECT_ROOT)
watchdog_manager = WatchdogManager(PROJECT_ROOT)
scheduler_service = SchedulerService(PROJECT_ROOT, refresh_service, watchdog_manager)
integration_service = IntegrationService(PROJECT_ROOT)
exception_service = ExceptionService(PROJECT_ROOT)
content_service = ContentService(PROJECT_ROOT)
index_maintenance_service = IndexMaintenanceService(PROJECT_ROOT)
learner_store = None  # Learner DB is opened lazily; normal UI requests never trigger analysis storage.
try:
    dashboard_service.warm_default()
except Exception:
    log.exception("Dashboard startup pre-aggregation failed; the API will retry on demand")

@asynccontextmanager
async def lifespan(_app: FastAPI):
    watchdog_manager.start()
    yield
    watchdog_manager.stop.set()


app = FastAPI(
    title="SMU Local Web API",
    version="0.1.0",
    description="Local API used by the SMU JavaScript frontend.",
    lifespan=lifespan,
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
    path = request.url.path
    polling = path in QUIET_POLL_PATHS or path.startswith("/api/jobs/")
    if response.status_code >= 400:
        log.warning("request_id=%s method=%s path=%s status=%s elapsed_ms=%.1f", request_id, request.method, path, response.status_code, elapsed_ms)
    elif elapsed_ms >= 1000 or not polling:
        log.info("request_id=%s method=%s path=%s status=%s elapsed_ms=%.1f", request_id, request.method, path, response.status_code, elapsed_ms)
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


@app.get("/api/system-info/current")
def system_info_current() -> dict:
    return {"success": True, "data": system_metrics_service.current()}


@app.get("/api/system-info/history")
def system_info_history(start: str, end: str, bucket: str = "auto") -> dict:
    try:
        data = system_metrics_service.history(start, end, bucket)
    except ValueError as exc:
        return error_response(str(uuid.uuid4()), "INVALID_SYSTEM_INFO_RANGE", str(exc), 400)
    return {"success": True, "data": data}


@app.get("/api/system-info/process-status")
def system_info_process_status() -> dict:
    return {"success": True, "data": watchdog_manager.status()}


@app.post("/api/system-info/collector/restart", status_code=202)
def restart_system_info_collector() -> dict:
    try:
        data = watchdog_manager.restart_collector()
    except Exception as exc:
        return error_response(str(uuid.uuid4()), "COLLECTOR_RESTART_FAILED", str(exc), 503)
    return {"success": True, "data": data}


@app.post("/api/system-info/watchdog/restart", status_code=202)
def restart_system_info_watchdog() -> dict:
    try:
        data = watchdog_manager.restart_watchdog()
    except Exception as exc:
        return error_response(str(uuid.uuid4()), "WATCHDOG_RESTART_FAILED", str(exc), 503)
    return {"success": True, "data": data}


@app.post("/api/system-info/indexer/restart", status_code=202)
def restart_system_info_indexer() -> dict:
    try:
        data = watchdog_manager.restart_indexer()
    except Exception as exc:
        return error_response(str(uuid.uuid4()), "INDEXER_RESTART_FAILED", str(exc), 503)
    return {"success": True, "data": data}


@app.post("/api/system-info/fetcher/restart", status_code=202)
def restart_system_info_fetcher() -> dict:
    try:
        data = watchdog_manager.restart_fetcher()
    except Exception as exc:
        return error_response(str(uuid.uuid4()), "FETCHER_RESTART_FAILED", str(exc), 503)
    return {"success": True, "data": data}


@app.post("/api/system-info/learner/restart", status_code=202)
def restart_system_info_learner() -> dict:
    try: data=watchdog_manager.restart_learner()
    except Exception as exc: return error_response(str(uuid.uuid4()),"LEARNER_RESTART_FAILED",str(exc),503)
    return {"success":True,"data":data}


@app.post("/api/system-info/laborer/restart", status_code=202)
def restart_system_info_laborer() -> dict:
    try:
        data = watchdog_manager.restart_laborer()
    except Exception as exc:
        return error_response(str(uuid.uuid4()), "LABORER_RESTART_FAILED", str(exc), 503)
    return {"success": True, "data": data}


def _dashboard_response(loader, start: date | None, end: date | None, *args) -> dict:
    try:
        data = loader(start, end, *args)
    except ValueError as exc:
        request_id = str(uuid.uuid4())
        return error_response(request_id, "INVALID_DASHBOARD_RANGE", str(exc), 400)
    return {"success": True, "data": data}


@app.get("/api/dashboard")
def get_dashboard(start: date | None = None, end: date | None = None, refresh: bool = False) -> dict:
    return _dashboard_response(dashboard_service.summary, start, end, refresh)


@app.get("/api/dashboard/assets")
def get_dashboard_assets(start: date | None = None, end: date | None = None) -> dict:
    return _dashboard_response(dashboard_service.assets, start, end)


@app.get("/api/dashboard/mix-trend")
def get_dashboard_mix_trend(start: date | None = None, end: date | None = None) -> dict:
    return _dashboard_response(dashboard_service.mix_trend, start, end)


@app.get("/api/dashboard/top-detection")
def get_dashboard_top_detection(start: date | None = None, end: date | None = None) -> dict:
    return _dashboard_response(dashboard_service.top_detection, start, end)


@app.get("/api/dashboard/top-mail")
def get_dashboard_top_mail(start: date | None = None, end: date | None = None) -> dict:
    return _dashboard_response(dashboard_service.top_mail, start, end)


@app.get("/api/dashboard/top-file")
def get_dashboard_top_file(start: date | None = None, end: date | None = None) -> dict:
    return _dashboard_response(dashboard_service.top_file, start, end)


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
    for name, relative in {"app": "cache/index/app_cache.db", "timeline": "cache/index/timeline_index.db", "events": "cache/index/events_index.db", "dashboard": "cache/index/web_dashboard_summary.json"}.items():
        path = PROJECT_ROOT / relative
        stat = path.stat() if path.exists() else None
        indexes[name] = {"exists": path.exists(), "bytes": stat.st_size if stat else 0, "latest": stat.st_mtime if stat else None}
    event_kinds = event_list_index.kind_status(["detections", "xdr", "firewall", "inbound", "outbound", "dlp"])
    return {"success": True, "data": {"sources": sources, "indexes": indexes, "eventKinds": event_kinds, "indexDatabases": index_maintenance_service.databases(), "logs": str(PROJECT_ROOT / "runtime/logs")}}


@app.get("/api/config/scheduler")
def get_scheduler() -> dict:
    return {"success": True, "data": scheduler_service.get()}


@app.put("/api/config/scheduler")
def save_scheduler(payload: dict = Body()) -> dict:
    return {"success": True, "data": scheduler_service.save(payload)}


@app.post("/api/config/scheduler/run", status_code=202)
def run_scheduler_now() -> dict:
    return {"success": True, "data": scheduler_service.run_now()}


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


@app.get("/api/config/theme/default")
def get_default_theme() -> dict:
    return {"success": True, "data": {"name": "SMU Neon Purple", "theme": dict(DEFAULT_THEME)}}


@app.get("/api/config/theme/presets")
def get_theme_presets() -> dict:
    return {"success": True, "data": {"items": theme_preset_service.load()}}


@app.post("/api/config/theme/presets")
def save_theme_preset(payload: dict = Body()) -> dict:
    try:
        data = theme_preset_service.save(payload.get("name", ""), payload.get("theme", {}))
    except ValueError as exc:
        return error_response(str(uuid.uuid4()), "INVALID_THEME_PRESET", str(exc), 400)
    return {"success": True, "data": {"items": data}}


@app.delete("/api/config/theme/presets/{name}")
def delete_theme_preset(name: str) -> dict:
    return {"success": True, "data": {"items": theme_preset_service.delete(name)}}


@app.get("/api/config/integrations")
def list_integrations() -> dict:
    return {"success": True, "data": {"items": integration_service.list()}}


@app.post("/api/config/integrations", status_code=201)
def create_integration(payload: dict = Body()) -> dict:
    try:
        data = integration_service.save(payload)
    except (KeyError, ValueError) as exc:
        return error_response(str(uuid.uuid4()), "INVALID_INTEGRATION", str(exc), 400)
    return {"success": True, "data": data}


@app.put("/api/config/integrations/{integration_id}")
def update_integration(integration_id: str, payload: dict = Body()) -> dict:
    try:
        data = integration_service.save(payload, integration_id)
    except KeyError:
        return error_response(str(uuid.uuid4()), "INTEGRATION_NOT_FOUND", "연동 정보를 찾을 수 없습니다.", 404)
    except ValueError as exc:
        return error_response(str(uuid.uuid4()), "INVALID_INTEGRATION", str(exc), 400)
    return {"success": True, "data": data}


@app.delete("/api/config/integrations/{integration_id}")
def delete_integration(integration_id: str) -> dict:
    try:
        integration_service.delete(integration_id)
    except KeyError:
        return error_response(str(uuid.uuid4()), "INTEGRATION_NOT_FOUND", "연동 정보를 찾을 수 없습니다.", 404)
    return {"success": True}


@app.post("/api/config/integrations/{integration_id}/test")
def test_integration(integration_id: str) -> dict:
    try:
        data = integration_service.test(integration_id)
    except KeyError:
        return error_response(str(uuid.uuid4()), "INTEGRATION_NOT_FOUND", "연동 정보를 찾을 수 없습니다.", 404)
    return {"success": True, "data": data}


@app.get("/api/config/exceptions/{kind}")
def list_exceptions(kind: str) -> dict:
    try:
        data = exception_service.list(kind)
    except ValueError as exc:
        return error_response(str(uuid.uuid4()), "INVALID_EXCEPTION_TYPE", str(exc), 400)
    return {"success": True, "data": data}


@app.post("/api/config/exceptions/{kind}", status_code=201)
def create_exception(kind: str, payload: dict = Body()) -> dict:
    try:
        data = exception_service.save(kind, payload)
    except ValueError as exc:
        return error_response(str(uuid.uuid4()), "INVALID_EXCEPTION", str(exc), 400)
    return {"success": True, "data": data}


@app.put("/api/config/exceptions/{kind}/{item_id}")
def update_exception(kind: str, item_id: str, payload: dict = Body()) -> dict:
    try:
        data = exception_service.save(kind, payload, item_id)
    except KeyError:
        return error_response(str(uuid.uuid4()), "EXCEPTION_NOT_FOUND", "예외 규칙을 찾을 수 없습니다.", 404)
    except ValueError as exc:
        return error_response(str(uuid.uuid4()), "INVALID_EXCEPTION", str(exc), 400)
    return {"success": True, "data": data}


@app.delete("/api/config/exceptions/{kind}/{item_id}")
def delete_exception(kind: str, item_id: str) -> dict:
    try:
        exception_service.delete(kind, item_id)
    except KeyError:
        return error_response(str(uuid.uuid4()), "EXCEPTION_NOT_FOUND", "예외 규칙을 찾을 수 없습니다.", 404)
    except ValueError as exc:
        return error_response(str(uuid.uuid4()), "INVALID_EXCEPTION_TYPE", str(exc), 400)
    return {"success": True}


@app.get("/api/config/content/{kind}")
def list_content_categories(kind: str) -> dict:
    try: data = content_service.list(kind)
    except ValueError as exc: return error_response(str(uuid.uuid4()), "INVALID_CONTENT_KIND", str(exc), 400)
    return {"success": True, "data": data}


@app.post("/api/config/content/{kind}", status_code=201)
def create_content_category(kind: str, payload: dict = Body()) -> dict:
    try: data = content_service.save(kind, payload)
    except ValueError as exc: return error_response(str(uuid.uuid4()), "INVALID_CONTENT_RULE", str(exc), 400)
    return {"success": True, "data": data}


@app.put("/api/config/content/{kind}/{item_id}")
def update_content_category(kind: str, item_id: str, payload: dict = Body()) -> dict:
    try: data = content_service.save(kind, payload, item_id)
    except ValueError as exc: return error_response(str(uuid.uuid4()), "INVALID_CONTENT_RULE", str(exc), 400)
    except KeyError: return error_response(str(uuid.uuid4()), "CONTENT_RULE_NOT_FOUND", "콘텐츠 카테고리를 찾을 수 없습니다.", 404)
    return {"success": True, "data": data}


@app.delete("/api/config/content/{kind}/{item_id}")
def delete_content_category(kind: str, item_id: str) -> dict:
    try: content_service.delete(kind, item_id)
    except ValueError as exc: return error_response(str(uuid.uuid4()), "INVALID_CONTENT_KIND", str(exc), 400)
    except KeyError: return error_response(str(uuid.uuid4()), "CONTENT_RULE_NOT_FOUND", "콘텐츠 카테고리를 찾을 수 없습니다.", 404)
    return {"success": True}


@app.post("/api/jobs/report", status_code=202)
def start_report(payload: dict = Body()) -> dict:
    try:
        start, end = date.fromisoformat(str(payload.get("start", ""))), date.fromisoformat(str(payload.get("end", "")))
        if start > end:
            raise ValueError("start date must not be after end date")
        sections = normalize_report_sections(payload.get("sections"))
    except ValueError as exc:
        return error_response(str(uuid.uuid4()), "INVALID_REPORT_RANGE", str(exc), 400)
    return {"success": True, "data": watchdog_manager.start_laborer_job("report", start=start.isoformat(), end=end.isoformat(), sections=sections)}


@app.get("/api/config/report/{filename}")
def download_report(filename: str):
    path = PROJECT_ROOT / "reports" / Path(filename).name
    if not path.exists():
        return error_response(str(uuid.uuid4()), "REPORT_NOT_FOUND", "Report not found", 404)
    return FileResponse(path, filename=path.name, media_type="application/pdf")


def export_config_data(kind: str, start: date, end: date):
    if start > end:
        return error_response(str(uuid.uuid4()), "INVALID_EXPORT_RANGE", "start date must not be after end date", 400)
    collectors = {"detections": detection_service._events, "xdr": email_security_service._collect_xdr, "firewall": firewall_detection_service._collect, "inbound": email_security_service._collect_inbound, "outbound": transfer_service._collect_outbound, "dlp": transfer_service._collect_dlp}
    collector = collectors.get(kind)
    if collector is None:
        return error_response(str(uuid.uuid4()), "INVALID_EXPORT", "Unknown export type", 400)
    try:
        columns = normalize_export_columns(kind, None)
    except ValueError as exc:
        return error_response(str(uuid.uuid4()), "INVALID_EXPORT", str(exc), 400)
    rows = [row for _record_id, _raw, row in collector(start, end)[0]]
    export_dir = PROJECT_ROOT / "exports"; export_dir.mkdir(parents=True, exist_ok=True)
    path = export_dir / f"{kind}_{start}_{end}.xlsx"
    write_xlsx(path, rows, columns=columns, headers=export_headers(kind))
    return FileResponse(path, filename=path.name, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


@app.get("/api/config/export/schema")
def export_schema() -> dict:
    return {"success": True, "data": schema_payload()}


@app.post("/api/jobs/export", status_code=202)
def start_export(payload: dict = Body()) -> dict:
    kind = str(payload.get("kind", ""))
    try:
        columns = normalize_export_columns(kind, payload.get("columns"))
        start, end = date.fromisoformat(str(payload.get("start", ""))), date.fromisoformat(str(payload.get("end", "")))
        if start > end: raise ValueError("start date must not be after end date")
    except ValueError as exc:
        return error_response(str(uuid.uuid4()), "INVALID_EXPORT", str(exc), 400)
    return {"success": True, "data": watchdog_manager.start_laborer_job("export", kind=kind, start=start.isoformat(), end=end.isoformat(), columns=columns)}


@app.get("/api/config/export/file/{filename}")
def download_export_file(filename: str):
    path = PROJECT_ROOT / "exports" / Path(filename).name
    if not path.exists():
        return error_response(str(uuid.uuid4()), "EXPORT_NOT_FOUND", "Export not found", 404)
    return FileResponse(path, filename=path.name, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


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
    allowed = {"detections", "inbound", "dlp", "outbound", "endpoints", "organizations", "users"}
    if target not in allowed:
        request_id = str(uuid.uuid4())
        return error_response(request_id, "UNKNOWN_REFRESH_TARGET", f"Unknown refresh target: {target}", 404)
    start = end = None
    if target in {"detections", "inbound"}:
        try:
            start = date.fromisoformat(str(payload.get("start", ""))); end = date.fromisoformat(str(payload.get("end", "")))
            if start > end: raise ValueError("start date must not be after end date")
        except ValueError as exc:
            request_id = str(uuid.uuid4()); return error_response(request_id, "INVALID_REFRESH_RANGE", str(exc), 400)
    if target in {"dlp", "outbound"}:
        try:
            start = date.fromisoformat(str(payload.get("start") or payload.get("date", "")))
            end = date.fromisoformat(str(payload.get("end") or payload.get("date", "")))
            if start > end: raise ValueError("start date must not be after end date")
            if (end - start).days > 31: raise ValueError("refresh range must not exceed 32 days")
        except ValueError as exc:
            request_id = str(uuid.uuid4()); return error_response(request_id, "INVALID_REFRESH_DATE", str(exc), 400)
    try:
        job = watchdog_manager.start_fetch_job([target], start, end)
    except Exception as exc:
        return error_response(str(uuid.uuid4()), "FETCHER_JOB_FAILED", str(exc), 503)
    return {"success": True, "data": job}


@app.post("/api/jobs/index", status_code=202)
def rebuild_indexes(payload: dict | None = Body(default=None)) -> dict:
    try:
        data = watchdog_manager.start_index_job(force_full=bool((payload or {}).get("force", False)), scope=(payload or {}).get("scope"))
    except Exception as exc:
        return error_response(str(uuid.uuid4()), "INDEXER_JOB_FAILED", str(exc), 503)
    return {"success": True, "data": data}




@app.post("/api/jobs/index/vacuum", status_code=202)
def vacuum_indexes(payload: dict | None = Body(default=None)) -> dict:
    target = str((payload or {}).get("target", "all"))
    return {"success": True, "data": watchdog_manager.start_laborer_job("vacuum", target=target)}


@app.post("/api/learner/jobs", status_code=202)
def start_learner_job(payload: dict = Body(default={})) -> dict:
    try:
        data=watchdog_manager.start_learner_job(str(payload.get("mode","incremental")),payload.get("sources"),payload.get("start"),payload.get("end"))
    except urllib.error.HTTPError as exc:
        if exc.code == 409:
            try: busy=json.loads(exc.read())
            except Exception: busy={}
            return JSONResponse(status_code=409,content={"success":False,"error":"LEARNER_BUSY","message":busy.get("message","현재 분석 작업이 실행 중입니다."),"currentJobId":busy.get("currentJobId"),"status":busy.get("status")})
        return error_response(str(uuid.uuid4()),"LEARNER_UNAVAILABLE",str(exc),503)
    except Exception as exc:
        log.exception("Learner job submission failed")
        return error_response(str(uuid.uuid4()),"LEARNER_UNAVAILABLE",str(exc),503)
    return {"success":True,"data":data}

@app.post("/api/learner/jobs/{job_id}/cancel", status_code=202)
def cancel_learner_job(job_id: str):
    try:
        data=watchdog_manager.cancel_learner_job(job_id)
        return {"success":True,"jobId":data.get("id",job_id),"status":data.get("status","cancelling")}
    except urllib.error.HTTPError as exc:
        return error_response(str(uuid.uuid4()),"LEARNER_CANCEL_CONFLICT","분석을 중단할 수 없는 상태입니다.",exc.code)
    except Exception as exc:return error_response(str(uuid.uuid4()),"LEARNER_UNAVAILABLE",str(exc),503)

@app.get("/api/learner/findings")
def learner_findings(source: str="", findingType: str="", start: str="", end: str="", view: str="review", page: int=Query(1,ge=1), pageSize: int=Query(30,ge=1,le=100)) -> dict:
    result=LearnerStore(PROJECT_ROOT).findings(source,findingType,start,(end+"T99") if end else "",pageSize,(page-1)*pageSize,view != "all")
    total=result["total"]
    return {"success":True,"data":{"items":result["items"],"pagination":{"page":page,"pageSize":pageSize,"total":total,"totalPages":max(1,(total+pageSize-1)//pageSize)}}}

@app.get("/api/learner/findings/{finding_id}")
def learner_finding(finding_id: str) -> dict:
    data=LearnerStore(PROJECT_ROOT).finding(finding_id)
    return {"success":True,"data":data} if data else error_response(str(uuid.uuid4()),"LEARNER_FINDING_NOT_FOUND","Finding not found",404)

@app.get("/api/learner/history")
def learner_history(source: str, scopeType: str, scopeKey: str, behaviorType: str, behaviorKey: str) -> dict:
    return {"success":True,"data":LearnerService(PROJECT_ROOT).history(source,scopeType,scopeKey,behaviorType,behaviorKey)}

@app.get("/api/jobs/{job_id}")
def get_job(job_id: str) -> dict:
    job = job_manager.get(job_id)
    if job is None:
        try:
            job = watchdog_manager.fetch_job(job_id) or watchdog_manager.index_job(job_id) or watchdog_manager.laborer_job(job_id) or watchdog_manager.learner_job(job_id)
        except Exception as exc:
            return error_response(str(uuid.uuid4()), "INDEXER_STATUS_FAILED", str(exc), 503)
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


@app.get("/api/firewall-detections")
def list_firewall_detections(start: date, end: date, conditions: str = "[]", page: int = Query(default=1, ge=1), page_size: int = Query(default=50, alias="pageSize", ge=10, le=200), sort: str = "time", direction: str = "desc") -> dict:
    try:
        parsed = json.loads(conditions)
        if not isinstance(parsed, list):
            raise ValueError("conditions must be a list")
        data = firewall_detection_service.list_records(start, end, parsed, page, page_size, sort, direction)
    except (ValueError, json.JSONDecodeError) as exc:
        request_id = str(uuid.uuid4())
        return error_response(request_id, "INVALID_FIREWALL_DETECTION_QUERY", str(exc), 400)
    return {"success": True, "data": data}


@app.get("/api/firewall-detections/{record_id}")
def get_firewall_detection(record_id: str, start: date, end: date) -> dict:
    data = firewall_detection_service.get_record(record_id, start, end)
    if data is None:
        return error_response(str(uuid.uuid4()), "FIREWALL_DETECTION_NOT_FOUND", "Firewall detection not found", 404)
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
def list_sensitive(kind: str, category: str = "전체", keyword: str = "", sources: str = "DLP,Outbound Mail", offset: int = Query(default=0, ge=0), limit: int = Query(default=50, ge=1, le=1000)) -> dict:
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


# Optional production host. API routes are registered first and static assets
# use /static so the frontend /assets/* screen routes remain available.
FRONTEND_DIST = PROJECT_ROOT / "frontend" / "dist"
if FRONTEND_DIST.is_dir():
    static_dir = FRONTEND_DIST / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=static_dir), name="frontend-static")

    @app.get("/{frontend_path:path}", include_in_schema=False)
    def frontend_spa(frontend_path: str):
        if frontend_path == "api" or frontend_path.startswith("api/"):
            return JSONResponse(status_code=404, content={"success": False, "error": {"code": "NOT_FOUND", "message": "API route not found"}})
        return FileResponse(FRONTEND_DIST / "index.html")
