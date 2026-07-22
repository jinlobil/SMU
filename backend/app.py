import logging
import time
import uuid

from fastapi import Body, FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from backend.config import WEB_ERROR_LOG
from backend.config import PROJECT_ROOT
from backend.logging_config import configure_logging
from backend.services.endpoints import EndpointService
from backend.services.organizations import OrganizationService


configure_logging()
log = logging.getLogger("smu.web")
endpoint_service = EndpointService(PROJECT_ROOT)
organization_service = OrganizationService(PROJECT_ROOT)

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
