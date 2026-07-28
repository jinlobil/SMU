"""Adapter for the security report implementation ported from ``uimain_window.py``."""
from __future__ import annotations

from datetime import date, datetime, time
from pathlib import Path
from typing import Any, Callable

from backend.services.detections import DetectionService
from backend.services.email_security import EmailSecurityService
from backend.services.endpoints import EndpointService, load_json_list, normalize_key
from backend.services.transfers import TransferService
from backend.services import legacy_report


class ReportService:
    """Run the original desktop report renderer against the web service caches."""

    def __init__(self, root: Path):
        self.root = root
        self.detections = DetectionService(root)
        self.email = EmailSecurityService(root)
        self.transfers = TransferService(root)
        self.endpoints = EndpointService(root)

    def _configure_legacy_data(self) -> None:
        legacy_report.REPORT_DIR = str(self.root / "reports")
        legacy_report.ENDPOINTS = load_json_list(self.root / "cache/endpoints.json")
        legacy_report.ORGS = load_json_list(self.root / "cache/user_groups.json")
        legacy_report.DEPT_MAP = {
            str(org.get("deptCode", "")): str(org.get("deptName") or org.get("name") or org.get("deptCode") or "미분류")
            for org in legacy_report.ORGS if isinstance(org, dict)
        }
        context = self.endpoints._department_context()
        hostname_depts: dict[str, dict[str, str]] = {}
        for index, endpoint in enumerate(legacy_report.ENDPOINTS):
            row = self.endpoints._row(endpoint, context, f"report-{index}")
            hostname_depts[normalize_key(endpoint.get("hostname"))] = {
                "dept_name": row.get("dept", "미분류"), "dept_code": ""
            }
        legacy_report.HOSTNAME_DEPT_MAP = hostname_depts
        legacy_report.DIRECTORY_USER_INDEX = {}
        for user in load_json_list(self.root / "cache/users.json"):
            entry = {
                "name": str(user.get("name") or ""),
                "user_id": str(user.get("exchangeLogin") or user.get("userId") or ""),
                "email": str(user.get("email") or ""),
                "dept_name": str(user.get("dept") or user.get("department") or "미분류"),
                "dept_code": "",
            }
            for value in (entry["name"], entry["user_id"], entry["email"], entry["email"].split("@", 1)[0]):
                if normalize_key(value):
                    legacy_report.DIRECTORY_USER_INDEX[normalize_key(value)] = entry

        def dates(start: str, end: str) -> tuple[date, date]:
            return date.fromisoformat(start), date.fromisoformat(end)

        legacy_report.load_endpoint_detections_by_range = lambda start, end: [raw for _id, raw, _row in self.detections._events(*dates(start, end))[0]]
        legacy_report.load_xdr_email_detections_by_range = lambda start, end: [raw for _id, raw, _row in self.email._collect_xdr(*dates(start, end))[0]]
        legacy_report.load_emails_by_range = lambda start, end: [raw for _id, raw, _row in self.email._collect_inbound(*dates(start, end))[0]]
        legacy_report.load_mailscreen_by_range = lambda start, end: [raw for _id, raw, _row in self.transfers._collect_outbound(*dates(start, end))[0]]
        legacy_report.load_dlp_by_range = lambda start, end: [raw for _id, raw, _row in self.transfers._collect_dlp(*dates(start, end))[0]]

    def build(self, start: date, end: date, progress: Callable[[str], None] = lambda _message: None) -> dict[str, Any]:
        if start > end:
            raise ValueError("start date must not be after end date")
        self._configure_legacy_data()
        renderer = legacy_report.LegacySecurityReport()
        path = renderer._generate_security_report_v2(
            datetime.combine(start, time.min), datetime.combine(end, time.max), progress
        )
        output = Path(path)
        return {"path": str(output), "filename": output.name}
