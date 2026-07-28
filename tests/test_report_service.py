from datetime import date
from pathlib import Path

from fastapi.responses import FileResponse

import backend.app as app_module
from backend.services.report import ReportService


def test_download_report_uses_sanitized_filename(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "reports"
    reports.mkdir()
    report = reports / "security_report.pdf"
    report.write_bytes(b"%PDF-test")
    monkeypatch.setattr(app_module, "PROJECT_ROOT", tmp_path)

    response = app_module.download_report("../security_report.pdf")

    assert isinstance(response, FileResponse)
    assert Path(response.path) == report
    assert response.media_type == "application/pdf"


def test_report_service_builds_downloadable_pdf(tmp_path: Path) -> None:
    service = ReportService(tmp_path)
    service.dashboard.summary = lambda _start, _end: {
        "endpoints": {"total": 2, "pc": 1, "server": 1},
        "organization": {"departments": 1, "users": 2},
        "totals": {"Detection - XDR": 3, "Email - XDR": 2},
        "top": {"hosts": [["PC-1", 3]], "rules": [["Rule", 3]], "senders": [["10.0.0.1", 2]]},
    }

    result = service.build(date(2026, 7, 22), date(2026, 7, 28))
    output = Path(result["path"])

    assert output.exists()
    assert output.name == "security_report_2026-07-22_2026-07-28.pdf"
    assert output.read_bytes().startswith(b"%PDF")
