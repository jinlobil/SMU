import json
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
    cache = tmp_path / "cache/detections/2026-07-22.json"
    cache.parent.mkdir(parents=True)
    cache.write_text(json.dumps([{
        "time": "2026-07-22T01:00:00Z", "sensor": {"type": "endpoint"},
        "detectionDescription": {"createdReasonId": "WIN-MALWARE-TEST"},
        "rawData": {"meta_hostname": "PC-1", "process_name": "bad.exe", "sha256": "abc"},
    }]), encoding="utf-8")
    service = ReportService(tmp_path)

    result = service.build(date(2026, 7, 22), date(2026, 7, 28))
    output = Path(result["path"])

    assert output.exists()
    assert output.name == "Security_Report_2026-07-22_2026-07-28.pdf"
    assert output.read_bytes().startswith(b"%PDF")
    assert result["pages"] >= 4
