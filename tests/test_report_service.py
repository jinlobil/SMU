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
    }, {
        "time": "2026-07-22T02:00:00Z", "sensor": {"type": "email"},
        "detectionDescription": {"createdReasonId": "XDR-sophos-email-virus"},
        "rawData": {"raw": json.dumps({"mailboxAddress": "user@example.com", "mailFrom": "bad@example.net", "subject": "virus", "attachments": [{"name": "bad.zip", "checksum": "deadbeef"}]})},
    }]), encoding="utf-8")
    email = tmp_path / "cache/emails/2026-07-22.json"
    email.parent.mkdir(parents=True)
    email.write_text(json.dumps([{"receivedAt": "2026-07-22T03:00:00Z", "from": {"localAddress": "bad", "domainAddress": "example.net"}, "to": [{"localAddress": "user", "domainAddress": "example.com"}], "subject": "test", "reason": "spam", "clientIp": "1.2.3.4"}]), encoding="utf-8")
    outbound = tmp_path / "cache/mailscreen/mailscreen_mail_2026-07-22.json"
    outbound.parent.mkdir(parents=True)
    outbound.write_text(json.dumps({"items": [{"date": "2026-07-22 12:00:00", "sender_email": "user@example.com", "sender_name": "홍길동", "sender_dept": "보안팀", "receiver": "outside@example.net", "send_result": "성공", "mail_process": "결재(승인)", "policy": "외부메일"}]}), encoding="utf-8")
    dlp = tmp_path / "cache/dlp/2026-07-22.jsonl"
    dlp.parent.mkdir(parents=True)
    dlp.write_text(json.dumps({"eventtimelocal": "2026-07-22 13:00:00", "event_id": "Content Threat Blocked", "machine_name": "PC-1", "client_name": "hong", "filename": "contract.pdf", "destination": "USB", "destination_type": "Removable Storage", "item_details": "USB drive"}) + "\n", encoding="utf-8")
    service = ReportService(tmp_path)
    progress = []

    result = service.build(date(2026, 7, 22), date(2026, 7, 28), progress.append)
    output = Path(result["path"])

    assert output.exists()
    assert output.name == "Security_Report_2026-07-22_2026-07-28.pdf"
    assert output.read_bytes().startswith(b"%PDF")
    assert output.stat().st_size > 20_000
    assert progress == ["데이터 로딩 중...", "DLP 분석 중...", "PDF 생성 중...", "저장 완료"]
