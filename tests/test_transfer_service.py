import json
from datetime import date
from pathlib import Path

from backend.services.transfers import TransferService


def test_dlp_and_outbound_normalization_and_exclusion(tmp_path: Path):
    dlp = tmp_path / "cache/dlp/2026-07-22.jsonl"; dlp.parent.mkdir(parents=True); dlp.write_text(json.dumps({"event_id": "Content Threat Blocked", "machine_name": "PC", "filename": "secret.txt", "destination": "USB"}) + "\n", encoding="utf-8")
    outbound = tmp_path / "cache/mailscreen/mailscreen_mail_2026-07-22.json"; outbound.parent.mkdir(parents=True); outbound.write_text(json.dumps({"items": [{"date": "2026-07-22", "sender": "sender@example.com", "receiver": "to@example.com", "send_result": "성공"}]}), encoding="utf-8")
    service = TransferService(tmp_path)
    dlp_result = service.list_records("dlp", date(2026, 7, 22), date(2026, 7, 22), [{"field": "source", "mode": "include", "query": "secret"}], 1, 50, "time", "desc")
    outbound_result = service.list_records("outbound", date(2026, 7, 22), date(2026, 7, 22), [{"field": "sendResult", "mode": "exclude", "query": "실패"}], 1, 50, "date", "desc")
    assert dlp_result["items"][0]["event"] == "차단"
    assert outbound_result["items"][0]["senderEmail"] == "sender@example.com"
