import json
from datetime import date
from pathlib import Path

from backend.services.email_security import EmailSecurityService


def write_json(path: Path, payload: object):
    path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(payload), encoding="utf-8")


def test_xdr_and_inbound_records_are_normalized(tmp_path: Path):
    write_json(tmp_path / "cache/detections/2026-07-22.json", [{"time": "2026-07-22T00:00:00Z", "sensor": {"type": "email"}, "detectionDescription": {"createdReasonId": "XDR-sophos-email-virus"}, "rawData": {"raw": json.dumps({"mailboxAddress": "user@example.com", "mailFrom": "bad@example.net", "attachments": [{"name": "bad.zip", "checksum": "sha"}]})}}])
    write_json(tmp_path / "cache/emails/2026-07-22.json", [{"receivedAt": "2026-07-22T00:00:00Z", "from": {"localAddress": "sender", "domainAddress": "test.com"}, "to": [{"localAddress": "one", "domainAddress": "example.com"}, {"localAddress": "two", "domainAddress": "example.com"}], "subject": "hello"}])
    service = EmailSecurityService(tmp_path)
    xdr = service.list_records("xdr", date(2026, 7, 22), date(2026, 7, 22), [{"field": "iocSha256", "query": "sha"}], 1, 50, "time", "desc")
    inbound = service.list_records("inbound", date(2026, 7, 22), date(2026, 7, 22), [], 1, 50, "received", "desc")
    assert xdr["items"][0]["ioc"] == "bad.zip"
    assert inbound["pagination"]["total"] == 2
    assert {row["to"] for row in inbound["items"]} == {"one@example.com", "two@example.com"}
