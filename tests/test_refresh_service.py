import json
from datetime import date
from pathlib import Path

from backend.services.refresh import RefreshService


class FakeSophosClient:
    def __init__(self, _path: Path):
        pass

    def fetch_endpoints(self):
        return [{"hostname": "PC-1"}]

    def fetch_organizations(self, _names):
        return ([{"deptCode": "100", "users": []}], [{"name": "User"}])

    def fetch_detections(self, _start, _end, _progress):
        return [{"time": "2026-07-21T15:30:00Z", "id": "detection"}]

    def fetch_inbound_emails(self, _start, _end, _progress):
        return [{"receivedAt": "2026-07-21T16:00:00Z", "id": "email"}]


def test_refresh_service_atomically_saves_endpoint_cache(tmp_path: Path) -> None:
    result = RefreshService(tmp_path, FakeSophosClient).refresh_endpoints(lambda _message: None)

    assert result == {"rows": 1}
    assert json.loads((tmp_path / "cache" / "endpoints.json").read_text(encoding="utf-8")) == [{"hostname": "PC-1"}]


def test_refresh_service_saves_groups_and_users(tmp_path: Path) -> None:
    result = RefreshService(tmp_path, FakeSophosClient).refresh_organizations(lambda _message: None)

    assert result == {"groups": 1, "users": 1}
    assert (tmp_path / "cache" / "user_groups.json").exists()
    assert (tmp_path / "cache" / "users.json").exists()


def test_range_refresh_buckets_records_by_kst_day(tmp_path: Path) -> None:
    service = RefreshService(tmp_path, FakeSophosClient)
    detection = service.refresh_detections(date(2026, 7, 22), date(2026, 7, 22), lambda _message: None)
    inbound = service.refresh_inbound(date(2026, 7, 22), date(2026, 7, 22), lambda _message: None)
    assert detection["days"] == {"2026-07-22": 1}
    assert inbound["days"] == {"2026-07-22": 1}
    assert (tmp_path / "cache/detections/2026-07-22.json").exists()
    assert (tmp_path / "cache/emails/2026-07-22.json").exists()

def test_dlp_and_outbound_ranges_run_each_day(tmp_path, monkeypatch):
    service = RefreshService(tmp_path)
    dlp_days=[];outbound_days=[]
    monkeypatch.setattr(service,"refresh_dlp",lambda day,progress: dlp_days.append(day) or {"count":2})
    monkeypatch.setattr(service,"refresh_outbound",lambda day,progress: outbound_days.append(day) or {"count":3})
    start=date(2026,7,24);end=date(2026,7,26)
    assert service.refresh_dlp_range(start,end,lambda _message:None)["rows"]==6
    assert service.refresh_outbound_range(start,end,lambda _message:None)["rows"]==9
    assert dlp_days==outbound_days==[date(2026,7,24),date(2026,7,25),date(2026,7,26)]

def test_dlp_range_continues_after_a_failed_day(tmp_path, monkeypatch):
    service=RefreshService(tmp_path);attempted=[]
    def refresh(day,progress):
        attempted.append(day)
        if day==date(2026,7,25): raise RuntimeError("login failed")
        return {"count":1}
    monkeypatch.setattr(service,"refresh_dlp",refresh)
    import pytest
    with pytest.raises(RuntimeError,match="2026-07-25"):
        service.refresh_dlp_range(date(2026,7,24),date(2026,7,26),lambda _message:None)
    assert attempted==[date(2026,7,24),date(2026,7,25),date(2026,7,26)]
