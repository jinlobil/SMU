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
