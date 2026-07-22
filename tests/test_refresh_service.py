import json
from pathlib import Path

from backend.services.refresh import RefreshService


class FakeSophosClient:
    def __init__(self, _path: Path):
        pass

    def fetch_endpoints(self):
        return [{"hostname": "PC-1"}]

    def fetch_organizations(self, _names):
        return ([{"deptCode": "100", "users": []}], [{"name": "User"}])


def test_refresh_service_atomically_saves_endpoint_cache(tmp_path: Path) -> None:
    result = RefreshService(tmp_path, FakeSophosClient).refresh_endpoints(lambda _message: None)

    assert result == {"rows": 1}
    assert json.loads((tmp_path / "cache" / "endpoints.json").read_text(encoding="utf-8")) == [{"hostname": "PC-1"}]


def test_refresh_service_saves_groups_and_users(tmp_path: Path) -> None:
    result = RefreshService(tmp_path, FakeSophosClient).refresh_organizations(lambda _message: None)

    assert result == {"groups": 1, "users": 1}
    assert (tmp_path / "cache" / "user_groups.json").exists()
    assert (tmp_path / "cache" / "users.json").exists()
