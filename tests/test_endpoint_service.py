import json
from pathlib import Path

from backend.services.endpoints import EndpointService


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def test_endpoint_list_matches_legacy_fields_and_search(tmp_path: Path) -> None:
    write_json(tmp_path / "cache" / "endpoints.json", [{
        "hostname": "PC-001",
        "associatedPerson": {"name": "홍길동", "viaLogin": "DOMAIN\\hong"},
        "ipv4Addresses": ["10.0.0.7"],
        "lastSeenAt": "2026-07-21T23:30:00Z",
    }])
    write_json(tmp_path / "cache" / "user_groups.json", [{
        "deptCode": "100",
        "deptName": "Security",
        "users": [{"name": "홍길동"}],
    }])
    write_json(tmp_path / "cache" / "users.json", [])

    result = EndpointService(tmp_path).list_endpoints(query="10.0.0", field="ip")

    assert result["pagination"]["total"] == 1
    assert result["items"] == [{
        "id": "endpoint-0",
        "hostname": "PC-001",
        "userId": "hong",
        "user": "홍길동",
        "dept": "Security",
        "ip": "10.0.0.7",
        "lastSeen": "2026-07-22 08:30:00",
    }]


def test_endpoint_list_reports_missing_cache(tmp_path: Path) -> None:
    result = EndpointService(tmp_path).list_endpoints()

    assert result["items"] == []
    assert result["source"]["exists"] is False


def test_endpoint_list_paginates_and_sorts(tmp_path: Path) -> None:
    write_json(tmp_path / "cache" / "endpoints.json", [
        {"hostname": "PC-B"}, {"hostname": "PC-A"}, {"hostname": "PC-C"},
    ])

    result = EndpointService(tmp_path).list_endpoints(page=2, page_size=2, sort="hostname")

    assert result["pagination"] == {"page": 2, "pageSize": 2, "total": 3, "totalPages": 2}
    assert [row["hostname"] for row in result["items"]] == ["PC-C"]


def test_endpoint_detail_returns_summary_and_raw_cache_row(tmp_path: Path) -> None:
    write_json(tmp_path / "cache" / "endpoints.json", [{
        "id": "endpoint-id", "hostname": "PC-DETAIL", "health": {"overall": "good"},
    }])

    result = EndpointService(tmp_path).get_endpoint("endpoint-id")

    assert result is not None
    assert result["summary"]["hostname"] == "PC-DETAIL"
    assert result["raw"]["health"] == {"overall": "good"}
