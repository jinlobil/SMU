import json
from pathlib import Path

from backend.services.organizations import OrganizationService


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def test_organization_rows_match_legacy_shape_and_department_map(tmp_path: Path) -> None:
    write_json(tmp_path / "cache" / "user_groups.json", [{
        "deptCode": "100",
        "deptName": "Original",
        "users": [{"name": "홍길동"}, {"name": "None"}, {"name": "김보안"}],
    }])
    env_path = tmp_path / "env" / "User_group_env.txt"
    env_path.parent.mkdir(parents=True)
    env_path.write_text("100=보안팀\n", encoding="utf-8")

    result = OrganizationService(tmp_path).list_organizations(query="보안", field="deptName")

    assert result["items"] == [
        {"deptCode": "100", "deptName": "보안팀", "user": "김보안"},
        {"deptCode": "100", "deptName": "보안팀", "user": "홍길동"},
    ]
    assert result["summary"] == {"departments": 1, "users": 2}


def test_organization_service_reports_missing_cache(tmp_path: Path) -> None:
    result = OrganizationService(tmp_path).list_organizations()

    assert result["items"] == []
    assert result["source"]["exists"] is False


def test_organization_service_paginates_and_sorts(tmp_path: Path) -> None:
    write_json(tmp_path / "cache" / "user_groups.json", [{
        "deptCode": "200", "deptName": "B", "users": ["User B", "User A", "User C"],
    }])

    result = OrganizationService(tmp_path).list_organizations(page=2, page_size=2, sort="user", direction="asc")

    assert result["pagination"] == {"page": 2, "pageSize": 2, "total": 3, "totalPages": 2}
    assert [row["user"] for row in result["items"]] == ["User C"]
