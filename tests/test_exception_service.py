import json
from datetime import date

import pytest

from backend.services.detections import DetectionService
from backend.services.endpoints import EndpointService
from backend.services.exceptions import ExceptionService
from backend.services.indexing import IndexService


def write_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def test_user_exception_requires_and_matches_full_principal(tmp_path):
    service = ExceptionService(tmp_path)
    with pytest.raises(ValueError, match="PREFIX"):
        service.save("users", {"principal": "mac", "displayName": "잘못된 사용자"})

    service.save("users", {"principal": r"HONGJEHEE\mac", "displayName": "홍지희"})

    assert service.resolve_user(r"HONGJEHEE\mac", "mac") == "홍지희"
    assert service.resolve_user(r"OTHER-PC\mac", "mac") == "mac"
    assert service.resolve_user("mac", "mac") == "mac"


def test_department_exception_is_the_final_override_by_specificity(tmp_path):
    service = ExceptionService(tmp_path)
    service.save("departments", {"matchType": "userName", "matchValue": "홍지희", "department": "공통지원팀"})
    service.save("departments", {"matchType": "hostname", "matchValue": "HONGJEHEE", "department": "IT팀"})
    service.save("departments", {"matchType": "principal", "matchValue": r"HONGJEHEE\mac", "department": "디자인팀"})

    result = service.finalize(principal=r"HONGJEHEE\mac", hostname="HONGJEHEE", user_name="홍지희", department="기본부서")

    assert result["dept"] == "디자인팀"


def test_legacy_department_file_migrates_as_auto_without_modifying_source(tmp_path):
    legacy = tmp_path / "env/Report_exception_List.txt"
    legacy.parent.mkdir(parents=True)
    original = "SOHNGAYOUNG=디자인팀\nkyoungwon.heo=디자인팀\n"
    legacy.write_text(original, encoding="utf-8")

    data = ExceptionService(tmp_path).list("departments")

    assert [item["matchType"] for item in data["items"]] == ["auto", "auto"]
    assert legacy.read_text(encoding="utf-8") == original


def test_endpoint_applies_exceptions_only_to_processed_summary_and_keeps_raw(tmp_path):
    raw = {"id": "endpoint-1", "hostname": "HONGJEHEE", "associatedPerson": {"name": "mac", "viaLogin": r"HONGJEHEE\mac"}}
    write_json(tmp_path / "cache/endpoints.json", [raw])
    write_json(tmp_path / "cache/user_groups.json", [])
    write_json(tmp_path / "cache/users.json", [])
    exceptions = ExceptionService(tmp_path)
    exceptions.save("users", {"principal": r"HONGJEHEE\mac", "displayName": "홍지희"})
    exceptions.save("departments", {"matchType": "principal", "matchValue": r"HONGJEHEE\mac", "department": "디자인팀"})

    result = EndpointService(tmp_path).get_endpoint("endpoint-1")

    assert result["summary"]["user"] == "홍지희"
    assert result["summary"]["dept"] == "디자인팀"
    assert result["raw"] == raw
    assert json.loads((tmp_path / "cache/endpoints.json").read_text(encoding="utf-8"))[0] == raw


def test_duplicate_rules_are_rejected_and_delete_is_atomic(tmp_path):
    service = ExceptionService(tmp_path)
    first = service.save("users", {"principal": r"PC-1\local", "displayName": "사용자1"})
    with pytest.raises(ValueError, match="이미 존재"):
        service.save("users", {"principal": r"pc-1\LOCAL", "displayName": "사용자2"})

    service.delete("users", first["id"])

    assert service.list("users")["items"] == []


def test_repeated_resolution_uses_cached_rule_file(tmp_path, monkeypatch):
    service = ExceptionService(tmp_path)
    service.save("users", {"principal": r"PC-1\local", "displayName": "사용자1"})
    original_read_text = type(service.user_path).read_text
    reads = 0

    def counted_read_text(path, *args, **kwargs):
        nonlocal reads
        if path == service.user_path:
            reads += 1
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(type(service.user_path), "read_text", counted_read_text)
    for _ in range(100):
        assert service.resolve_user(r"PC-1\local", "local") == "사용자1"

    assert reads == 0


def test_repeated_department_resolution_uses_compiled_lookup(tmp_path, monkeypatch):
    service = ExceptionService(tmp_path)
    service.save("departments", {"matchType": "hostname", "matchValue": "PC-1", "department": "보안팀"})
    normalized_calls = 0
    original = __import__("backend.services.exceptions", fromlist=["normalize_identity"]).normalize_identity

    def counted(value):
        nonlocal normalized_calls
        normalized_calls += 1
        return original(value)

    monkeypatch.setattr("backend.services.exceptions.normalize_identity", counted)
    for _ in range(100):
        assert service.resolve_department(hostname="PC-1") == "보안팀"

    assert normalized_calls < 510


def test_detection_prefers_hostname_principal_over_os_generated_via_login(tmp_path):
    raw_endpoint = {
        "id": "endpoint-1",
        "hostname": "DEVICE-01",
        "associatedPerson": {
            "name": r"DEVICE-01\account",
            "viaLogin": r"Operating System Device\account",
        },
    }
    write_json(tmp_path / "cache/endpoints.json", [raw_endpoint])
    write_json(tmp_path / "cache/user_groups.json", [])
    write_json(tmp_path / "cache/users.json", [])
    write_json(tmp_path / "cache/detections/2026-07-31.json", [{
        "time": "2026-07-31T01:00:00Z",
        "sensor": {"type": "endpoint"},
        "rawData": {"meta_hostname": "DEVICE-01", "process_name": "sample.exe"},
    }])
    ExceptionService(tmp_path).save("users", {
        "principal": r"DEVICE-01\account",
        "displayName": "표시 사용자",
    })
    IndexService(tmp_path).rebuild_scope("events", lambda _message: None)

    result = DetectionService(tmp_path).list_detections(
        date(2026, 7, 31), date(2026, 7, 31), []
    )

    assert result["items"][0]["username"] == "표시 사용자"
    assert json.loads((tmp_path / "cache/endpoints.json").read_text(encoding="utf-8")) == [raw_endpoint]
