import json
from datetime import date
from pathlib import Path

from backend.services.detections import DetectionService


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def test_detection_service_normalizes_filters_and_returns_detail(tmp_path: Path) -> None:
    write_json(tmp_path / "cache" / "detections" / "2026-07-22.json", [{
        "time": "2026-07-22T01:00:00Z", "sensor": {"type": "endpoint"},
        "detectionDescription": {"createdReasonId": "Malicious-Rule"},
        "rawData": {"meta_hostname": "PC-1", "meta_ip_address": "10.0.0.1", "meta_public_ip": "1.2.3.4", "process_name": "bad.exe", "process_sha256": "abc"},
    }, {"time": "2026-07-22T02:00:00Z", "sensor": {"type": "email"}}])
    service = DetectionService(tmp_path)

    result = service.list_detections(date(2026, 7, 22), date(2026, 7, 22), [{"field": "rule", "query": "malicious"}])

    assert result["pagination"]["total"] == 1
    row = result["items"][0]
    assert row["hostname"] == "PC-1"
    assert row["file"] == "bad.exe"
    assert row["sha256"] == "abc"
    detail = service.get_detection(row["id"], date(2026, 7, 22), date(2026, 7, 22))
    assert detail["raw"]["rawData"]["meta_public_ip"] == "1.2.3.4"


def test_detection_conditions_are_combined_with_and(tmp_path: Path) -> None:
    write_json(tmp_path / "cache" / "detections" / "2026-07-22.json", [{
        "time": "2026-07-22T01:00:00Z", "sensor": {"type": "endpoint"}, "rawData": {"meta_hostname": "PC-1", "process_name": "one.exe"},
    }])
    result = DetectionService(tmp_path).list_detections(date(2026, 7, 22), date(2026, 7, 22), [{"field": "hostname", "query": "PC-1"}, {"field": "file", "query": "missing"}])
    assert result["pagination"]["total"] == 0
