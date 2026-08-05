import json
import os
import time

import pytest

from datetime import date
from pathlib import Path

from backend.services.detections import DetectionService
from backend.services.event_list_index import EventListIndexUnavailable
from backend.services.indexing import IndexService


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def test_detection_service_normalizes_filters_and_returns_detail(tmp_path: Path) -> None:
    write_json(tmp_path / "cache" / "detections" / "2026-07-22.json", [{
        "time": "2026-07-22T01:00:00Z", "sensor": {"type": "endpoint"},
        "detectionDescription": {"createdReasonId": "Malicious-Rule"},
        "rawData": {"meta_hostname": "PC-1", "meta_ip_address": "10.0.0.1", "meta_public_ip": "1.2.3.4", "process_name": "bad.exe", "process_sha256": "abc"},
    }, {"time": "2026-07-22T02:00:00Z", "sensor": {"type": "email"}}])
    IndexService(tmp_path).rebuild_scope("events", lambda _message: None)
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
    IndexService(tmp_path).rebuild_scope("events", lambda _message: None)
    result = DetectionService(tmp_path).list_detections(date(2026, 7, 22), date(2026, 7, 22), [{"field": "hostname", "query": "PC-1"}, {"field": "file", "query": "missing"}])
    assert result["pagination"]["total"] == 0


def test_detection_list_uses_events_index_when_available(tmp_path: Path) -> None:
    service = IndexService(tmp_path)
    service._build_events_index([
        {"kind": "detections", "recordId": "idx-1", "eventTime": "2026-07-22 09:00:00", "rowJson": json.dumps({"id": "idx-1", "time": "2026-07-22 09:00:00", "hostname": "INDEX-PC", "rule": "Indexed"}), "searchText": "indexed index-pc", "sourceFile": "2026-07-22.json"}
    ])
    detections = DetectionService(tmp_path)
    detections._events = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("raw cache must not be read for list"))

    result = detections.list_detections(date(2026, 7, 22), date(2026, 7, 22), [], 1, 50, "time", "desc")

    assert result["source"]["index"] == "events_index.db"
    assert result["items"][0]["hostname"] == "INDEX-PC"


def test_detection_list_rejects_stale_events_index_without_raw_fallback(tmp_path: Path) -> None:
    source = tmp_path / "cache" / "detections" / "2026-07-23.json"
    write_json(source, [{"time": "2026-07-23T02:00:00Z", "sensor": {"type": "endpoint"}, "rawData": {"meta_hostname": "RAW-PC"}}])
    service = IndexService(tmp_path)
    service._build_events_index([
        {"kind": "detections", "recordId": "old", "eventTime": "2026-07-23 01:00:00", "rowJson": json.dumps({"id": "old", "time": "2026-07-23 01:00:00", "hostname": "STALE-PC"}), "searchText": "stale", "sourceFile": str(source.resolve())}
    ])
    source.write_text(source.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    os.utime(source, (time.time() + 10, time.time() + 10))

    detection_service = DetectionService(tmp_path)
    detection_service._events = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("raw cache must not be read for stale list"))

    with pytest.raises(EventListIndexUnavailable):
        detection_service.list_detections(date(2026, 7, 23), date(2026, 7, 23), [], 1, 50, "time", "desc")
