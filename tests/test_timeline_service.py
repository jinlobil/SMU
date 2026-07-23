import json
from pathlib import Path

from backend.services.timeline import TimelineService


def test_timeline_search_groups_sources_and_filters_identity(tmp_path: Path):
    path = tmp_path / "cache/detections/2026-07-22.json"; path.parent.mkdir(parents=True); path.write_text(json.dumps([{"time": "2026-07-22T01:01:10Z", "sensor": {"type": "endpoint"}, "detectionDescription": {"createdReasonId": "Rule"}, "rawData": {"meta_hostname": "PC-1", "process_name": "bad.exe"}}, {"time": "2026-07-22T01:01:30Z", "sensor": {"type": "endpoint"}, "detectionDescription": {"createdReasonId": "Rule"}, "rawData": {"meta_hostname": "PC-1", "process_name": "bad.exe"}}]), encoding="utf-8")
    result = TimelineService(tmp_path).search("PC-1", "bad.exe", {"Detection"})
    assert result["pagination"]["totalEvents"] == 2
    assert result["pagination"]["totalGroups"] == 1
    assert result["groups"][0]["count"] == 2
