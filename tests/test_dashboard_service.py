import json
from pathlib import Path

from backend.services.dashboard import DashboardService


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def test_dashboard_summarizes_assets_and_recent_detection(tmp_path: Path) -> None:
    write_json(tmp_path / "cache/endpoints.json", [{"type": "computer"}, {"type": "server"}])
    write_json(tmp_path / "cache/user_groups.json", [{"deptCode": "100", "users": [{"name": "홍길동"}]}])
    write_json(tmp_path / "cache/detections/2026-07-23.json", [{
        "time": "2026-07-23T01:00:00Z", "sensor": {"type": "endpoint"},
        "detectionDescription": {"createdReasonId": "Malware Rule"},
        "rawData": {"meta_hostname": "PC-1", "process_name": "bad.exe", "sha256": "abc"},
    }])

    result = DashboardService(tmp_path).summary()

    assert result["endpoints"] == {"pc": 1, "server": 1, "total": 2}
    assert result["organization"] == {"departments": 1, "users": 1}
    assert result["totals"]["Detection - XDR"] == 1
    assert result["top"]["hosts"] == [("PC-1", 1)]
