import json
from datetime import date
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
    assert result["cache"] == "freshly-aggregated"

    cached = DashboardService(tmp_path).summary()
    assert cached["cache"] == "pre-aggregated"


def test_dashboard_accepts_explicit_date_range(tmp_path: Path) -> None:
    write_json(tmp_path / "cache/detections/2026-07-01.json", [])

    result = DashboardService(tmp_path).summary(
        start=date(2026, 7, 1),
        end=date(2026, 7, 3),
    )

    assert result["range"] == {"start": "2026-07-01", "end": "2026-07-03"}
    assert result["trend"]["dates"] == ["2026-07-01", "2026-07-02", "2026-07-03"]
