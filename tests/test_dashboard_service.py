import json
import sqlite3
from datetime import date
from pathlib import Path

from backend.services.dashboard import DashboardService


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def write_index_row(root: Path, kind: str, event_time: str, row: dict[str, str], record_id: str = "1") -> None:
    path = root / "cache/index/events_index.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS event_list_rows (
                kind TEXT NOT NULL,
                record_id TEXT NOT NULL,
                event_time TEXT NOT NULL,
                row_json TEXT NOT NULL,
                search_text TEXT NOT NULL,
                source_file TEXT NOT NULL,
                PRIMARY KEY (kind, record_id)
            )
            """
        )
        db.execute("CREATE INDEX IF NOT EXISTS idx_event_list_rows_kind_time ON event_list_rows(kind, event_time)")
        db.execute(
            "INSERT OR REPLACE INTO event_list_rows(kind, record_id, event_time, row_json, search_text, source_file) VALUES (?, ?, ?, ?, ?, ?)",
            (kind, record_id, event_time, json.dumps(row, ensure_ascii=False), " ".join(row.values()), f"cache/{kind}/{event_time[:10]}.json"),
        )


def test_dashboard_summarizes_assets_and_recent_detection_from_event_index(tmp_path: Path) -> None:
    write_json(tmp_path / "cache/endpoints.json", [{"type": "computer"}, {"type": "server"}])
    write_json(tmp_path / "cache/user_groups.json", [{"deptCode": "100", "users": [{"name": "홍길동"}]}])
    write_index_row(tmp_path, "detections", "2026-07-23T01:00:00Z", {"time": "2026-07-23T01:00:00Z", "hostname": "PC-1", "file": "bad.exe", "sha256": "abc", "rule": "Malware Rule"})
    write_index_row(tmp_path, "inbound", "2026-07-23T02:00:00Z", {"received": "2026-07-23T02:00:00Z", "senderIp": "10.0.0.1", "reason": "spam", "to": "a@example.com"}, "2")

    result = DashboardService(tmp_path).summary()

    assert result["endpoints"] == {"pc": 1, "server": 1, "total": 2}
    assert result["organization"] == {"departments": 1, "users": 1}
    assert result["totals"]["Detection - XDR"] == 1
    assert result["totals"]["Inbound Mail"] == 1
    assert result["top"]["hosts"] == [("PC-1", 1)]
    assert result["top"]["senders"] == [("10.0.0.1", 1)]
    assert result["cache"] == "freshly-aggregated"

    cached = DashboardService(tmp_path).summary()
    assert cached["cache"] == "pre-aggregated"


def test_dashboard_accepts_explicit_date_range_without_raw_cache(tmp_path: Path) -> None:
    result = DashboardService(tmp_path).summary(
        start=date(2026, 7, 1),
        end=date(2026, 7, 3),
    )

    assert result["range"] == {"start": "2026-07-01", "end": "2026-07-03"}
    assert result["trend"]["dates"] == ["2026-07-01", "2026-07-02", "2026-07-03"]
    assert all(value == 0 for value in result["totals"].values())


def test_dashboard_comparison_uses_previous_day_and_previous_month_day(tmp_path: Path) -> None:
    result = DashboardService(tmp_path).mix_trend(date(2026, 3, 25), date(2026, 3, 31))

    assert result["comparisonRange"] == {"day": "2026-03-30", "month": "2026-02-28"}
    assert set(result["comparison"]["File"]) == {"day", "month"}


def test_dashboard_group_methods_share_indexed_range_and_payloads(tmp_path: Path) -> None:
    write_index_row(tmp_path, "detections", "2026-08-05 12:22:52", {"time": "2026-08-05 12:22:52", "hostname": "PC-2", "file": "tool.exe", "sha256": "def", "rule": "Rule-A"})

    service = DashboardService(tmp_path)

    assert service.mix_trend()["range"] == {"start": "2026-07-30", "end": "2026-08-05"}
    assert service.top_detection()["top"]["files"] == [("tool.exe", 1)]
    assert service.top_mail()["top"]["senders"] == []
    assert service.top_file()["summary"]["file"][0] == ["Top Machine", []]


def test_dashboard_warms_quick_ranges_into_preaggregate_cache(tmp_path: Path) -> None:
    write_index_row(tmp_path, "detections", "2026-08-05 12:22:52", {"time": "2026-08-05 12:22:52", "hostname": "PC-2", "file": "tool.exe", "sha256": "def", "rule": "Rule-A"})

    service = DashboardService(tmp_path)
    service.warm_quick_ranges()

    cache = json.loads((tmp_path / "cache/index/web_dashboard_summary.json").read_text(encoding="utf-8"))
    assert "2026-08-05:2026-08-05" in cache
    assert "2026-07-30:2026-08-05" in cache
    assert "2026-07-22:2026-08-05" in cache
    assert "2026-07-07:2026-08-05" in cache
    assert service.summary(date(2026, 7, 7), date(2026, 8, 5))["cache"] == "pre-aggregated"
