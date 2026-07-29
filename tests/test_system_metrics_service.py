import json
import sys
from datetime import datetime, timedelta
from types import SimpleNamespace

sys.modules.setdefault("psutil", SimpleNamespace(cpu_percent=lambda interval=None: 0.0, virtual_memory=lambda: None))
from backend.services.system_metrics import SystemMetricsService


def sample(timestamp: datetime, cpu: float, memory: float) -> dict:
    return {
        "timestamp": timestamp.astimezone().isoformat(timespec="seconds"),
        "cpuPercent": cpu,
        "memoryPercent": memory,
        "memoryUsedBytes": 50,
        "memoryAvailableBytes": 50,
        "memoryTotalBytes": 100,
    }


def test_history_aggregates_selected_bucket(tmp_path):
    service = SystemMetricsService(tmp_path, autostart=False)
    now = datetime.now().astimezone().replace(second=0, microsecond=0)
    service.directory.mkdir(parents=True)
    rows = [sample(now, 10, 40), sample(now + timedelta(seconds=5), 30, 50)]
    (service.directory / f"{now.date()}.jsonl").write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
    )

    result = service.history(now.isoformat(), (now + timedelta(minutes=1)).isoformat(), "minute")

    assert len(result["points"]) == 1
    assert result["points"][0]["cpu"] == {"average": 20.0, "minimum": 10.0, "maximum": 30.0}
    assert result["points"][0]["memory"]["average"] == 45.0
    assert result["points"][0]["samples"] == 2


def test_history_rejects_unknown_bucket(tmp_path):
    service = SystemMetricsService(tmp_path, autostart=False)

    try:
        service.history("2026-01-01", "2026-01-02", "week")
    except ValueError as exc:
        assert "지원하지 않는 표시 단위" in str(exc)
    else:
        raise AssertionError("ValueError was not raised")


def test_history_preserves_five_second_samples_in_second_bucket(tmp_path):
    service = SystemMetricsService(tmp_path, autostart=False)
    now = datetime.now().astimezone().replace(second=0, microsecond=0)
    service.directory.mkdir(parents=True)
    rows = [sample(now, 10, 40), sample(now + timedelta(seconds=5), 30, 50)]
    (service.directory / f"{now.date()}.jsonl").write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
    )

    result = service.history(now.isoformat(), (now + timedelta(minutes=1)).isoformat(), "second")

    assert [point["cpu"]["average"] for point in result["points"]] == [10.0, 30.0]


def test_history_auto_selects_bucket_below_point_limit(tmp_path):
    service = SystemMetricsService(tmp_path, autostart=False)
    now = datetime.now().astimezone().replace(hour=0, minute=0, second=0, microsecond=0)

    result = service.history(now.isoformat(), (now + timedelta(days=1)).isoformat(), "auto")

    assert result["requestedBucket"] == "auto"
    assert result["bucket"] == "5minute"
    assert result["bucketSeconds"] == 300
    assert result["maxPoints"] == 600


def test_history_rejects_manual_bucket_with_too_many_points(tmp_path):
    service = SystemMetricsService(tmp_path, autostart=False)
    now = datetime.now().astimezone().replace(hour=0, minute=0, second=0, microsecond=0)

    try:
        service.history(now.isoformat(), (now + timedelta(days=1)).isoformat(), "minute")
    except ValueError as exc:
        assert "최대 600개 포인트" in str(exc)
    else:
        raise AssertionError("ValueError was not raised")


def test_current_reads_independent_collector_snapshot(tmp_path):
    service = SystemMetricsService(tmp_path, autostart=False)
    service.directory.mkdir(parents=True)
    current = sample(datetime.now().astimezone(), 22.5, 55.5)
    (service.directory / "collector_status.json").write_text(
        json.dumps({"status": "running", "lastError": None, "sample": current}), encoding="utf-8"
    )

    result = service.current()

    assert result["collector"]["running"] is True
    assert result["sample"]["cpuPercent"] == 22.5
