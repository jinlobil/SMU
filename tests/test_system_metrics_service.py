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
        service.history("2026-01-01", "2026-01-02", "second")
    except ValueError as exc:
        assert "minute, hour, day" in str(exc)
    else:
        raise AssertionError("ValueError was not raised")
