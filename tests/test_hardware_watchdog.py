import json
from datetime import datetime

from system_monitor.watchdog import HardwareWatchdog
from system_monitor.collector import acquire_singleton


def test_watchdog_reuses_healthy_independent_collector(tmp_path, monkeypatch):
    watchdog = HardwareWatchdog(tmp_path)
    watchdog.directory.mkdir(parents=True)
    status = {"status": "running", "pid": 4321, "lastSampleAt": datetime.now().astimezone().isoformat()}
    watchdog.collector_status.write_text(json.dumps(status), encoding="utf-8")
    monkeypatch.setattr("system_monitor.watchdog.process_alive", lambda pid: pid == 4321)
    restarted = []
    monkeypatch.setattr(watchdog, "restart_collector", lambda: restarted.append(True))

    watchdog.ensure_collector()

    assert restarted == []


def test_fresh_heartbeat_wins_when_windows_pid_probe_is_unavailable(tmp_path, monkeypatch):
    watchdog = HardwareWatchdog(tmp_path)
    watchdog.directory.mkdir(parents=True)
    status = {"status": "running", "pid": 4321, "lastSampleAt": datetime.now().astimezone().isoformat()}
    watchdog.collector_status.write_text(json.dumps(status), encoding="utf-8")
    monkeypatch.setattr("system_monitor.watchdog.process_alive", lambda _pid: False)
    restarted = []
    monkeypatch.setattr(watchdog, "restart_collector", lambda: restarted.append(True))

    watchdog.ensure_collector()

    assert restarted == []


def test_watchdog_restarts_stale_collector(tmp_path, monkeypatch):
    watchdog = HardwareWatchdog(tmp_path)
    watchdog.directory.mkdir(parents=True)
    status = {"status": "running", "pid": 4321, "lastSampleAt": "2020-01-01T00:00:00+00:00"}
    watchdog.collector_status.write_text(json.dumps(status), encoding="utf-8")
    monkeypatch.setattr("system_monitor.watchdog.process_alive", lambda pid: True)
    restarted = []
    monkeypatch.setattr(watchdog, "restart_collector", lambda: restarted.append(True))

    watchdog.ensure_collector()

    assert restarted == [True]


def test_collector_singleton_prevents_duplicate_writer(tmp_path):
    first = acquire_singleton(tmp_path / "collector.lock")
    second = acquire_singleton(tmp_path / "collector.lock")

    assert first is not None
    assert second is None
    first.close()


def test_wait_accepts_existing_healthy_collector_after_spawn_race(tmp_path, monkeypatch):
    watchdog = HardwareWatchdog(tmp_path)
    watchdog.directory.mkdir(parents=True)
    status = {"status": "running", "pid": 9999, "lastSampleAt": datetime.now().astimezone().isoformat()}
    watchdog.collector_status.write_text(json.dumps(status), encoding="utf-8")
    monkeypatch.setattr("system_monitor.watchdog.process_alive", lambda pid: pid == 9999)

    result = watchdog._wait_for_collector(1234, timeout=0.1)

    assert result["pid"] == 9999


def test_process_alive_uses_psutil_on_windows_compatible_path(monkeypatch):
    monkeypatch.setattr("system_monitor.watchdog.psutil.pid_exists", lambda pid: pid == 321)

    assert __import__("system_monitor.watchdog", fromlist=["process_alive"]).process_alive(321) is True
    assert __import__("system_monitor.watchdog", fromlist=["process_alive"]).process_alive(654) is False


def test_restart_count_is_reported_for_collector_not_watchdog(tmp_path):
    watchdog = HardwareWatchdog(tmp_path)
    watchdog.restart_count = 7

    snapshot = watchdog.snapshot()

    assert "restartCount" not in snapshot["watchdog"]
    assert snapshot["collector"]["restartCount"] == 7


def test_watchdog_checks_indexer_health_before_submitting_job(tmp_path, monkeypatch):
    watchdog = HardwareWatchdog(tmp_path)
    calls = []
    monkeypatch.setattr(watchdog, "ensure_indexer", lambda: calls.append("health") or {"status": "running"})
    monkeypatch.setattr(watchdog, "_indexer_request", lambda path, method="GET", timeout=3: calls.append((path, method)) or {"id": "job-1"})

    result = watchdog.submit_index_job()

    assert result["id"] == "job-1"
    assert calls == ["health", ("/jobs", "POST")]


def test_watchdog_retries_transient_indexer_submission_failure(tmp_path, monkeypatch):
    import urllib.error
    watchdog = HardwareWatchdog(tmp_path); calls = []
    monkeypatch.setattr(watchdog, "ensure_indexer", lambda: calls.append("health") or {"status": "running"})
    def request(path, method="GET", timeout=3):
        calls.append(path)
        if calls.count(path) < 2: raise urllib.error.URLError("starting")
        return {"id": "index-after-retry"}
    monkeypatch.setattr(watchdog, "_indexer_request", request)
    monkeypatch.setattr("system_monitor.watchdog.time.sleep", lambda _seconds: None)

    assert watchdog.submit_index_job()["id"] == "index-after-retry"
    assert calls.count("health") == 2


def test_watchdog_snapshot_includes_indexer_status(tmp_path, monkeypatch):
    watchdog = HardwareWatchdog(tmp_path)
    watchdog.indexer_restart_count = 3
    monkeypatch.setattr(watchdog, "read_indexer", lambda: {"status": "running", "pid": 9876})
    monkeypatch.setattr(watchdog, "read_fetcher", lambda: {"status": "running", "pid": 8765})

    snapshot = watchdog.snapshot()

    assert snapshot["indexer"] == {"status": "running", "pid": 9876, "restartCount": 3}
    assert snapshot["fetcher"] == {"status": "running", "pid": 8765, "restartCount": 0}


def test_watchdog_checks_fetcher_health_before_submitting_job(tmp_path, monkeypatch):
    watchdog = HardwareWatchdog(tmp_path); calls = []
    monkeypatch.setattr(watchdog, "ensure_fetcher", lambda: calls.append("health") or {"status": "running"})
    monkeypatch.setattr(watchdog, "_fetcher_request", lambda path, method="GET", timeout=3: calls.append((path, method)) or {"id": "fetch-1"})

    result = watchdog.submit_fetch_job("targets=detections")

    assert result["id"] == "fetch-1"
    assert calls == ["health", ("/jobs?targets=detections", "POST")]
