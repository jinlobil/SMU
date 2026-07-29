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
    monkeypatch.setattr(watchdog, "prune_duplicate_collectors", lambda pid: None)
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


def test_watchdog_prunes_duplicate_collectors(tmp_path, monkeypatch):
    watchdog = HardwareWatchdog(tmp_path)
    monkeypatch.setattr(watchdog, "collector_pids", lambda: [100, 200, 300])
    stopped = []
    monkeypatch.setattr("system_monitor.watchdog.os.kill", lambda pid, _signal: stopped.append(pid))

    watchdog.prune_duplicate_collectors(200)

    assert stopped == [100, 300]


def test_process_alive_uses_psutil_on_windows_compatible_path(monkeypatch):
    monkeypatch.setattr("system_monitor.watchdog.psutil.pid_exists", lambda pid: pid == 321)

    assert __import__("system_monitor.watchdog", fromlist=["process_alive"]).process_alive(321) is True
    assert __import__("system_monitor.watchdog", fromlist=["process_alive"]).process_alive(654) is False
