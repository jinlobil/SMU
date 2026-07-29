import json
from datetime import datetime

from system_monitor.watchdog import HardwareWatchdog


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
