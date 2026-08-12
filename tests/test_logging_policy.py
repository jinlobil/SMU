import logging
from datetime import date, timedelta

from backend.logging_config import ConsoleFilter
from backend.services.watchdog_client import WatchdogManager
from system_monitor.logging_utils import daily_file_handler, dated_process_log


def record(name: str, level: int) -> logging.LogRecord:
    return logging.LogRecord(name, level, __file__, 1, "message", (), None)


def test_console_filter_keeps_warnings_and_job_events_only():
    policy = ConsoleFilter()
    assert not policy.filter(record("smu.web", logging.INFO))
    assert policy.filter(record("smu.web", logging.WARNING))
    assert policy.filter(record("smu.job.events", logging.INFO))


def test_daily_handler_uses_midnight_rotation_and_retention(tmp_path):
    handler = daily_file_handler(tmp_path / "web_app.log", retention_days=30)
    try:
        assert handler.when == "MIDNIGHT"
        assert handler.backupCount == 30
        assert handler.suffix == "%Y-%m-%d"
    finally:
        handler.close()


def test_dated_process_log_prunes_expired_files(tmp_path):
    expired = tmp_path / f"indexer_process.{(date.today()-timedelta(days=61)).isoformat()}.log"
    recent = tmp_path / f"indexer_process.{date.today().isoformat()}.log"
    expired.write_text("old", encoding="utf-8")
    recent.write_text("today", encoding="utf-8")

    result = dated_process_log(tmp_path, "indexer_process", retention_days=60)

    assert result == recent
    assert not expired.exists()
    assert recent.exists()


def test_watchdog_manager_reports_each_job_state_once(tmp_path, caplog):
    manager = WatchdogManager(tmp_path)
    with caplog.at_level(logging.INFO, logger="smu.job.events"):
        manager._report_job_state({"id": "job-1", "status": "running"}, "Indexer")
        manager._report_job_state({"id": "job-1", "status": "running"}, "Indexer")
        manager._report_job_state({"id": "job-1", "status": "completed"}, "Indexer")

    messages = [record.message for record in caplog.records]
    assert sum("running" in message for message in messages) == 1
    assert sum("completed" in message for message in messages) == 1
