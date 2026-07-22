from pathlib import Path

import run_local


def test_write_line_creates_persistent_log(tmp_path: Path, monkeypatch) -> None:
    log_dir = tmp_path / "logs"
    launch_log = log_dir / "launcher.log"
    monkeypatch.setattr(run_local, "LOG_DIR", log_dir)
    monkeypatch.setattr(run_local, "LAUNCH_LOG", launch_log)

    run_local.write_line("test failure details")

    assert launch_log.exists()
    assert "test failure details" in launch_log.read_text(encoding="utf-8")

