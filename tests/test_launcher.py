from pathlib import Path
from unittest.mock import Mock

import run_local


def test_write_line_creates_persistent_log(tmp_path: Path, monkeypatch) -> None:
    log_dir = tmp_path / "logs"
    launch_log = log_dir / "launcher.log"
    monkeypatch.setattr(run_local, "LOG_DIR", log_dir)
    monkeypatch.setattr(run_local, "LAUNCH_LOG", launch_log)

    run_local.write_line("test failure details")

    assert launch_log.exists()
    assert "test failure details" in launch_log.read_text(encoding="utf-8")


def test_start_process_uses_supplied_executable(tmp_path: Path, monkeypatch) -> None:
    process = Mock(stdout=None)
    popen = Mock(return_value=process)
    monkeypatch.setattr(run_local.subprocess, "Popen", popen)
    monkeypatch.setattr(run_local.threading.Thread, "start", Mock())
    monkeypatch.setattr(run_local, "LOG_DIR", tmp_path)
    monkeypatch.setattr(run_local, "LAUNCH_LOG", tmp_path / "launcher.log")

    run_local.start_process("frontend", ["C:\\Node\\npm.cmd", "run", "dev"], tmp_path)

    assert popen.call_args.args[0][0] == "C:\\Node\\npm.cmd"
