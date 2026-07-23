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


def test_wait_for_service_reports_ready_without_delay(monkeypatch) -> None:
    process = Mock()
    process.poll.return_value = None
    response = Mock(status=200)
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(run_local.urllib.request, "urlopen", Mock(return_value=response))

    assert run_local.wait_for_service("http://127.0.0.1:8765/api/health", process, "backend") is True


def test_wait_for_service_fails_fast_when_process_exits() -> None:
    process = Mock()
    process.poll.return_value = 3

    try:
        run_local.wait_for_service("http://127.0.0.1:8765/api/health", process, "backend")
    except RuntimeError as error:
        assert "backend process exited during startup" in str(error)
    else:
        raise AssertionError("Expected early backend exit to raise RuntimeError")
