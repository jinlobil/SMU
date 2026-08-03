from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_start_launcher_uses_explicit_virtualenv_python() -> None:
    raw = (ROOT / "start_local.bat").read_bytes()
    script = raw.decode("ascii")

    assert '"%~dp0.venv\\Scripts\\python.exe" "%~dp0run_local.py"' in script
    assert "python run_local.py" not in script
    assert "bootstrap.log" in script
    assert 'import fastapi,psutil,uvicorn' in script
    assert "pause" in script.lower()
    assert "browser will open" not in script.lower()
    assert all(byte < 128 for byte in raw)
    assert b"\r\n" in raw


def test_setup_launcher_records_setup_failures() -> None:
    raw = (ROOT / "setup_local.bat").read_bytes()
    script = raw.decode("ascii")

    assert "setup.log" in script
    assert "pip install -r" in script
    assert "npm.cmd install" in script
    assert "pause" in script.lower()
    assert all(byte < 128 for byte in raw)
    assert b"\r\n" in raw


def test_stop_monitor_launcher_only_targets_monitor_modules() -> None:
    raw = (ROOT / "stop_system_monitor.bat").read_bytes()
    script = raw.decode("ascii")

    assert "system_monitor[.]watchdog" in script
    assert "system_monitor[.]collector" in script
    assert "system_monitor[.]fetcher" in script
    assert "system_monitor[.]indexer" in script
    assert "Stop-Process" in script
    assert "uvicorn" not in script
    assert all(byte < 128 for byte in raw)
    assert b"\r\n" in raw
    assert b"\n" not in raw.replace(b"\r\n", b"")


def test_python_launcher_does_not_open_a_browser() -> None:
    script = (ROOT / "run_local.py").read_text(encoding="utf-8")

    assert "import webbrowser" not in script
    assert "webbrowser.open" not in script
    assert "open_browser_when_ready" not in script
    assert '"--no-access-log"' in script
