from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_start_launcher_uses_explicit_virtualenv_python() -> None:
    raw = (ROOT / "start_local.bat").read_bytes()
    script = raw.decode("ascii")

    assert '"%~dp0.venv\\Scripts\\python.exe" "%~dp0run_local.py"' in script
    assert "python run_local.py" not in script
    assert "bootstrap.log" in script
    assert "pause" in script.lower()
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
