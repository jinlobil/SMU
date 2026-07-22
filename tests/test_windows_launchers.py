from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_start_launcher_uses_explicit_virtualenv_python() -> None:
    script = (ROOT / "start_local.bat").read_text(encoding="utf-8")

    assert '"%~dp0.venv\\Scripts\\python.exe" "%~dp0run_local.py"' in script
    assert "python run_local.py" not in script
    assert "bootstrap.log" in script
    assert "pause" in script.lower()


def test_setup_launcher_records_setup_failures() -> None:
    script = (ROOT / "setup_local.bat").read_text(encoding="utf-8")

    assert "setup.log" in script
    assert "pip install -r" in script
    assert "npm.cmd install" in script
    assert "pause" in script.lower()
