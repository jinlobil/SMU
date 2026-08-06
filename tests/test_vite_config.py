from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_vite_uses_polling_to_avoid_windows_locked_file_crashes() -> None:
    config = (ROOT / "frontend/vite.config.ts").read_text(encoding="utf-8")

    assert "watch:" in config
    assert "usePolling: true" in config
    assert "interval: 1000" in config
