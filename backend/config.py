from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_DIR = PROJECT_ROOT / "runtime"
LOG_DIR = RUNTIME_DIR / "logs"
WEB_ERROR_LOG = LOG_DIR / "web_errors.log"
WEB_APP_LOG = LOG_DIR / "web_app.log"


def ensure_runtime_directories() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)

