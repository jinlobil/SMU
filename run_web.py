from __future__ import annotations

import logging
import os
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
# Windows can launch a .bat file with System32 or another folder as the process
# working directory.  Make application imports independent of that directory.
os.chdir(ROOT)
root_text = str(ROOT)
if root_text in sys.path:
    sys.path.remove(root_text)
sys.path.insert(0, root_text)
FRONTEND_INDEX = ROOT / "web_frontend" / "dist" / "index.html"
LOG_DIR = ROOT / "logs"
LOG_PATH = LOG_DIR / "web_server.log"
URL = "http://127.0.0.1:8000"


def configure_logging() -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    file_handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
    file_handler.setFormatter(formatter)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logging.basicConfig(
        level=logging.INFO,
        handlers=[file_handler, console_handler],
        force=True,
    )
    return logging.getLogger("smu.web.launcher")


def open_browser_when_ready(log: logging.Logger, attempts: int = 60) -> None:
    health_url = f"{URL}/api/health"
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(health_url, timeout=1) as response:
                if response.status == 200:
                    log.info("Server is ready; opening %s", URL)
                    webbrowser.open(URL)
                    return
        except OSError:
            time.sleep(0.5)
    log.error("Server did not become ready. Review %s", LOG_PATH)


def load_web_app(log: logging.Logger):
    # Import shared backend layers and the web adapter before opening a browser.
    from core.storage import sqlite_cache  # noqa: F401
    from modules.dlp import formatters  # noqa: F401
    from web_backend import theme_store  # noqa: F401
    from web_backend.app import app
    from web_backend.release import RELEASE

    required_routes = {
        "/api/health",
        "/api/overview",
        "/api/records/{source}",
        "/api/theme",
        "/api/jobs/reindex",
        "/api/jobs/{job_id}",
    }
    available_routes = {getattr(route, "path", "") for route in app.routes}
    missing_routes = required_routes - available_routes
    if missing_routes:
        raise RuntimeError(f"Web API startup audit failed; missing routes: {sorted(missing_routes)}")
    log.info("Startup audit passed: release=%s, %d required API routes", RELEASE, len(required_routes))
    return app


def main(check_only: bool = False) -> int:
    log = configure_logging()
    log.info("Starting SMU Web")
    log.info("Persistent log: %s", LOG_PATH)
    from web_backend.release import RELEASE, audit_bundle

    log.info("Release: %s", RELEASE)
    missing_files = audit_bundle(ROOT, require_build=True)
    if missing_files:
        for missing in missing_files:
            log.error("Required release file is missing: %s", ROOT / missing)
        log.error("Download a complete current ZIP and run INSTALL_WEB.bat.")
        return 2

    try:
        import uvicorn
        app = load_web_app(log)
        if check_only:
            log.info("SMU Web preflight check completed successfully")
            return 0

        browser_thread = threading.Thread(
            target=open_browser_when_ready,
            args=(log,),
            name="browser-readiness",
            daemon=True,
        )
        browser_thread.start()
        uvicorn.run(
            app,
            host="127.0.0.1",
            port=8000,
            reload=False,
            log_config=None,
            access_log=True,
        )
        log.info("SMU Web stopped normally")
        return 0
    except Exception:
        log.exception("SMU Web failed to start")
        log.error("Open this file for the complete error: %s", LOG_PATH)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(check_only="--check" in sys.argv[1:]))
