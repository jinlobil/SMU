from __future__ import annotations

import logging
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
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


def main() -> int:
    log = configure_logging()
    log.info("Starting SMU Web")
    log.info("Persistent log: %s", LOG_PATH)
    if not FRONTEND_INDEX.exists():
        log.error("Frontend build is missing: %s", FRONTEND_INDEX)
        log.error("Run INSTALL_WEB.bat before starting the server.")
        return 2

    try:
        import uvicorn

        browser_thread = threading.Thread(
            target=open_browser_when_ready,
            args=(log,),
            name="browser-readiness",
            daemon=True,
        )
        browser_thread.start()
        uvicorn.run(
            "web_backend.app:app",
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
    raise SystemExit(main())
