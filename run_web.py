from __future__ import annotations

import logging
import importlib.util
import os
import sys
import threading
import time
import types
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


def ensure_local_package(name: str) -> Path:
    """Register a repository package even when Windows ignores ``sys.path``.

    Some Windows Python/launcher combinations observed in the field imported
    ``run_web.py`` but still failed to resolve sibling packages.  Loading the
    package spec from its absolute path removes that ambient-path dependency.
    """
    package_dir = ROOT / name
    if not package_dir.is_dir():
        raise RuntimeError(f"Required SMU directory is missing: {package_dir}")
    if name in sys.modules:
        return package_dir
    init_file = package_dir / "__init__.py"
    if not init_file.is_file():
        # Git/ZIP tools can omit an empty __init__.py.  Register a standards-
        # compliant namespace package so the real modules remain importable.
        module = types.ModuleType(name)
        module.__file__ = None
        module.__package__ = name
        module.__path__ = [str(package_dir)]
        module.__spec__ = importlib.util.spec_from_loader(name, loader=None, is_package=True)
        sys.modules[name] = module
        return package_dir
    spec = importlib.util.spec_from_file_location(
        name,
        init_file,
        submodule_search_locations=[str(package_dir)],
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load SMU package: {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(name, None)
        raise
    return package_dir


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
    for package_name in ("core", "modules"):
        package_path = ensure_local_package(package_name)
        marker = "regular" if (package_path / "__init__.py").is_file() else "namespace"
        log.info("Local package ready: %s -> %s (%s)", package_name, package_path, marker)

    # Import the deepest reused modules first.  This is an intentional startup
    # audit: missing files or internal imports fail before a browser is opened.
    from core.storage import sqlite_cache  # noqa: F401
    from web_backend import theme_store  # noqa: F401
    from web_backend.app import app

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
    log.info("Startup audit passed: %d required API routes", len(required_routes))
    return app


def main(check_only: bool = False) -> int:
    log = configure_logging()
    log.info("Starting SMU Web")
    log.info("Persistent log: %s", LOG_PATH)
    if not FRONTEND_INDEX.exists():
        log.error("Frontend build is missing: %s", FRONTEND_INDEX)
        log.error("Run INSTALL_WEB.bat before starting the server.")
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
