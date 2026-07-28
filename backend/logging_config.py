import logging
from logging.handlers import RotatingFileHandler

from backend.config import WEB_APP_LOG, WEB_ERROR_LOG, ensure_runtime_directories


def configure_logging() -> None:
    """Configure persistent application and error logs once per process."""
    ensure_runtime_directories()
    root = logging.getLogger()
    if getattr(root, "_smu_web_configured", False):
        return

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s [%(name)s] %(message)s"
    )
    app_handler = RotatingFileHandler(
        WEB_APP_LOG, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    app_handler.setLevel(logging.INFO)
    app_handler.setFormatter(formatter)

    error_handler = RotatingFileHandler(
        WEB_ERROR_LOG, maxBytes=10 * 1024 * 1024, backupCount=10, encoding="utf-8"
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(formatter)

    root.setLevel(logging.INFO)
    root.addHandler(app_handler)
    root.addHandler(error_handler)
    root.addHandler(stream_handler)
    root._smu_web_configured = True

