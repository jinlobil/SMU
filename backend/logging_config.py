import logging

from backend.config import WEB_APP_LOG, WEB_ERROR_LOG, ensure_runtime_directories
from system_monitor.logging_utils import daily_file_handler


class ConsoleFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno >= logging.WARNING or record.name == "smu.job.events"


def configure_logging() -> None:
    """Configure persistent application and error logs once per process."""
    ensure_runtime_directories()
    root = logging.getLogger()
    if getattr(root, "_smu_web_configured", False):
        return

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s [%(name)s] %(message)s"
    )
    app_handler = daily_file_handler(WEB_APP_LOG, retention_days=30)

    error_handler = daily_file_handler(WEB_ERROR_LOG, retention_days=90, level=logging.ERROR)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(formatter)
    stream_handler.addFilter(ConsoleFilter())

    root.setLevel(logging.INFO)
    root.addHandler(app_handler)
    root.addHandler(error_handler)
    root.addHandler(stream_handler)
    root._smu_web_configured = True
