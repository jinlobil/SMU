import logging
from datetime import date, timedelta
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path


LOG_FORMAT = "%(asctime)s %(levelname)s [%(name)s] %(message)s"


def daily_file_handler(path: Path, *, retention_days: int, level: int = logging.INFO) -> TimedRotatingFileHandler:
    """Create a local-midnight log handler with dated backups."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = TimedRotatingFileHandler(
        path, when="midnight", interval=1, backupCount=retention_days,
        encoding="utf-8", delay=True,
    )
    handler.suffix = "%Y-%m-%d"
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    return handler


def configure_agent_logging(path: Path, *, retention_days: int = 60) -> None:
    """Configure one agent process to write INFO+ into daily files."""
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.INFO)
    root.addHandler(daily_file_handler(path, retention_days=retention_days))


def dated_process_log(log_dir: Path, stem: str, *, retention_days: int = 60) -> Path:
    """Return today's bootstrap-output log and prune older dated files."""
    log_dir.mkdir(parents=True, exist_ok=True)
    cutoff = date.today() - timedelta(days=retention_days)
    for path in log_dir.glob(f"{stem}.????-??-??.log"):
        try:
            stamp = date.fromisoformat(path.name.removeprefix(f"{stem}.").removesuffix(".log"))
            if stamp < cutoff:
                path.unlink()
        except (OSError, ValueError):
            continue
    return log_dir / f"{stem}.{date.today().isoformat()}.log"
