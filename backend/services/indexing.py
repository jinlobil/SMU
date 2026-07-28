import json
import sqlite3
from pathlib import Path
from typing import Callable

from backend.services.dashboard import DashboardService
from backend.services.sensitive import SensitiveService, normalized_identity
from backend.services.timeline import ALL_SOURCES, TimelineService


class IndexService:
    """Rebuilds web indexes with transactional table swaps safe for Windows readers."""

    def __init__(self, project_root: Path):
        self.root = project_root
        self.directory = project_root / "cache" / "index"
        self.sensitive = SensitiveService(project_root)
        self.timeline = TimelineService(project_root)
        self.dashboard = DashboardService(project_root)

    @staticmethod
    def _connect(path: Path) -> sqlite3.Connection:
        connection = sqlite3.connect(path, timeout=60)
        connection.execute("PRAGMA busy_timeout=60000")
        return connection

    def rebuild_all(self, progress: Callable[[str], None]) -> dict:
        self.directory.mkdir(parents=True, exist_ok=True)
        self._remove_legacy_temp_files(progress)
        progress("민감 파일 후보 계산 중")
        files = self.sensitive.file_records({"DLP", "Outbound Mail"})
        progress("민감 사이트 후보 계산 중")
        sites = self.sensitive.site_records()
        progress("민감 파일/사이트 SQLite 반영 중")
        app_path = self._build_sensitive(files, sites)
        progress("통합 타임라인 이벤트 계산 중")
        events = self.timeline.all_events(set(ALL_SOURCES))
        progress("통합 타임라인 SQLite 반영 중")
        timeline_path = self._build_timeline(events)
        progress("Dashboard 기본 기간 사전 집계 중")
        self.dashboard.warm_default()
        progress(f"전체 캐시 인덱싱 완료 · 민감 {len(files)+len(sites):,}건 / 타임라인 {len(events):,}건")
        return {"sensitive": len(files) + len(sites), "timeline": len(events), "dashboard": True, "paths": [str(app_path), str(timeline_path)]}

    def _remove_legacy_temp_files(self, progress: Callable[[str], None]) -> None:
        """Remove abandoned whole-database temp files from the old indexer."""
        for name in ("app_cache.db.tmp", "timeline_index.db.tmp"):
            path = self.directory / name
            if not path.exists():
                continue
            try:
                path.unlink()
                progress(f"이전 실패 임시 파일 정리: {name}")
            except OSError as error:
                # A stale file is not used by the transactional table-swap
                # indexer, so cleanup failure must not stop a valid rebuild.
                progress(f"이전 임시 파일 정리 보류: {name} ({error})")

    def _build_sensitive(self, files: list[dict], sites: list[dict]) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True)
        final = self.directory / "app_cache.db"
        with self._connect(final) as db:
            for table, records in (("sensitive_files_index", files), ("sensitive_sites_index", sites)):
                latest_records: dict[str, dict] = {}
                for record in records:
                    key = self._sensitive_key(table, record)
                    if key not in latest_records or str(record.get("time", "")) > str(latest_records[key].get("time", "")):
                        latest_records[key] = record
                staging = f"{table}_web_next"
                db.execute(f"DROP TABLE IF EXISTS {staging}")
                db.execute(f"CREATE TABLE {staging} (dedupe_key TEXT PRIMARY KEY, source TEXT, category TEXT, event_time TEXT, search_text TEXT, record_json TEXT)")
                db.executemany(
                    f"INSERT OR REPLACE INTO {staging} VALUES (?,?,?,?,?,?)",
                    [(key, r["source"], r["category"], r["time"], json.dumps(r, ensure_ascii=False).lower(), json.dumps({**r, "row": r.get("raw", r)}, ensure_ascii=False)) for key, r in latest_records.items()],
                )
                db.execute(f"DROP TABLE IF EXISTS {table}")
                db.execute(f"ALTER TABLE {staging} RENAME TO {table}")
                db.execute(f"CREATE INDEX idx_web_{table}_filter ON {table}(source, category, event_time DESC)")
        return final

    @staticmethod
    def _sensitive_key(table: str, record: dict) -> str:
        """Use the same semantic primary key as the desktop indexes."""
        subject = record.get("name") if table == "sensitive_files_index" else record.get("site")
        return "|".join((normalized_identity(record.get("source")), normalized_identity(subject),
                         normalized_identity(record.get("dept")), normalized_identity(record.get("user"))))

    def _build_timeline(self, events: list[dict]) -> Path:
        final = self.directory / "timeline_index.db"
        fields = ("time", "source", "user", "userId", "dept", "asset", "event", "direction", "peer", "summary", "indicator")
        staging = "timeline_events_web_next"
        with self._connect(final) as db:
            db.execute(f"DROP TABLE IF EXISTS {staging}")
            db.execute(f"CREATE TABLE {staging} (time TEXT, source TEXT, user TEXT, user_id TEXT, dept TEXT, asset TEXT, event TEXT, direction TEXT, peer TEXT, summary TEXT, indicator TEXT, raw_json TEXT)")
            db.executemany(f"INSERT INTO {staging} VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", [tuple(event.get(key, "") for key in fields) + (json.dumps(event.get("raw", {}), ensure_ascii=False),) for event in events])
            db.execute("DROP TABLE IF EXISTS timeline_events")
            db.execute(f"ALTER TABLE {staging} RENAME TO timeline_events")
            db.execute("CREATE INDEX idx_web_timeline_time ON timeline_events(time DESC)")
            db.execute("CREATE INDEX idx_web_timeline_source ON timeline_events(source, time DESC)")
        return final
