import json
import os
import sqlite3
from pathlib import Path
from typing import Callable

from backend.services.sensitive import SensitiveService
from backend.services.timeline import ALL_SOURCES, TimelineService


class IndexService:
    """Builds web-compatible SQLite indexes off-line, then swaps them atomically."""

    def __init__(self, project_root: Path):
        self.root = project_root
        self.directory = project_root / "cache" / "index"
        self.sensitive = SensitiveService(project_root)
        self.timeline = TimelineService(project_root)

    def rebuild_all(self, progress: Callable[[str], None]) -> dict:
        self.directory.mkdir(parents=True, exist_ok=True)
        progress("민감 파일/사이트 인덱스 생성 중")
        files = self.sensitive.file_records({"DLP", "Outbound Mail"})
        sites = self.sensitive.site_records()
        app_path = self._build_sensitive(files, sites)
        progress("통합 타임라인 인덱스 생성 중")
        events = self.timeline.all_events(set(ALL_SOURCES))
        timeline_path = self._build_timeline(events)
        progress(f"전체 캐시 인덱싱 완료 · 민감 {len(files)+len(sites):,}건 / 타임라인 {len(events):,}건")
        return {"sensitive": len(files) + len(sites), "timeline": len(events), "paths": [str(app_path), str(timeline_path)]}

    def _build_sensitive(self, files: list[dict], sites: list[dict]) -> Path:
        final = self.directory / "app_cache.db"; temp = final.with_suffix(".db.tmp")
        temp.unlink(missing_ok=True)
        with sqlite3.connect(temp) as db:
            for table in ("sensitive_files_index", "sensitive_sites_index"):
                db.execute(f"CREATE TABLE {table} (dedupe_key TEXT PRIMARY KEY, source TEXT, category TEXT, event_time TEXT, search_text TEXT, record_json TEXT)")
                db.execute(f"CREATE INDEX idx_{table}_filter ON {table}(source, category, event_time DESC)")
            for table, records in (("sensitive_files_index", files), ("sensitive_sites_index", sites)):
                db.executemany(f"INSERT OR REPLACE INTO {table} VALUES (?,?,?,?,?,?)", [(r["id"], r["source"], r["category"], r["time"], json.dumps(r, ensure_ascii=False).lower(), json.dumps({**r, "row": r.get("raw", r)}, ensure_ascii=False)) for r in records])
        os.replace(temp, final); return final

    def _build_timeline(self, events: list[dict]) -> Path:
        final = self.directory / "timeline_index.db"; temp = final.with_suffix(".db.tmp")
        temp.unlink(missing_ok=True)
        fields = ("time", "source", "user", "userId", "dept", "asset", "event", "direction", "peer", "summary", "indicator")
        with sqlite3.connect(temp) as db:
            db.execute("CREATE TABLE timeline_events (time TEXT, source TEXT, user TEXT, user_id TEXT, dept TEXT, asset TEXT, event TEXT, direction TEXT, peer TEXT, summary TEXT, indicator TEXT)")
            db.execute("CREATE INDEX idx_timeline_time ON timeline_events(time DESC)")
            db.execute("CREATE INDEX idx_timeline_source ON timeline_events(source, time DESC)")
            db.executemany("INSERT INTO timeline_events VALUES (?,?,?,?,?,?,?,?,?,?,?)", [tuple(e.get(k, "") for k in fields) for e in events])
        os.replace(temp, final); return final
