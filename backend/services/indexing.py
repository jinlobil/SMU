import json
import os
import re
import sqlite3
from datetime import date, timedelta
from pathlib import Path
from typing import Callable

from backend.services.dashboard import DashboardService
from backend.services.detections import DetectionService
from backend.services.email_security import EmailSecurityService
from backend.services.event_list_schema import DISPLAY_COLUMNS, SCHEMA_VERSION, values_for_row
from backend.services.sensitive import SensitiveService, normalized_identity
from backend.services.timeline import ALL_SOURCES, TimelineService
from backend.services.transfers import TransferService


class IndexService:
    """Rebuilds web indexes with transactional table swaps safe for Windows readers."""

    def __init__(self, project_root: Path):
        self.root = project_root
        self.directory = project_root / "cache" / "index"
        self.manifest_path = self.directory / "web_index_manifest.json"
        self.sensitive = SensitiveService(project_root)
        self.timeline = TimelineService(project_root)
        self.dashboard = DashboardService(project_root)
        self.detections = DetectionService(project_root)
        self.email = EmailSecurityService(project_root)
        self.transfers = TransferService(project_root)

    @staticmethod
    def _connect(path: Path) -> sqlite3.Connection:
        connection = sqlite3.connect(path, timeout=60)
        connection.execute("PRAGMA busy_timeout=60000")
        return connection

    def rebuild_all(self, progress: Callable[[str], None]) -> dict:
        self.directory.mkdir(parents=True, exist_ok=True)
        self._remove_legacy_temp_files(progress)
        progress("전체 인덱싱 · 민감 파일 원본 확인 중")
        try: files = self.sensitive.file_records({"DLP", "Outbound Mail"}, progress=progress)
        except TypeError as exc:
            if "progress" not in str(exc): raise
            files = self.sensitive.file_records({"DLP", "Outbound Mail"})
        progress("전체 인덱싱 · 민감 사이트 원본 확인 중")
        try: sites = self.sensitive.site_records(progress=progress)
        except TypeError as exc:
            if "progress" not in str(exc): raise
            sites = self.sensitive.site_records()
        progress(f"전체 인덱싱 · 민감 파일/사이트 SQLite 교체 준비 · {len(files)+len(sites):,}건")
        app_path = self._build_sensitive(files, sites, progress)
        bounds = self.timeline.date_bounds()
        progress(f"전체 인덱싱 · 통합 타임라인 원본 계산 시작 · {bounds[0]}~{bounds[1]}" if bounds else "전체 인덱싱 · 통합 타임라인 원본 없음")
        try: events = self.timeline.all_events(set(ALL_SOURCES), progress=progress)
        except TypeError as exc:
            if "progress" not in str(exc): raise
            events = self.timeline.all_events(set(ALL_SOURCES))
        progress(f"전체 인덱싱 · 통합 타임라인 SQLite 교체 준비 · {len(events):,}건")
        timeline_path = self._build_timeline(events, progress)
        event_rows = self._event_index_rows(bounds[0], bounds[1], progress) if bounds else []
        events_path = self._build_events_index(event_rows, progress)
        progress("Dashboard 기본 기간 사전 집계 중")
        self.dashboard.warm_default()
        progress(f"전체 캐시 인덱싱 완료 · 민감 {len(files)+len(sites):,}건 / 타임라인 {len(events):,}건 / 리스트 {len(event_rows):,}건")
        self._save_manifest(self._source_snapshot())
        return {"sensitive": len(files) + len(sites), "timeline": len(events), "events": len(event_rows), "dashboard": True, "paths": [str(app_path), str(timeline_path), str(events_path)]}


    def rebuild_scope(self, scope: str, progress: Callable[[str], None]) -> dict:
        if scope == "app":
            progress("민감 콘텐츠 인덱스 전체 재생성 시작")
            files = self.sensitive.file_records({"DLP", "Outbound Mail"}, progress=progress)
            sites = self.sensitive.site_records(progress=progress)
            path = self._build_sensitive(files, sites, progress)
            progress(f"민감 콘텐츠 인덱스 전체 재생성 완료 · {len(files)+len(sites):,}건")
            return {"scope": "app", "sensitive": len(files)+len(sites), "paths": [str(path)]}
        if scope == "timeline":
            bounds = self.timeline.date_bounds()
            progress(f"타임라인 인덱스 전체 재생성 시작 · {bounds[0]}~{bounds[1]}" if bounds else "타임라인 인덱스 원본 없음")
            events = self.timeline.all_events(set(ALL_SOURCES), progress=progress)
            path = self._build_timeline(events, progress)
            progress(f"타임라인 인덱스 전체 재생성 완료 · {len(events):,}건")
            return {"scope": "timeline", "timeline": len(events), "paths": [str(path)]}
        if scope == "dashboard":
            progress("Dashboard 사전 집계 전체 재생성 시작")
            self.dashboard.warm_default()
            progress("Dashboard 사전 집계 전체 재생성 완료")
            return {"scope": "dashboard", "dashboard": True}
        if scope == "events":
            bounds = self._cache_bounds()
            if not bounds:
                progress("Detection 리스트 인덱스 원본 없음")
                path = self._build_events_index([], progress)
                return {"scope": "events", "events": 0, "paths": [str(path)]}
            progress(f"Detection 리스트 인덱스 전체 재생성 시작 · {bounds[0]}~{bounds[1]}")
            rows = self._event_index_rows(bounds[0], bounds[1], progress)
            path = self._build_events_index(rows, progress)
            progress(f"Detection 리스트 인덱스 전체 재생성 완료 · {len(rows):,}건 · Raw 상세 참조형")
            return {"scope": "events", "events": len(rows), "paths": [str(path)]}
        raise ValueError(f"지원하지 않는 인덱싱 범위입니다: {scope}")


    def rebuild_from_fetch_job(self, fetch_job_id: str, progress: Callable[[str], None]) -> dict:
        """Incrementally rebuild indexes for files actually refreshed by a Fetcher job."""
        self.directory.mkdir(parents=True, exist_ok=True)
        fetch_job = self._load_fetch_job(fetch_job_id)
        if not fetch_job:
            raise RuntimeError(f"Fetcher 작업 결과를 찾을 수 없습니다: {fetch_job_id}")
        if fetch_job.get("status") != "completed":
            raise RuntimeError(f"완료되지 않은 Fetcher 작업은 인덱싱할 수 없습니다: {fetch_job_id}")
        result = fetch_job.get("result") or {}
        current = self._source_snapshot()
        source_files = self._source_files_from_fetch_result(result)
        progress(f"Fetcher 증분 · 갱신 파일 {len(source_files):,}개 확인")
        if not source_files:
            self._save_manifest(current)
            progress("Fetcher 증분 완료 · 갱신된 Raw 파일 없음")
            return {"mode": "fetch-incremental", "fetchJobId": fetch_job_id, "changed": 0, "events": 0, "dashboard": False}
        touched_events = 0
        touched_timeline = 0
        touched_sensitive = 0
        for number, source_file in enumerate(source_files, 1):
            key = str(Path(source_file).resolve())
            meta = current.get(key) or self._infer_source_meta(Path(source_file))
            if not meta:
                progress(f"Fetcher 증분 · {number}/{len(source_files)} · 지원하지 않는 파일 건너뜀 · {Path(source_file).name}")
                continue
            source = meta["source"]
            day = date.fromisoformat(meta["date"])
            exists = Path(source_file).exists()
            progress(f"Fetcher 증분 · {number}/{len(source_files)} · {source} · {Path(source_file).name}")
            if source == "detections":
                events = self.timeline.events_between(day, day, {"Detection", "XDR"}, progress) if exists else []
                self._replace_timeline_file(key, events, progress)
                rows = self._event_rows_for_source_file(source, day, key, progress) if exists else []
                self._replace_event_file(key, rows, progress)
                touched_timeline += len(events); touched_events += len(rows)
            elif source == "emails":
                events = self.timeline.events_between(day, day, {"Email"}, progress) if exists else []
                self._replace_timeline_file(key, events, progress)
                rows = self._event_rows_for_source_file(source, day, key, progress) if exists else []
                self._replace_event_file(key, rows, progress)
                touched_timeline += len(events); touched_events += len(rows)
            elif source == "mailscreen":
                events = self.timeline.events_between(day, day, {"Outbound Mail"}, progress) if exists else []
                files = self.sensitive.file_records({"Outbound Mail"}, day, day, progress) if exists else []
                self._replace_timeline_file(key, events, progress)
                self._replace_sensitive_file("sensitive_files_index", key, files, progress)
                rows = self._event_rows_for_source_file(source, day, key, progress) if exists else []
                self._replace_event_file(key, rows, progress)
                touched_timeline += len(events); touched_sensitive += len(files); touched_events += len(rows)
            elif source == "dlp":
                events = self.timeline.events_between(day, day, {"File"}, progress) if exists else []
                files = self.sensitive.file_records({"DLP"}, day, day, progress) if exists else []
                sites = self.sensitive.site_records(day, day, progress) if exists else []
                self._replace_timeline_file(key, events, progress)
                self._replace_sensitive_file("sensitive_files_index", key, files, progress)
                rows = self._event_rows_for_source_file(source, day, key, progress) if exists else []
                self._replace_event_file(key, rows, progress)
                self._replace_sensitive_file("sensitive_sites_index", key, sites, progress)
                touched_timeline += len(events); touched_sensitive += len(files) + len(sites); touched_events += len(rows)
        progress("Fetcher 증분 · Dashboard 기본 기간 사전 집계 중")
        self.dashboard.warm_default()
        self._save_manifest(current)
        progress(f"Fetcher 증분 완료 · 파일 {len(source_files):,}개 / 타임라인 {touched_timeline:,}건 / 리스트 {touched_events:,}건")
        return {"mode": "fetch-incremental", "fetchJobId": fetch_job_id, "files": len(source_files), "timeline": touched_timeline, "sensitive": touched_sensitive, "events": touched_events, "dashboard": True}

    def rebuild_smart(self, progress: Callable[[str], None]) -> dict:
        """Scan all source metadata, but parse and replace only changed files."""
        self.directory.mkdir(parents=True, exist_ok=True)
        current = self._source_snapshot()
        previous = self._load_manifest()
        progress(f"스마트 증분 · 원본 파일 {len(current):,}개 변경 여부 비교 중")
        if not previous:
            message = "스마트 증분 중단 · manifest가 없습니다. General에서 전체 캐시 인덱싱을 수동 실행하세요."
            progress(message)
            raise RuntimeError(message)
        if not self._smart_schema_ready():
            message = "스마트 증분 중단 · 기존 인덱스 형식이 호환되지 않습니다. General에서 전체 캐시 인덱싱을 수동 실행하세요."
            progress(message)
            raise RuntimeError(message)
        identity_sources = {"endpoints", "orgs", "users", "rules"}
        all_changed = sorted(path for path, meta in current.items() if previous.get(path) != meta)
        all_removed = sorted(path for path in previous if path not in current)
        metadata_changed = [path for path in all_changed if current[path].get("source") in identity_sources]
        metadata_removed = [path for path in all_removed if previous[path].get("source") in identity_sources]
        changed = [path for path in all_changed if path not in metadata_changed]
        removed = [path for path in all_removed if path not in metadata_removed]
        unchanged = len(current) - len(all_changed)
        progress(f"스마트 증분 · 원본 변경 {len(changed):,}개 / 삭제 {len(removed):,}개 / 유지 {unchanged:,}개")
        if metadata_changed or metadata_removed:
            progress(
                "스마트 증분 · 기준정보/규칙 변경 "
                f"{len(metadata_changed) + len(metadata_removed):,}개 확인 · 자동 전체 인덱싱 없이 원본 변경분만 계속 처리"
            )
        if not changed and not removed:
            self._save_manifest(current)
            progress(f"스마트 증분 완료 · 원본 변경 없음 · {unchanged:,}개 파일 건너뜀")
            return {"mode": "smart", "changed": 0, "removed": 0, "skipped": unchanged, "dashboard": False}

        affected = changed + removed
        for number, path in enumerate(affected, 1):
            meta = current.get(path) or previous[path]
            source, day = meta["source"], date.fromisoformat(meta["date"])
            progress(f"스마트 증분 · {number}/{len(affected)} · {source} · {Path(path).name}")
            exists = path in current
            if source == "detections":
                events = self.timeline.events_between(day, day, {"Detection", "XDR"}, progress) if exists else []
                self._replace_timeline_file(path, events, progress)
                self._replace_event_file(path, self._event_rows_for_source_file(source, day, path, progress) if exists else [], progress)
            elif source == "emails":
                events = self.timeline.events_between(day, day, {"Email"}, progress) if exists else []
                self._replace_timeline_file(path, events, progress)
                self._replace_event_file(path, self._event_rows_for_source_file(source, day, path, progress) if exists else [], progress)
            elif source == "mailscreen":
                events = self.timeline.events_between(day, day, {"Outbound Mail"}, progress) if exists else []
                files = self.sensitive.file_records({"Outbound Mail"}, day, day, progress) if exists else []
                self._replace_timeline_file(path, events, progress)
                self._replace_sensitive_file("sensitive_files_index", path, files, progress)
                self._replace_event_file(path, self._event_rows_for_source_file(source, day, path, progress) if exists else [], progress)
            elif source == "dlp":
                events = self.timeline.events_between(day, day, {"File"}, progress) if exists else []
                files = self.sensitive.file_records({"DLP"}, day, day, progress) if exists else []
                sites = self.sensitive.site_records(day, day, progress) if exists else []
                self._replace_timeline_file(path, events, progress)
                self._replace_sensitive_file("sensitive_files_index", path, files, progress)
                self._replace_event_file(path, self._event_rows_for_source_file(source, day, path, progress) if exists else [], progress)
                self._replace_sensitive_file("sensitive_sites_index", path, sites, progress)
        progress("스마트 증분 · Dashboard 기본 기간 사전 집계 중")
        self.dashboard.warm_default()
        self._save_manifest(current)
        progress(f"스마트 증분 완료 · 변경 {len(changed):,}개 / 삭제 {len(removed):,}개 / 유지 {unchanged:,}개")
        return {"mode": "smart", "changed": len(changed), "removed": len(removed), "skipped": unchanged, "events": True, "dashboard": True}


    def _load_fetch_job(self, fetch_job_id: str) -> dict | None:
        database = self.root / "runtime" / "fetcher" / "jobs.db"
        if not database.exists():
            return None
        with sqlite3.connect(database, timeout=30) as db:
            db.row_factory = sqlite3.Row
            row = db.execute("SELECT status, result, error FROM jobs WHERE id=?", (fetch_job_id,)).fetchone()
        if not row:
            return None
        return {"status": row["status"], "result": json.loads(row["result"]) if row["result"] else None, "error": json.loads(row["error"]) if row["error"] else None}

    def _source_files_from_fetch_result(self, result: dict) -> list[str]:
        files: set[str] = set()
        target_specs = {
            "detections": ("detections", self.root / "cache" / "detections", "{day}.json"),
            "inbound": ("emails", self.root / "cache" / "emails", "{day}.json"),
            "outbound": ("mailscreen", self.root / "cache" / "mailscreen", "mailscreen_mail_{day}.json"),
            "dlp": ("dlp", self.root / "cache" / "dlp", "{day}.jsonl"),
        }

        def add_path(path_value: object) -> None:
            if not path_value:
                return
            files.add(str(Path(str(path_value)).resolve()))

        def add_day(target: str, day_value: object) -> None:
            spec = target_specs.get(target)
            if not spec or not day_value:
                return
            _source, directory, template = spec
            files.add(str((directory / template.format(day=str(day_value))).resolve()))

        def visit(target: str, value: object) -> None:
            if isinstance(value, dict):
                if "path" in value:
                    add_path(value.get("path"))
                if isinstance(value.get("days"), dict):
                    for day_key in value["days"]:
                        add_day(target, day_key)
                elif isinstance(value.get("days"), list):
                    for item in value["days"]:
                        visit(target, item)
                for key in ("today", "data"):
                    if key in value:
                        visit(target, value[key])
                if isinstance(value.get("finalizedDays"), list):
                    for item in value["finalizedDays"]:
                        visit(target, item)
                if "date" in value:
                    add_day(target, value.get("date"))
            elif isinstance(value, list):
                for item in value:
                    visit(target, item)

        for target, payload in result.items():
            if target in target_specs:
                visit(target, payload)
        return sorted(files)

    def _infer_source_meta(self, path: Path) -> dict | None:
        match = re.search(r"\d{4}-\d{2}-\d{2}", path.name)
        if not match:
            return None
        name = path.name
        if path.suffix == ".jsonl" and path.parent.name == "dlp":
            return {"source": "dlp", "date": match.group()}
        if name.startswith("mailscreen_mail_"):
            return {"source": "mailscreen", "date": match.group()}
        if path.parent.name == "emails":
            return {"source": "emails", "date": match.group()}
        if path.parent.name == "detections":
            return {"source": "detections", "date": match.group()}
        return None

    def _cache_bounds(self) -> tuple[date, date] | None:
        days = sorted({date.fromisoformat(meta["date"]) for meta in self._source_snapshot().values() if meta.get("date")})
        return (days[0], days[-1]) if days else None

    @staticmethod
    def _event_time(kind: str, row: dict[str, str]) -> str:
        if kind in {"detections", "xdr"}:
            return str(row.get("time") or "")
        if kind == "inbound":
            return str(row.get("received") or "")
        if kind in {"outbound", "dlp"}:
            return str(row.get("date") or row.get("time") or "")
        return ""

    def _event_index_rows(self, start: date, end: date, progress: Callable[[str], None]) -> list[dict[str, str]]:
        collectors = (
            ("detections", "Detection", self.detections._events),
            ("xdr", "Email XDR", self.email._collect_xdr),
            ("inbound", "Inbound Mail", self.email._collect_inbound),
            ("outbound", "Outbound Mail", self.transfers._collect_outbound),
            ("dlp", "DLP", self.transfers._collect_dlp),
        )
        output: list[dict[str, str]] = []
        for kind, label, collector in collectors:
            progress(f"Detection 리스트 인덱스 · {label} 리스트 필드 계산 중")
            try:
                records, _files = collector(start, end, progress)
            except TypeError:
                records, _files = collector(start, end)
            total = len(records)
            for offset in range(0, total, 5000):
                batch = records[offset:offset+5000]
                for record_id, _raw, row in batch:
                    output.append({
                        "kind": kind,
                        "recordId": str(record_id),
                        "eventTime": self._event_time(kind, row),
                        "rowJson": json.dumps({key: value for key, value in row.items() if key != "_sourceFile"}, ensure_ascii=False),
                        "searchText": json.dumps(row, ensure_ascii=False).lower(),
                        "sourceFile": str(row.get("_sourceFile", "")),
                    })
                progress(f"Detection 리스트 인덱스 · {label} {min(offset+len(batch), total):,}/{total:,}건")
        return output

    def _build_events_index(self, rows: list[dict[str, str]], progress=lambda _message: None) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True)
        final = self.directory / "events_index.db"
        staging = "event_list_rows_web_next"
        with self._connect(final) as db:
            db.execute(f"DROP TABLE IF EXISTS {staging}")
            display_definition = ", ".join(f"{column} TEXT NOT NULL DEFAULT ''" for column in DISPLAY_COLUMNS)
            db.execute(f"CREATE TABLE {staging} (kind TEXT, record_id TEXT, event_time TEXT, search_text TEXT, row_json TEXT, source_file TEXT, {display_definition}, PRIMARY KEY(kind, record_id))")
            for offset in range(0, len(rows), 5000):
                batch = rows[offset:offset+5000]
                placeholders = ",".join("?" for _ in range(6 + len(DISPLAY_COLUMNS)))
                db.executemany(f"INSERT OR REPLACE INTO {staging} VALUES ({placeholders})", [self._event_db_values(row) for row in batch])
                progress(f"Detection 리스트 인덱스 SQLite 기록 {min(offset+len(batch),len(rows)):,}/{len(rows):,}건")
            db.execute("DROP TABLE IF EXISTS event_list_rows")
            db.execute(f"ALTER TABLE {staging} RENAME TO event_list_rows")
            db.execute("CREATE INDEX idx_web_event_list_kind_time ON event_list_rows(kind, event_time DESC)")
            db.execute("CREATE INDEX idx_web_event_list_source_file ON event_list_rows(source_file)")
            db.execute("CREATE TABLE IF NOT EXISTS index_metadata (key TEXT PRIMARY KEY, value TEXT)")
            db.execute("INSERT OR REPLACE INTO index_metadata VALUES ('mode','display-list-raw-detail')")
            db.execute("INSERT OR REPLACE INTO index_metadata VALUES ('event_list_schema_version',?)", (SCHEMA_VERSION,))
            db.execute("INSERT OR REPLACE INTO index_metadata VALUES ('updated_at', datetime('now'))")
        return final

    def _event_rows_for_source_file(self, source: str, day: date, source_file: str, progress: Callable[[str], None]) -> list[dict[str, str]]:
        kinds = {"detections": {"detections", "xdr"}, "emails": {"inbound"}, "mailscreen": {"outbound"}, "dlp": {"dlp"}}.get(source, set())
        if not kinds:
            return []
        resolved = str(source_file)
        return [row for row in self._event_index_rows(day, day, progress) if row.get("kind") in kinds and row.get("sourceFile") == resolved]

    def _ensure_events_index(self, progress: Callable[[str], None]) -> Path:
        final = self.directory / "events_index.db"
        if not final.exists():
            return self._build_events_index([], progress)
        with self._connect(final) as db:
            exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='event_list_rows'").fetchone()
        if not exists:
            return self._build_events_index([], progress)
        self._migrate_event_list_schema(final, progress)
        return final

    @staticmethod
    def _event_db_values(row: dict[str, str]) -> tuple[str, ...]:
        try:
            display = json.loads(row.get("rowJson", "{}"))
        except json.JSONDecodeError:
            display = {}
        if not isinstance(display, dict):
            display = {}
        return (row["kind"], row["recordId"], row["eventTime"], row["searchText"], row["rowJson"], row["sourceFile"], *values_for_row(display))

    def _migrate_event_list_schema(self, final: Path, progress: Callable[[str], None]) -> None:
        with self._connect(final) as db:
            db.execute("CREATE TABLE IF NOT EXISTS index_metadata (key TEXT PRIMARY KEY, value TEXT)")
            version = db.execute("SELECT value FROM index_metadata WHERE key='event_list_schema_version'").fetchone()
            if version and str(version[0]) == SCHEMA_VERSION:
                return
            existing = {str(row[1]) for row in db.execute("PRAGMA table_info(event_list_rows)")}
            for column in DISPLAY_COLUMNS:
                if column not in existing:
                    db.execute(f"ALTER TABLE event_list_rows ADD COLUMN {column} TEXT NOT NULL DEFAULT ''")
            rows = db.execute("SELECT kind, record_id, row_json FROM event_list_rows").fetchall()
            assignments = ",".join(f"{column}=?" for column in DISPLAY_COLUMNS)
            for offset in range(0, len(rows), 2000):
                batch = rows[offset:offset + 2000]
                updates = []
                for item in batch:
                    try:
                        display = json.loads(item[2] or "{}")
                    except json.JSONDecodeError:
                        display = {}
                    updates.append((*values_for_row(display if isinstance(display, dict) else {}), item[0], item[1]))
                db.executemany(f"UPDATE event_list_rows SET {assignments} WHERE kind=? AND record_id=?", updates)
                progress(f"Detection 리스트 검색 스키마 이전 {min(offset + len(batch), len(rows)):,}/{len(rows):,}건")
            db.execute("INSERT OR REPLACE INTO index_metadata VALUES ('event_list_schema_version',?)", (SCHEMA_VERSION,))

    def _update_events_range(self, rows: list[dict[str, str]], start: date, end: date, progress: Callable[[str], None]) -> Path:
        final = self._ensure_events_index(progress)
        with self._connect(final) as db:
            exclusive_end = (end + timedelta(days=1)).isoformat()
            db.execute("DELETE FROM event_list_rows WHERE event_time >= ? AND event_time < ?", (start.isoformat(), exclusive_end))
            for offset in range(0, len(rows), 5000):
                batch = rows[offset:offset+5000]
                placeholders = ",".join("?" for _ in range(6 + len(DISPLAY_COLUMNS)))
                db.executemany(f"INSERT OR REPLACE INTO event_list_rows VALUES ({placeholders})", [self._event_db_values(row) for row in batch])
                progress(f"증분 인덱싱 · Detection 리스트 SQLite 반영 {min(offset+len(batch),len(rows)):,}/{len(rows):,}건")
        return final

    def _replace_event_file(self, source_file: str, rows: list[dict[str, str]], progress: Callable[[str], None]) -> None:
        final = self._ensure_events_index(progress)
        with self._connect(final) as db:
            db.execute("DELETE FROM event_list_rows WHERE source_file=?", (source_file,))
            for offset in range(0, len(rows), 5000):
                batch = rows[offset:offset+5000]
                placeholders = ",".join("?" for _ in range(6 + len(DISPLAY_COLUMNS)))
                db.executemany(f"INSERT OR REPLACE INTO event_list_rows VALUES ({placeholders})", [self._event_db_values(row) for row in batch])
                progress(f"스마트 증분 · Detection 리스트 SQLite {min(offset+len(batch),len(rows)):,}/{len(rows):,}건")

    def _source_snapshot(self) -> dict[str, dict]:
        specs = (("detections", self.root/"cache/detections", "????-??-??.json"), ("emails", self.root/"cache/emails", "????-??-??.json"), ("mailscreen", self.root/"cache/mailscreen", "mailscreen_mail_????-??-??.json"), ("dlp", self.root/"cache/dlp", "????-??-??.jsonl"))
        result: dict[str, dict] = {}
        for source, directory, pattern in specs:
            if not directory.exists(): continue
            for path in directory.glob(pattern):
                match = re.search(r"\d{4}-\d{2}-\d{2}", path.name)
                if not match: continue
                stat = path.stat(); key = str(path.resolve())
                result[key] = {"source": source, "date": match.group(), "mtimeNs": stat.st_mtime_ns, "size": stat.st_size}
        for source, path in (("endpoints", self.root/"cache/endpoints.json"), ("orgs", self.root/"cache/user_groups.json"), ("users", self.root/"cache/users.json")):
            if path.exists():
                stat = path.stat(); result[str(path.resolve())] = {"source": source, "date": "", "mtimeNs": stat.st_mtime_ns, "size": stat.st_size}
        rule_paths = [self.root/"env/Report_exception_List.txt", *(self.root/"env/exceptions").glob("*.json"), *(self.root/"env/content").glob("*.json")]
        for path in rule_paths:
            if path.exists():
                stat = path.stat(); result[str(path.resolve())] = {"source": "rules", "date": "", "mtimeNs": stat.st_mtime_ns, "size": stat.st_size}
        return result

    def _load_manifest(self) -> dict:
        try:
            value = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _save_manifest(self, value: dict) -> None:
        temporary = self.manifest_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temporary, self.manifest_path)

    def _smart_schema_ready(self) -> bool:
        requirements = ((self.directory/"app_cache.db", ("sensitive_files_index", "sensitive_sites_index")), (self.directory/"timeline_index.db", ("timeline_events",)))
        try:
            for path, tables in requirements:
                if not path.exists(): return False
                with self._connect(path) as db:
                    for table in tables:
                        columns = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
                        if "source_file" not in columns: return False
            return True
        except sqlite3.Error:
            return False

    def rebuild_range(self, start: date, end: date, progress: Callable[[str], None]) -> dict:
        """Refresh only cache dates collected by the scheduler, preserving older index rows."""
        self.directory.mkdir(parents=True, exist_ok=True)
        progress(f"증분 인덱싱 · 대상 기간 {start.isoformat()}~{end.isoformat()} 확인 중")
        files = self.sensitive.file_records({"DLP", "Outbound Mail"}, start, end, progress)
        sites = self.sensitive.site_records(start, end, progress)
        app_path = self._update_sensitive_range(files, sites, start, end, progress)
        events = self.timeline.events_between(start, end, set(ALL_SOURCES), progress)
        timeline_path = self._update_timeline_range(events, start, end, progress)
        event_rows = self._event_index_rows(start, end, progress)
        events_path = self._update_events_range(event_rows, start, end, progress)
        progress("증분 인덱싱 · Dashboard 기본 기간 사전 집계 중")
        self.dashboard.warm_default()
        progress(f"증분 인덱싱 완료 · {start.isoformat()}~{end.isoformat()} · 민감 {len(files)+len(sites):,}건 / 타임라인 {len(events):,}건 / 리스트 {len(event_rows):,}건")
        return {"mode": "incremental", "start": start.isoformat(), "end": end.isoformat(), "sensitive": len(files)+len(sites), "timeline": len(events), "events": len(event_rows), "dashboard": True, "paths": [str(app_path), str(timeline_path), str(events_path)]}

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

    def _build_sensitive(self, files: list[dict], sites: list[dict], progress=lambda _message: None) -> Path:
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
                db.execute(f"CREATE TABLE {staging} (dedupe_key TEXT PRIMARY KEY, source TEXT, category TEXT, event_time TEXT, search_text TEXT, record_json TEXT, source_file TEXT)")
                items = list(latest_records.items())
                for offset in range(0, len(items), 5000):
                    batch = items[offset:offset+5000]
                    db.executemany(f"INSERT OR REPLACE INTO {staging} VALUES (?,?,?,?,?,?,?)", [(key, r["source"], r["category"], r["time"], json.dumps(r, ensure_ascii=False).lower(), json.dumps({**r, "row": r.get("raw", r)}, ensure_ascii=False), r.get("sourceFile", "")) for key, r in batch])
                    progress(f"전체 인덱싱 · {table} SQLite 기록 {min(offset+len(batch),len(items)):,}/{len(items):,}건")
                db.execute(f"DROP TABLE IF EXISTS {table}")
                db.execute(f"ALTER TABLE {staging} RENAME TO {table}")
                db.execute(f"CREATE INDEX idx_web_{table}_filter ON {table}(source, category, event_time DESC)")
                db.execute(f"CREATE INDEX idx_web_{table}_source_file ON {table}(source_file)")
        return final

    def _update_sensitive_range(self, files: list[dict], sites: list[dict], start: date, end: date, progress) -> Path:
        final = self.directory / "app_cache.db"
        if not final.exists():
            message = "증분 인덱싱 중단 · 기존 민감 인덱스가 없습니다. 전체 캐시 인덱싱을 수동 실행하세요."
            progress(message); raise RuntimeError(message)
        with self._connect(final) as db:
            missing = any("source_file" not in {row[1] for row in db.execute(f"PRAGMA table_info({table})")} for table in ("sensitive_files_index", "sensitive_sites_index"))
        if missing:
            message = "증분 인덱싱 중단 · 기존 민감 인덱스 형식이 호환되지 않습니다. 전체 캐시 인덱싱을 수동 실행하세요."
            progress(message); raise RuntimeError(message)
        with self._connect(final) as db:
            for table, records in (("sensitive_files_index", files), ("sensitive_sites_index", sites)):
                db.execute(f"DELETE FROM {table} WHERE substr(event_time,1,10) BETWEEN ? AND ?", (start.isoformat(), end.isoformat()))
                latest = {self._sensitive_key(table, record): record for record in records}
                items = list(latest.items())
                for offset in range(0, len(items), 5000):
                    batch = items[offset:offset+5000]
                    db.executemany(f"INSERT OR REPLACE INTO {table} VALUES (?,?,?,?,?,?,?)", [(key, r["source"], r["category"], r["time"], json.dumps(r, ensure_ascii=False).lower(), json.dumps({**r, "row": r.get("raw", r)}, ensure_ascii=False), r.get("sourceFile", "")) for key, r in batch])
                    progress(f"증분 인덱싱 · {table} SQLite 반영 {min(offset+len(batch),len(items)):,}/{len(items):,}건")
        return final

    @staticmethod
    def _sensitive_key(table: str, record: dict) -> str:
        """Use the same semantic primary key as the desktop indexes."""
        subject = record.get("name") if table == "sensitive_files_index" else record.get("site")
        return "|".join((normalized_identity(record.get("source")), normalized_identity(subject),
                         normalized_identity(record.get("dept")), normalized_identity(record.get("user"))))

    def _build_timeline(self, events: list[dict], progress=lambda _message: None) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True)
        final = self.directory / "timeline_index.db"
        fields = ("time", "source", "user", "userId", "dept", "asset", "event", "direction", "peer", "summary", "indicator")
        staging = "timeline_events_web_next"
        with self._connect(final) as db:
            db.execute(f"DROP TABLE IF EXISTS {staging}")
            db.execute(f"CREATE TABLE {staging} (time TEXT, source TEXT, user TEXT, user_id TEXT, dept TEXT, asset TEXT, event TEXT, direction TEXT, peer TEXT, summary TEXT, indicator TEXT, raw_json TEXT, source_file TEXT)")
            for offset in range(0, len(events), 5000):
                batch = events[offset:offset+5000]
                db.executemany(f"INSERT INTO {staging} VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", [tuple(event.get(key, "") for key in fields) + (json.dumps(event.get("raw", {}), ensure_ascii=False), event.get("sourceFile", "")) for event in batch])
                progress(f"전체 인덱싱 · 통합 타임라인 SQLite 기록 {min(offset+len(batch),len(events)):,}/{len(events):,}건")
            db.execute("DROP TABLE IF EXISTS timeline_events")
            db.execute(f"ALTER TABLE {staging} RENAME TO timeline_events")
            db.execute("CREATE INDEX idx_web_timeline_time ON timeline_events(time DESC)")
            db.execute("CREATE INDEX idx_web_timeline_source ON timeline_events(source, time DESC)")
            db.execute("CREATE INDEX idx_web_timeline_groups ON timeline_events(source, substr(time,1,16), event, time DESC)")
            db.execute("CREATE INDEX idx_web_timeline_source_file ON timeline_events(source_file)")
        return final

    def _update_timeline_range(self, events: list[dict], start: date, end: date, progress) -> Path:
        final = self.directory / "timeline_index.db"
        if not final.exists():
            message = "증분 인덱싱 중단 · 기존 타임라인 인덱스가 없습니다. 전체 캐시 인덱싱을 수동 실행하세요."
            progress(message); raise RuntimeError(message)
        fields = ("time", "source", "user", "userId", "dept", "asset", "event", "direction", "peer", "summary", "indicator")
        with self._connect(final) as db:
            exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='timeline_events'").fetchone()
            columns = {row[1] for row in db.execute("PRAGMA table_info(timeline_events)")} if exists else set()
        if not exists or not {"raw_json", "source_file"}.issubset(columns):
            message = "증분 인덱싱 중단 · 기존 타임라인 인덱스 형식이 호환되지 않습니다. 전체 캐시 인덱싱을 수동 실행하세요."
            progress(message); raise RuntimeError(message)
        with self._connect(final) as db:
            db.execute("CREATE INDEX IF NOT EXISTS idx_web_timeline_groups ON timeline_events(source, substr(time,1,16), event, time DESC)")
            exclusive_end = (end + timedelta(days=1)).isoformat()
            db.execute("DELETE FROM timeline_events WHERE time >= ? AND time < ?", (start.isoformat(), exclusive_end))
            for offset in range(0, len(events), 5000):
                batch = events[offset:offset+5000]
                db.executemany("INSERT INTO timeline_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", [tuple(event.get(key, "") for key in fields) + (json.dumps(event.get("raw", {}), ensure_ascii=False), event.get("sourceFile", "")) for event in batch])
                progress(f"증분 인덱싱 · 통합 타임라인 SQLite 반영 {min(offset+len(batch),len(events)):,}/{len(events):,}건")
        return final

    def _replace_timeline_file(self, source_file: str, events: list[dict], progress) -> None:
        fields = ("time", "source", "user", "userId", "dept", "asset", "event", "direction", "peer", "summary", "indicator")
        with self._connect(self.directory/"timeline_index.db") as db:
            db.execute("DELETE FROM timeline_events WHERE source_file=?", (source_file,))
            for offset in range(0, len(events), 5000):
                batch = events[offset:offset+5000]
                db.executemany("INSERT INTO timeline_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", [tuple(event.get(key, "") for key in fields) + (json.dumps(event.get("raw", {}), ensure_ascii=False), source_file) for event in batch])
                progress(f"스마트 증분 · Timeline SQLite {min(offset+len(batch),len(events)):,}/{len(events):,}건")

    def _replace_sensitive_file(self, table: str, source_file: str, records: list[dict], progress) -> None:
        with self._connect(self.directory/"app_cache.db") as db:
            db.execute(f"DELETE FROM {table} WHERE source_file=?", (source_file,))
            for index, record in enumerate(records, 1):
                key = self._sensitive_key(table, record)
                existing = db.execute(f"SELECT event_time FROM {table} WHERE dedupe_key=?", (key,)).fetchone()
                if existing and str(existing[0] or "") > str(record.get("time", "")): continue
                db.execute(f"INSERT OR REPLACE INTO {table} VALUES (?,?,?,?,?,?,?)", (key, record["source"], record["category"], record["time"], json.dumps(record, ensure_ascii=False).lower(), json.dumps({**record, "row": record.get("raw", record)}, ensure_ascii=False), source_file))
                if index % 5000 == 0: progress(f"스마트 증분 · {table} SQLite {index:,}/{len(records):,}건")
