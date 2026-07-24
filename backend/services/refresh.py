import json
import os
from pathlib import Path
from datetime import date, datetime, time, timedelta, timezone
from typing import Callable

from backend.clients.sophos import SophosClient
from backend.services.endpoints import load_key_value_file


class RefreshService:
    def __init__(self, project_root: Path, client_factory=SophosClient):
        self.project_root = project_root
        self.cache_dir = project_root / "cache"
        self.env_dir = project_root / "env"
        self.client_factory = client_factory

    def save_json_atomic(self, path: Path, payload: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temporary, path)

    def refresh_endpoints(self, progress: Callable[[str], None]) -> dict:
        progress("Sophos 인증 중")
        rows = self.client_factory(self.env_dir / "Sophos_env.txt").fetch_endpoints()
        progress(f"Endpoint {len(rows)}개 저장 중")
        self.save_json_atomic(self.cache_dir / "endpoints.json", rows)
        return {"rows": len(rows)}

    def refresh_organizations(self, progress: Callable[[str], None]) -> dict:
        progress("Sophos 인증 및 조직 조회 중")
        names = load_key_value_file(self.env_dir / "User_group_env.txt")
        groups, users = self.client_factory(self.env_dir / "Sophos_env.txt").fetch_organizations(names)
        progress(f"조직 {len(groups)}개, 사용자 {len(users)}명 저장 중")
        self.save_json_atomic(self.cache_dir / "user_groups.json", groups)
        self.save_json_atomic(self.cache_dir / "users.json", users)
        return {"groups": len(groups), "users": len(users)}

    def refresh_users(self, progress: Callable[[str], None]) -> dict:
        progress("Sophos 인증 및 사용자 조회 중")
        client = self.client_factory(self.env_dir / "Sophos_env.txt")
        client.authenticate()
        users = client.fetch_users()
        self.save_json_atomic(self.cache_dir / "users.json", users)
        return {"users": len(users)}

    def refresh_dlp(self, day: date, progress: Callable[[str], None]) -> dict:
        from backend.clients.legacy_collectors import DlpClient
        progress(f"DLP {day.isoformat()} 인증 및 수집 중")
        return DlpClient(progress_cb=progress).refresh_dlp_day(day.isoformat())

    def refresh_outbound(self, day: date, progress: Callable[[str], None]) -> dict:
        from backend.clients.legacy_collectors import MailScreenClient
        progress(f"Outbound Mail {day.isoformat()} 인증 및 수집 중")
        return MailScreenClient(progress_cb=progress).refresh_mail_day(day.isoformat())

    @staticmethod
    def utc_range(start: date, end: date) -> tuple[str, str]:
        kst = timezone(timedelta(hours=9))
        start_dt = datetime.combine(start, time.min, tzinfo=kst).astimezone(timezone.utc)
        end_dt = datetime.combine(end, time(23, 59, 59), tzinfo=kst).astimezone(timezone.utc)
        return start_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z"), end_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    @staticmethod
    def kst_day(value: object) -> str:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
        return parsed.astimezone(timezone(timedelta(hours=9))).date().isoformat()

    def save_daily(self, directory: Path, rows: list[dict], time_field: str) -> dict[str, int]:
        buckets: dict[str, list[dict]] = {}
        for row in rows:
            try: day = self.kst_day(row.get(time_field))
            except (ValueError, TypeError): continue
            buckets.setdefault(day, []).append(row)
        for day, items in buckets.items(): self.save_json_atomic(directory / f"{day}.json", items)
        return {day: len(items) for day, items in buckets.items()}

    def refresh_detections(self, start: date, end: date, progress: Callable[[str], None]) -> dict:
        from_ts, to_ts = self.utc_range(start, end); client = self.client_factory(self.env_dir / "Sophos_env.txt")
        progress("Sophos Detection 인증 및 쿼리 생성 중"); rows = client.fetch_detections(from_ts, to_ts, progress)
        progress(f"Detection {len(rows)}개 일별 저장 중"); days = self.save_daily(self.cache_dir / "detections", rows, "time")
        return {"rows": len(rows), "days": days}

    def refresh_inbound(self, start: date, end: date, progress: Callable[[str], None]) -> dict:
        from_ts, to_ts = self.utc_range(start, end); client = self.client_factory(self.env_dir / "Sophos_env.txt")
        progress("Sophos Inbound Mail 인증 중"); rows = client.fetch_inbound_emails(from_ts, to_ts, progress)
        progress(f"Inbound Mail {len(rows)}개 일별 저장 중"); days = self.save_daily(self.cache_dir / "emails", rows, "receivedAt")
        return {"rows": len(rows), "days": days}
