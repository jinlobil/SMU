import json
import os
from pathlib import Path
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
