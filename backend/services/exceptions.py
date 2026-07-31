from __future__ import annotations

import json
import os
import re
import shutil
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MATCH_TYPES = {"principal", "hostname", "email", "userName", "auto"}


def normalize_identity(value: Any) -> str:
    return re.sub(r"\s+", "", str(value or "").strip().replace("/", "\\")).casefold()


class ExceptionService:
    """Final-stage user and department overrides for processed rows only."""

    def __init__(self, root: Path):
        self.root = root
        self.directory = root / "env" / "exceptions"
        self.department_path = self.directory / "department_exceptions.json"
        self.user_path = self.directory / "user_exceptions.json"
        self.legacy_path = root / "env" / "Report_exception_List.txt"
        self.lock = threading.RLock()
        self._migrate_legacy()

    @staticmethod
    def _empty() -> dict[str, Any]:
        return {"version": 1, "items": []}

    def _load(self, path: Path) -> dict[str, Any]:
        if not path.exists():
            return self._empty()
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"예외 설정 파일을 읽을 수 없습니다: {path.name}") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
            raise ValueError(f"예외 설정 파일 형식이 올바르지 않습니다: {path.name}")
        return {"version": int(payload.get("version", 1)), "items": [item for item in payload["items"] if isinstance(item, dict)]}

    def _write(self, path: Path, payload: dict[str, Any]) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        json.loads(temporary.read_text(encoding="utf-8"))
        if path.exists():
            shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
        os.replace(temporary, path)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

    def _migrate_legacy(self) -> None:
        if self.department_path.exists() or not self.legacy_path.exists():
            return
        items = []
        seen = set()
        for raw in self.legacy_path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, department = (part.strip() for part in line.split("=", 1))
            normalized = normalize_identity(key)
            if not normalized or not department or normalized in seen:
                continue
            seen.add(normalized)
            items.append({"id": f"legacy-{uuid.uuid4().hex[:12]}", "matchType": "auto", "matchValue": key, "department": department, "description": "Report_exception_List.txt에서 자동 마이그레이션", "enabled": True, "updatedAt": self._now()})
        if items:
            self._write(self.department_path, {"version": 1, "items": items})

    def list(self, kind: str) -> dict[str, Any]:
        path = self.department_path if kind == "departments" else self.user_path if kind == "users" else None
        if path is None:
            raise ValueError("예외 종류는 departments 또는 users여야 합니다.")
        return self._load(path)

    def _validate(self, kind: str, payload: dict[str, Any], current_id: str = "") -> dict[str, Any]:
        now = self._now()
        if kind == "departments":
            match_type = str(payload.get("matchType", "")).strip()
            match_value = str(payload.get("matchValue", "")).strip()
            department = str(payload.get("department", "")).strip()
            if match_type not in MATCH_TYPES:
                raise ValueError("부서 예외 매칭 유형이 올바르지 않습니다.")
            if not match_value or not department:
                raise ValueError("식별값과 최종 부서를 입력해주세요.")
            return {"id": current_id or f"dept-{uuid.uuid4().hex[:12]}", "matchType": match_type, "matchValue": match_value, "department": department, "description": str(payload.get("description", "")).strip(), "enabled": bool(payload.get("enabled", True)), "updatedAt": now}
        principal = str(payload.get("principal", "")).strip().replace("/", "\\")
        display_name = str(payload.get("displayName", "")).strip()
        if "\\" not in principal or not all(part.strip() for part in principal.split("\\", 1)):
            raise ValueError(r"전체 사용자 식별값을 PREFIX\account 형식으로 입력해주세요.")
        if not display_name:
            raise ValueError("표시 사용자명을 입력해주세요.")
        return {"id": current_id or f"user-{uuid.uuid4().hex[:12]}", "principal": principal, "displayName": display_name, "description": str(payload.get("description", "")).strip(), "enabled": bool(payload.get("enabled", True)), "updatedAt": now}

    def save(self, kind: str, payload: dict[str, Any], item_id: str = "") -> dict[str, Any]:
        path = self.department_path if kind == "departments" else self.user_path if kind == "users" else None
        if path is None:
            raise ValueError("예외 종류는 departments 또는 users여야 합니다.")
        with self.lock:
            data = self._load(path)
            item = self._validate(kind, payload, item_id)
            key = normalize_identity(item["matchValue"] if kind == "departments" else item["principal"])
            for existing in data["items"]:
                existing_key = normalize_identity(existing.get("matchValue") if kind == "departments" else existing.get("principal"))
                same_type = kind == "users" or existing.get("matchType") == item.get("matchType")
                if existing.get("id") != item["id"] and same_type and existing_key == key:
                    raise ValueError("동일한 식별값의 예외 규칙이 이미 존재합니다.")
            index = next((index for index, existing in enumerate(data["items"]) if existing.get("id") == item["id"]), None)
            if item_id and index is None:
                raise KeyError(item_id)
            if index is None:
                data["items"].append(item)
            else:
                data["items"][index] = item
            data["version"] = int(data.get("version", 1)) + 1
            self._write(path, data)
            return item

    def delete(self, kind: str, item_id: str) -> None:
        path = self.department_path if kind == "departments" else self.user_path if kind == "users" else None
        if path is None:
            raise ValueError("예외 종류는 departments 또는 users여야 합니다.")
        with self.lock:
            data = self._load(path)
            filtered = [item for item in data["items"] if item.get("id") != item_id]
            if len(filtered) == len(data["items"]):
                raise KeyError(item_id)
            data["items"] = filtered
            data["version"] = int(data.get("version", 1)) + 1
            self._write(path, data)

    def resolve_user(self, principal: Any, default_name: Any) -> str:
        key = normalize_identity(principal)
        if not key or "\\" not in key:
            return str(default_name or "None")
        for item in self._load(self.user_path)["items"]:
            if item.get("enabled", True) and normalize_identity(item.get("principal")) == key:
                return str(item.get("displayName") or default_name or "None")
        return str(default_name or "None")

    def resolve_department(self, *, principal: Any = "", hostname: Any = "", email: Any = "", user_name: Any = "", default_department: Any = "미분류") -> str:
        candidates = {"principal": normalize_identity(principal), "hostname": normalize_identity(hostname), "email": normalize_identity(email), "userName": normalize_identity(user_name)}
        rules = [item for item in self._load(self.department_path)["items"] if item.get("enabled", True)]
        for match_type in ("principal", "hostname", "email", "userName", "auto"):
            for item in rules:
                if item.get("matchType") != match_type:
                    continue
                target = normalize_identity(item.get("matchValue"))
                matched = target in candidates.values() if match_type == "auto" else target == candidates.get(match_type)
                if target and matched:
                    return str(item.get("department") or default_department or "미분류")
        return str(default_department or "미분류")

    def finalize(self, *, principal: Any = "", hostname: Any = "", email: Any = "", user_name: Any = "", department: Any = "미분류") -> dict[str, str]:
        display_name = self.resolve_user(principal, user_name)
        final_department = self.resolve_department(principal=principal, hostname=hostname, email=email, user_name=display_name, default_department=department)
        return {"principal": str(principal or ""), "user": display_name, "dept": final_department}
