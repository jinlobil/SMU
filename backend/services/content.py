from __future__ import annotations

import json
import os
import shutil
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


KINDS = {"files": "SENSITIVE_FILE_CATEGORY_SPECS", "sites": "SENSITIVE_SITE_CATEGORY_SPECS"}


class ContentService:
    """Backend-owned Sensitive Files/Sites classification configuration."""

    def __init__(self, root: Path):
        self.root = root
        self.directory = root / "env" / "content"
        self.lock = threading.RLock()
        self._cache: dict[Path, tuple[int, int, dict[str, Any]]] = {}
        self._migrate()

    def _path(self, kind: str) -> Path:
        if kind not in KINDS:
            raise ValueError("콘텐츠 종류는 files 또는 sites여야 합니다.")
        return self.directory / f"sensitive_{kind}.json"

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

    @staticmethod
    def _empty() -> dict[str, Any]:
        return {"version": 1, "categories": []}

    def _load(self, path: Path) -> dict[str, Any]:
        if not path.exists():
            return self._empty()
        stat = path.stat(); cached = self._cache.get(path)
        if cached and cached[0] == stat.st_mtime_ns and cached[1] == stat.st_size:
            return cached[2]
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"콘텐츠 설정 파일을 읽을 수 없습니다: {path.name}") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("categories"), list):
            raise ValueError(f"콘텐츠 설정 파일 형식이 올바르지 않습니다: {path.name}")
        data = {"version": int(payload.get("version", 1)), "categories": [item for item in payload["categories"] if isinstance(item, dict)]}
        self._cache[path] = (stat.st_mtime_ns, stat.st_size, data)
        return data

    def _write(self, path: Path, payload: dict[str, Any]) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        json.loads(temporary.read_text(encoding="utf-8"))
        if path.exists():
            shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
        os.replace(temporary, path)
        stat = path.stat(); self._cache[path] = (stat.st_mtime_ns, stat.st_size, payload)

    def _legacy(self, variable_name: str) -> list[tuple[str, list[str]]]:
        # Import only the safe AST reader; the legacy module itself is never executed.
        from backend.services.sensitive import FILE_CATEGORIES, SITE_CATEGORIES, legacy_specs
        fallback = FILE_CATEGORIES if variable_name == "SENSITIVE_FILE_CATEGORY_SPECS" else SITE_CATEGORIES
        values = legacy_specs(self.root, variable_name, fallback)
        return list(values.items())

    def _migrate(self) -> None:
        for kind, variable in KINDS.items():
            path = self._path(kind)
            if path.exists():
                continue
            categories = []
            for index, (name, keywords) in enumerate(self._legacy(variable)):
                categories.append({"id": f"migrated-{uuid.uuid4().hex[:12]}", "name": name, "keywords": keywords, "enabled": True, "priority": (index + 1) * 10, "description": "기존 Sensitive 분류 설정에서 마이그레이션", "updatedAt": self._now()})
            self._write(path, {"version": 1, "categories": categories})

    def list(self, kind: str) -> dict[str, Any]:
        data = self._load(self._path(kind))
        items = sorted(data["categories"], key=lambda item: (int(item.get("priority", 0)), str(item.get("name", "")).casefold(), str(item.get("id", ""))))
        return {"version": data["version"], "categories": items, "keywordCount": sum(len(item.get("keywords") or []) for item in items)}

    def specs(self, kind: str) -> dict[str, list[str]]:
        return {str(item["name"]): [str(value) for value in item.get("keywords", [])] for item in self.list(kind)["categories"] if item.get("enabled", True)}

    def _validate(self, kind: str, payload: dict[str, Any], item_id: str = "") -> dict[str, Any]:
        self._path(kind)
        name = " ".join(str(payload.get("name", "")).split())
        if not name:
            raise ValueError("카테고리명을 입력해주세요.")
        raw_keywords = payload.get("keywords", [])
        if isinstance(raw_keywords, str):
            raw_keywords = raw_keywords.splitlines()
        if not isinstance(raw_keywords, list):
            raise ValueError("키워드 목록 형식이 올바르지 않습니다.")
        keywords, seen = [], set()
        for raw in raw_keywords:
            value = str(raw).strip()
            key = value.casefold()
            if value and key not in seen:
                seen.add(key); keywords.append(value)
        if not keywords:
            raise ValueError("키워드 또는 도메인을 하나 이상 입력해주세요.")
        if kind == "sites" and any(value.casefold() in {"com", "net", "org", "co.kr"} for value in keywords):
            raise ValueError("너무 광범위한 최상위 도메인은 등록할 수 없습니다.")
        try: priority = max(1, int(payload.get("priority", 10)))
        except (TypeError, ValueError) as exc: raise ValueError("우선순위는 숫자여야 합니다.") from exc
        return {"id": item_id or f"content-{uuid.uuid4().hex[:12]}", "name": name, "keywords": keywords, "enabled": bool(payload.get("enabled", True)), "priority": priority, "description": str(payload.get("description", "")).strip(), "updatedAt": self._now()}

    def save(self, kind: str, payload: dict[str, Any], item_id: str = "") -> dict[str, Any]:
        path = self._path(kind)
        with self.lock:
            data = self._load(path); item = self._validate(kind, payload, item_id)
            for existing in data["categories"]:
                if existing.get("id") != item["id"] and str(existing.get("name", "")).casefold() == item["name"].casefold():
                    raise ValueError("동일한 이름의 카테고리가 이미 존재합니다.")
            index = next((index for index, existing in enumerate(data["categories"]) if existing.get("id") == item["id"]), None)
            if item_id and index is None: raise KeyError(item_id)
            if index is None: data["categories"].append(item)
            else: data["categories"][index] = item
            data["version"] = int(data.get("version", 1)) + 1; self._write(path, data)
            return item

    def delete(self, kind: str, item_id: str) -> None:
        path = self._path(kind)
        with self.lock:
            data = self._load(path); filtered = [item for item in data["categories"] if item.get("id") != item_id]
            if len(filtered) == len(data["categories"]): raise KeyError(item_id)
            data["categories"] = filtered; data["version"] = int(data.get("version", 1)) + 1; self._write(path, data)
