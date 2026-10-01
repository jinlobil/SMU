from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.services.firewall import FIREWALL_DEFINITIONS, FirewallClient, FirewallService


class IntegrationService:
    """Manage the existing env-backed integrations without exposing credentials."""

    TYPES = {"sophos", "firewall", "mailscreen", "dlp"}
    FIREWALL_IDS = {name.lower(): (name, prefix) for name, prefix in FIREWALL_DEFINITIONS.items()}
    SECRET_FIELDS = {
        "sophos": {"clientSecret"},
        "firewall": {"password"},
        "mailscreen": {"password"},
        "dlp": {"password"},
    }
    META = {
        "sophos": ("Sophos Central", "Cloud Security", "Endpoint, Detection, Email XDR, Easy Query"),
        "firewall": ("Sophos Firewall", "Network Security", "Block IP, Block Domain"),
        "mailscreen": ("MailScreen", "Outbound Mail Security", "Outbound Mail, Attachment, Approval"),
        "dlp": ("DLP", "File Security", "File Event, Upload, Destination"),
    }

    def __init__(self, root: Path):
        self.root = root
        self.env_dir = root / "env"
        self.state_path = self.env_dir / "Integration_state.json"
        self.lock = threading.RLock()

    @staticmethod
    def _read_values(path: Path) -> dict[str, str]:
        if not path.exists():
            return {}
        values: dict[str, str] = {}
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip().upper()] = value.strip()
        return values

    @staticmethod
    def _write_values(path: Path, values: dict[str, str]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text("".join(f"{key}={value}\n" for key, value in values.items() if value != ""), encoding="utf-8")
        os.replace(temporary, path)

    def _state(self) -> dict[str, dict[str, Any]]:
        if not self.state_path.exists():
            return {}
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _write_state(self, state: dict[str, dict[str, Any]]) -> None:
        self.env_dir.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temporary, self.state_path)

    @staticmethod
    def _bool(value: Any, default: bool = False) -> bool:
        if value is None:
            return default
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    @staticmethod
    def _required(values: dict[str, Any], fields: tuple[str, ...]) -> None:
        missing = [field for field in fields if not str(values.get(field, "")).strip()]
        if missing:
            raise ValueError("필수 연동 정보를 입력해주세요: " + ", ".join(missing))

    def _identity(self, kind: str, instance: str = "") -> str:
        kind = kind.lower().strip()
        if kind not in self.TYPES:
            raise ValueError("지원하지 않는 연동 솔루션입니다.")
        if kind == "firewall":
            location = instance.lower().strip()
            if location not in self.FIREWALL_IDS:
                raise ValueError("Firewall 위치는 Cloud, Seoul, Icheon, Anseong 중 하나여야 합니다.")
            return f"firewall-{location}"
        return {"sophos": "sophos-central", "mailscreen": "mailscreen", "dlp": "dlp"}[kind]

    def _record(self, integration_id: str) -> tuple[str, str, dict[str, Any], set[str]]:
        if integration_id == "sophos-central":
            raw = self._read_values(self.env_dir / "Sophos_env.txt")
            values = {"clientId": raw.get("SOPHOS_CLIENT_ID", ""), "clientSecret": raw.get("SOPHOS_CLIENT_SECRET", ""), "tokenUrl": raw.get("SOPHOS_TOKEN_URL", "https://id.sophos.com/api/v2/oauth2/token"), "whoamiUrl": raw.get("SOPHOS_WHOAMI_URL", "https://api.central.sophos.com/whoami/v1")}
            return "sophos", "", values, {"clientId", "clientSecret"}
        if integration_id == "mailscreen":
            raw = self._read_values(self.env_dir / "Mail_Screen_env.txt")
            values = {"baseUrl": raw.get("MS_BASE_URL", ""), "username": raw.get("MS_USERNAME", ""), "password": raw.get("MS_PASSWORD", ""), "verifySsl": self._bool(raw.get("MS_VERIFY_SSL")), "timeout": raw.get("MS_TIMEOUT", "30"), "rowCount": raw.get("MS_ROW_NUM", "100"), "sleep": raw.get("MS_SLEEP", "0.3")}
            return "mailscreen", "", values, {"baseUrl", "username", "password"}
        if integration_id == "dlp":
            raw = self._read_values(self.env_dir / "DLP_env.txt")
            values = {"baseUrl": raw.get("DLP_BASE_URL", ""), "username": raw.get("DLP_USERNAME", ""), "password": raw.get("DLP_PASSWORD", ""), "verifySsl": self._bool(raw.get("DLP_VERIFY_SSL")), "timeout": raw.get("DLP_TIMEOUT", "30")}
            return "dlp", "", values, {"baseUrl", "username", "password"}
        if integration_id.startswith("firewall-"):
            location = integration_id.removeprefix("firewall-")
            if location not in self.FIREWALL_IDS:
                raise KeyError(integration_id)
            name, prefix = self.FIREWALL_IDS[location]
            raw = self._read_values(self.env_dir / "Firewall_env.txt")
            stem = f"FW_{prefix}"
            values = {"location": name, "host": raw.get(f"{stem}HOST", ""), "port": raw.get(f"{stem}PORT", ""), "username": raw.get(f"{stem}USERNAME", ""), "password": raw.get(f"{stem}PASSWORD", ""), "verifySsl": self._bool(raw.get(f"{stem}VERIFY_SSL")), "description": raw.get("FW_IPHOST_DESCRIPTION", ""), "ipHostGroup": raw.get("FW_IPHOST_GROUP", ""), "fqdnHostGroup": raw.get("FW_FQDNHOST_GROUP", "")}
            return "firewall", location, values, {"host", "port", "username", "password"}
        raise KeyError(integration_id)

    def _public(self, integration_id: str, kind: str, instance: str, values: dict[str, Any], required: set[str]) -> dict[str, Any]:
        state = self._state().get(integration_id, {})
        public_values = {key: value for key, value in values.items() if key not in self.SECRET_FIELDS[kind]}
        for secret in self.SECRET_FIELDS[kind]:
            public_values[f"{secret}Configured"] = bool(values.get(secret))
        title, category, capabilities = self.META[kind]
        return {"id": integration_id, "type": kind, "instance": instance, "name": title, "displayName": f"{title} · {values.get('location')}" if kind == "firewall" else title, "category": category, "capabilities": [item.strip() for item in capabilities.split(",")], "configured": all(bool(str(values.get(field, "")).strip()) for field in required), "status": state.get("status", "configured"), "lastCheckedAt": state.get("lastCheckedAt"), "lastError": state.get("lastError", ""), "values": public_values}

    def list(self) -> list[dict[str, Any]]:
        ids = ["sophos-central", *(f"firewall-{location}" for location in self.FIREWALL_IDS), "mailscreen", "dlp"]
        output = []
        for integration_id in ids:
            kind, instance, values, required = self._record(integration_id)
            if any(str(values.get(field, "")).strip() for field in required):
                output.append(self._public(integration_id, kind, instance, values, required))
        return output

    def get(self, integration_id: str) -> dict[str, Any]:
        kind, instance, values, required = self._record(integration_id)
        return self._public(integration_id, kind, instance, values, required)

    def save(self, payload: dict[str, Any], integration_id: str | None = None) -> dict[str, Any]:
        kind = str(payload.get("type", "")).lower().strip()
        instance = str(payload.get("instance", "")).strip()
        target_id = integration_id or self._identity(kind, instance)
        current_kind, current_instance, current, _required_fields = self._record(target_id)
        if integration_id is None and all(str(current.get(field, "")).strip() for field in _required_fields):
            raise ValueError("이미 등록된 연동입니다. 기존 카드의 설정 버튼을 사용해주세요.")
        if kind and kind != current_kind:
            raise ValueError("연동 종류는 변경할 수 없습니다.")
        incoming = payload.get("values") if isinstance(payload.get("values"), dict) else {}
        merged = {**current, **{key: value for key, value in incoming.items() if value not in (None, "")}}
        if current_kind == "sophos":
            self._required(merged, ("clientId", "clientSecret")); path = self.env_dir / "Sophos_env.txt"
            data = {"SOPHOS_CLIENT_ID": str(merged["clientId"]).strip(), "SOPHOS_CLIENT_SECRET": str(merged["clientSecret"]).strip(), "SOPHOS_TOKEN_URL": str(merged.get("tokenUrl", "")).strip(), "SOPHOS_WHOAMI_URL": str(merged.get("whoamiUrl", "")).strip()}
        elif current_kind == "mailscreen":
            self._required(merged, ("baseUrl", "username", "password")); path = self.env_dir / "Mail_Screen_env.txt"
            data = {"MS_BASE_URL": str(merged["baseUrl"]).strip(), "MS_USERNAME": str(merged["username"]).strip(), "MS_PASSWORD": str(merged["password"]).strip(), "MS_VERIFY_SSL": str(self._bool(merged.get("verifySsl"))).lower(), "MS_TIMEOUT": str(merged.get("timeout", "30")), "MS_ROW_NUM": str(merged.get("rowCount", "100")), "MS_SLEEP": str(merged.get("sleep", "0.3"))}
        elif current_kind == "dlp":
            self._required(merged, ("baseUrl", "username", "password")); path = self.env_dir / "DLP_env.txt"
            data = {"DLP_BASE_URL": str(merged["baseUrl"]).strip(), "DLP_USERNAME": str(merged["username"]).strip(), "DLP_PASSWORD": str(merged["password"]).strip(), "DLP_VERIFY_SSL": str(self._bool(merged.get("verifySsl"))).lower(), "DLP_TIMEOUT": str(merged.get("timeout", "30"))}
        else:
            self._required(merged, ("host", "port", "username", "password")); path = self.env_dir / "Firewall_env.txt"; data = self._read_values(path)
            _name, prefix = self.FIREWALL_IDS[current_instance]; stem = f"FW_{prefix}"
            data.update({f"{stem}HOST": str(merged["host"]).strip(), f"{stem}PORT": str(merged["port"]).strip(), f"{stem}USERNAME": str(merged["username"]).strip(), f"{stem}PASSWORD": str(merged["password"]).strip(), f"{stem}VERIFY_SSL": str(self._bool(merged.get("verifySsl"))).lower(), "FW_IPHOST_DESCRIPTION": str(merged.get("description", "")).strip(), "FW_IPHOST_GROUP": str(merged.get("ipHostGroup", "")).strip(), "FW_FQDNHOST_GROUP": str(merged.get("fqdnHostGroup", "")).strip()})
        with self.lock:
            self._write_values(path, data)
            state = self._state(); state[target_id] = {"status": "configured", "lastCheckedAt": None, "lastError": ""}; self._write_state(state)
        return self.get(target_id)

    def delete(self, integration_id: str) -> None:
        kind, instance, _values, _required = self._record(integration_id)
        with self.lock:
            if kind == "firewall":
                path = self.env_dir / "Firewall_env.txt"; data = self._read_values(path); _name, prefix = self.FIREWALL_IDS[instance]; stem = f"FW_{prefix}"
                for suffix in ("HOST", "PORT", "USERNAME", "PASSWORD", "VERIFY_SSL"):
                    data.pop(f"{stem}{suffix}", None)
                self._write_values(path, data)
            else:
                path = self.env_dir / {"sophos": "Sophos_env.txt", "mailscreen": "Mail_Screen_env.txt", "dlp": "DLP_env.txt"}[kind]
                if path.exists():
                    path.unlink()
            state = self._state(); state.pop(integration_id, None); self._write_state(state)

    def test(self, integration_id: str) -> dict[str, Any]:
        kind, instance, _values, _required = self._record(integration_id)
        try:
            if kind == "sophos":
                from backend.clients.sophos import SophosClient
                client = SophosClient(self.env_dir / "Sophos_env.txt"); client.authenticate(); detail = f"Tenant {client.tenant_id}"
            elif kind == "firewall":
                config = next(item for item in FirewallService(self.root).configurations() if item["name"].lower() == instance)
                if not config.get("iphost_group"):
                    raise ValueError("IP Host Group을 먼저 설정해주세요.")
                FirewallClient(config).group("IP"); detail = f"{config['name']} Firewall 인증 성공"
            elif kind == "mailscreen":
                from backend.clients.legacy_collectors import MailScreenClient
                MailScreenClient().login(); detail = "MailScreen 로그인 성공"
            else:
                from backend.clients.legacy_collectors import DlpClient
                DlpClient().login(); detail = "DLP 로그인 성공"
            status, error = "connected", ""
        except Exception as exc:
            status, detail, error = "error", "연결 실패", str(exc)
        checked = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
        with self.lock:
            state = self._state(); state[integration_id] = {"status": status, "lastCheckedAt": checked, "lastError": error}; self._write_state(state)
        return {"integration": self.get(integration_id), "ok": status == "connected", "message": detail}
