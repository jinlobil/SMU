import json

import pytest

from backend.services.integrations import IntegrationService


def test_integration_service_writes_env_and_masks_secrets(tmp_path):
    service = IntegrationService(tmp_path)

    saved = service.save({
        "type": "sophos",
        "instance": "",
        "values": {
            "clientId": "client-id",
            "clientSecret": "super-secret",
            "tokenUrl": "https://token.example",
            "whoamiUrl": "https://whoami.example",
        },
    })

    assert saved["id"] == "sophos-central"
    assert saved["values"]["clientSecretConfigured"] is True
    assert "clientSecret" not in saved["values"]
    assert "super-secret" not in json.dumps(saved)
    text = (tmp_path / "env/Sophos_env.txt").read_text(encoding="utf-8")
    assert "SOPHOS_CLIENT_SECRET=super-secret" in text


def test_update_keeps_existing_secret_when_password_is_blank(tmp_path):
    service = IntegrationService(tmp_path)
    service.save({"type": "dlp", "values": {"baseUrl": "https://dlp", "username": "admin", "password": "first", "timeout": "30"}})

    service.save({"type": "dlp", "values": {"baseUrl": "https://new-dlp", "username": "admin", "password": ""}}, "dlp")

    text = (tmp_path / "env/DLP_env.txt").read_text(encoding="utf-8")
    assert "DLP_BASE_URL=https://new-dlp" in text
    assert "DLP_PASSWORD=first" in text


def test_firewalls_are_independent_cards_and_delete_preserves_other_site(tmp_path):
    service = IntegrationService(tmp_path)
    common = {"port": "4444", "username": "admin", "password": "pw", "ipHostGroup": "blocked-ip", "fqdnHostGroup": "blocked-domain"}
    service.save({"type": "firewall", "instance": "seoul", "values": {**common, "host": "seoul-fw"}})
    service.save({"type": "firewall", "instance": "icheon", "values": {**common, "host": "icheon-fw"}})

    assert {item["id"] for item in service.list()} == {"firewall-seoul", "firewall-icheon"}
    service.delete("firewall-seoul")
    text = (tmp_path / "env/Firewall_env.txt").read_text(encoding="utf-8")
    assert "FW_SEOUL_HOST" not in text
    assert "FW_ICHEON_HOST=icheon-fw" in text
    assert "FW_IPHOST_GROUP=blocked-ip" in text


def test_duplicate_singleton_requires_editing_existing_card(tmp_path):
    service = IntegrationService(tmp_path)
    payload = {"type": "mailscreen", "values": {"baseUrl": "https://mail", "username": "admin", "password": "pw"}}
    service.save(payload)

    with pytest.raises(ValueError, match="이미 등록된 연동"):
        service.save(payload)
