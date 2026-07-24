from pathlib import Path

import pytest

from backend.services.firewall import FirewallClient, FirewallService, parse_status


def write_env(root: Path) -> None:
    env = root / "env/Firewall_env.txt"
    env.parent.mkdir(parents=True)
    env.write_text("\n".join([
        "FW_HOST=firewall.local", "FW_PORT=4444", "FW_USERNAME=admin", "FW_PASSWORD=secret",
        "FW_IPHOST_DESCRIPTION=SMU", "FW_IPHOST_GROUP=Blocked IP", "FW_FQDNHOST_GROUP=Blocked Domain",
    ]), encoding="utf-8")


def test_firewall_configuration_never_exposes_credentials(tmp_path: Path) -> None:
    write_env(tmp_path)

    configurations = FirewallService(tmp_path).public_configurations()

    assert configurations[0] == {"name": "Cloud", "configured": True}
    assert "password" not in configurations[0]


def test_firewall_target_validation(tmp_path: Path) -> None:
    service = FirewallService(tmp_path)
    assert service.targets("IP", ["1.2.3.4", "1.2.3.4"]) == ["1.2.3.4"]
    assert service.targets("DOMAIN", ["example.com"]) == ["example.com"]
    with pytest.raises(ValueError):
        service.targets("IP", ["999.2.3.4"])


def test_firewall_execute_classifies_success_and_existing(tmp_path: Path, monkeypatch) -> None:
    write_env(tmp_path)
    responses = iter([
        '<Response><Status code="200">Configuration applied successfully.</Status></Response>',
        '<Response><Status code="502">Object already exists.</Status></Response>',
    ])
    monkeypatch.setattr(FirewallClient, "_post_xml", lambda self, xml: next(responses))

    result = FirewallService(tmp_path).execute("IP", ["1.2.3.4", "5.6.7.8"], ["Cloud"])

    assert [row["result"] for row in result["results"]] == ["SUCCESS", "EXISTS"]
    assert result["counts"] == {"SUCCESS": 1, "EXISTS": 1, "FAIL": 0}
    assert parse_status(result["results"][0]["raw"])["code"] == "200"
