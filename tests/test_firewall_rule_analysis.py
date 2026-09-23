import pytest

import backend.services.firewall_network_mapping as mapping_module
from backend.services.firewall_network_mapping import NetworkMapping, classify_analysis_sheet, classify_rule_side
from backend.services.firewall_rule_export import classify_parsed_rule


def row(source_object: str, source_resolved: str, destination_object: str, destination_resolved: str) -> dict[str, str]:
    return {
        "Source Object": source_object,
        "Source Resolved": source_resolved,
        "Destination Object": destination_object,
        "Destination Resolved": destination_resolved,
    }


@pytest.mark.parametrize(("rule", "expected"), [
    (row("Seoul", "101.1.0.0/22", "AWS", "100.1.0.0/22"), "LAN ↔ OFFICE"),
    (row("AWS", "100.1.0.0/22", "Seoul", "101.1.0.10"), "LAN ↔ OFFICE"),
    (row("AWS", "100.1.0.0/22", "Public DNS", "8.8.8.8"), "LAN ↔ WAN"),
    (row("Public DNS", "8.8.8.8", "AWS", "100.1.0.0/22"), "LAN ↔ WAN"),
    (row("Seoul", "101.1.0.0/22", "Icheon", "101.3.0.0/23"), "ETC"),
    (row("AWS LOCK", "100.1.0.0/22", "AWS AIDR", "10.10.0.0/16"), "ETC"),
    (row("Seoul\nIcheon", "101.1.0.0/22\n101.3.0.0/23", "AWS", "100.1.0.0/22"), "LAN ↔ OFFICE"),
    (row("Seoul\nAWS", "101.1.0.0/22\n100.1.0.0/22", "AWS AIDR", "10.10.0.0/16"), "ETC"),
    (row("Unknown Object", "Unknown Object", "AWS", "100.1.0.0/22"), "ETC"),
    (row("Any", "Any", "AWS", "100.1.0.0/22"), "ETC"),
])
def test_required_network_analysis_cases(rule: dict[str, str], expected: str) -> None:
    assert classify_parsed_rule(rule)[0] == expected


def test_analysis_columns_preserve_direction_and_sites() -> None:
    bucket, derived = classify_parsed_rule(row("Seoul", "101.1.0.0/22", "AWS", "100.1.0.0/22"))
    assert bucket == "LAN ↔ OFFICE"
    assert derived == {
        "Source Category": "OFFICE",
        "Destination Category": "LAN",
        "Source Site": "서울사업장 유선",
        "Destination Site": "AWS_LOCK_VPC",
    }


def test_longest_prefix_match_prefers_most_specific_mapping(monkeypatch) -> None:
    monkeypatch.setattr(mapping_module, "NETWORK_MAPPINGS", (
        NetworkMapping("Broad", "OFFICE", "10.0.0.0/8"),
        NetworkMapping("Specific", "LAN", "10.10.0.0/16"),
    ))
    categories, sites = classify_rule_side("Specific host", "10.10.1.5")
    assert categories == {"LAN"}
    assert sites == ["Specific"]


def test_classifier_requires_one_category_per_side() -> None:
    assert classify_analysis_sheet({"OFFICE", "LAN"}, {"LAN"}) == "ETC"
    assert classify_analysis_sheet(set(), {"WAN"}) == "ETC"
