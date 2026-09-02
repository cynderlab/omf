import re
from pathlib import Path

import pytest

from omf.baseline.loader import load_catalog, resolve_params

_TITLE_POLARITY = re.compile(
    r"\b(is set|is enabled|is configured|is present|is denied|is recorded|"
    r"are changed|are disabled|are not|are bounded|is not|have no|has no|"
    r"do not|uses |meets )\b",
    re.IGNORECASE,
)


def test_catalog_has_unique_ids():
    checks = load_catalog()
    ids = [c.id for c in checks]
    assert len(ids) == len(set(ids))
    assert "FW-POL-002" in ids
    assert "FW-ADM-011" in ids
    assert len({c.id for c in load_catalog("mikrotik")}) == len(load_catalog("mikrotik"))
    assert len({c.id for c in load_catalog("fortinet")}) == len(load_catalog("fortinet"))


def test_titles_are_neutral_topics():
    polar = [f"{c.id}: {c.title}" for c in load_catalog() if _TITLE_POLARITY.search(c.title)]
    assert polar == []


_MIKROTIK_SEVERITY = {
    "FW-ADM-001": "medium",
    "FW-ADM-002": "medium",
    "FW-ADM-003": "low",
    "FW-ADM-006": "low",
    "FW-ADM-009": "medium",
    "FW-ADM-011": "low",
    "FW-SVC-001": "high",
    "FW-SVC-002": "high",
    "FW-SVC-004": "low",
    "FW-SVC-005": "medium",
    "FW-L2-001": "low",
    "FW-L2-002": "high",
    "FW-VPN-001": "high",
    "FW-NTP-001": "low",
    "FW-DNS-001": "low",
    "FW-LOG-001": "medium",
    "FW-LOG-002": "medium",
    "FW-SNMP-001": "high",
    "FW-SNMP-002": "medium",
    "FW-POL-001": "high",
    "FW-POL-002": "high",
    "FW-POL-003": "medium",
    "FW-SYS-001": "low",
    "FW-SYS-002": "high",
}


def test_mikrotik_severities_match_audit_scale():
    by_id = {c.id: c.severity for c in load_catalog("mikrotik")}
    assert by_id == _MIKROTIK_SEVERITY


def test_pol002_only_mikrotik():
    mt = {c.id for c in load_catalog("mikrotik")}
    ft = {c.id for c in load_catalog("fortinet")}
    assert "FW-POL-002" in mt
    assert "FW-POL-002" not in ft
    assert len(mt) == 24
    assert len(ft) == 57
    assert {"FW-UTM-001", "FW-UTM-007", "FW-FAB-001"} <= ft


def test_generic_account_params_are_names_only():
    mt = next(c for c in load_catalog("mikrotik") if c.id == "FW-ADM-001")
    ft = next(c for c in load_catalog("fortinet") if c.id == "FW-ADM-001")
    mt_params = resolve_params(mt, "mikrotik")
    ft_params = resolve_params(ft, "fortinet")
    assert "mode" not in mt_params
    assert "mode" not in ft_params
    assert mt_params["names"] == ["admin"]
    assert ft_params["names"] == ["admin"]


def test_mitigation_is_nonempty():
    check = next(c for c in load_catalog("mikrotik") if c.id == "FW-SYS-001")
    assert check.mitigation


def test_fortinet_descriptions_are_present_and_technical():
    for check in load_catalog("fortinet"):
        assert check.description.strip(), check.id
        assert len(check.description) >= 80, check.id
        assert "\n" not in check.description, check.id
        low = check.description.lower()
        assert "click" not in low, check.id
        assert not low.startswith("ensure "), check.id


def test_mikrotik_descriptions_are_present_and_technical():
    for check in load_catalog("mikrotik"):
        assert check.description.strip(), check.id
        assert len(check.description) >= 80, check.id
        assert "\n" not in check.description, check.id
        low = check.description.lower()
        assert "click" not in low, check.id
        assert not low.startswith("ensure "), check.id


def test_mikrotik_adm001_avoids_password_substring():
    check = next(c for c in load_catalog("mikrotik") if c.id == "FW-ADM-001")
    blob = (check.description + check.mitigation).lower()
    assert "password" not in blob


def test_mikrotik_sys002_mitigation_is_auditor_owned():
    text = next(c for c in load_catalog("mikrotik") if c.id == "FW-SYS-002").mitigation
    assert "check-for-updates" not in text


_MIKROTIK_CLI = frozenset({
    "FW-ADM-001", "FW-ADM-002", "FW-ADM-003", "FW-ADM-006", "FW-ADM-009",
    "FW-ADM-011", "FW-SVC-001", "FW-SVC-002", "FW-SVC-004", "FW-SVC-005",
    "FW-L2-001", "FW-L2-002", "FW-VPN-001", "FW-NTP-001", "FW-DNS-001",
    "FW-LOG-001", "FW-LOG-002", "FW-SNMP-001", "FW-SNMP-002",
    "FW-POL-001", "FW-POL-002", "FW-POL-003", "FW-SYS-001",
})


def test_mikrotik_mitigations_include_routeros_cli():
    for check in load_catalog("mikrotik"):
        if check.id not in _MIKROTIK_CLI:
            continue
        text = check.mitigation
        assert text.strip().startswith("/") or "\n/" in "\n" + text, check.id
        assert "config system" not in text, check.id


_CIS_L1_FORTINET = frozenset({
    "FW-ADM-001", "FW-ADM-002", "FW-ADM-003", "FW-ADM-004", "FW-ADM-005",
    "FW-ADM-006", "FW-ADM-007", "FW-ADM-008", "FW-ADM-009", "FW-ADM-010",
    "FW-ADM-011",
    "FW-SVC-001", "FW-SVC-002", "FW-SVC-003",
    "FW-NET-001",
    "FW-NTP-001", "FW-DNS-001",
    "FW-LOG-003", "FW-LOG-004",
    "FW-SNMP-001", "FW-SNMP-002", "FW-SNMP-003",
    "FW-POL-003", "FW-POL-004", "FW-POL-005",
    "FW-LIP-001", "FW-LIP-002",
    "FW-HA-001", "FW-HA-002",
    "FW-UTM-001", "FW-UTM-002", "FW-UTM-003", "FW-UTM-004",
    "FW-UTM-005", "FW-UTM-006", "FW-UTM-007",
    "FW-FAB-001",
})


def test_fortinet_cis_l1_mitigations_include_cli():
    for check in load_catalog("fortinet"):
        if check.id not in _CIS_L1_FORTINET:
            continue
        text = check.mitigation
        assert "config " in text, check.id
        assert "end" in text, check.id


def test_idle_timeout_cli_is_fortinet_only():
    ft = next(c for c in load_catalog("fortinet") if c.id == "FW-ADM-002")
    mt = next(c for c in load_catalog("mikrotik") if c.id == "FW-ADM-002")
    assert "set admintimeout" in ft.mitigation
    assert "config system" not in mt.mitigation


def test_new_admin_l1_checks_are_fortinet_only():
    ids = {c.id for c in load_catalog()}
    assert "FW-ADM-004" in ids
    assert "FW-ADM-004" not in {c.id for c in load_catalog("mikrotik")}
    assert "FW-ADM-004" in {c.id for c in load_catalog("fortinet")}


def test_catalog_final_counts():
    assert len(load_catalog()) == 63
    assert len(load_catalog("mikrotik")) == 24
    assert len(load_catalog("fortinet")) == 57
    assert {"FW-ADM-006", "FW-ADM-009", "FW-ADM-011", "FW-POL-003"} <= {
        c.id for c in load_catalog("mikrotik")
    }
    assert {
        "FW-L2-001", "FW-L2-002", "FW-SVC-004", "FW-SVC-005", "FW-VPN-001", "FW-SYS-002",
    } <= {c.id for c in load_catalog("mikrotik")}
    assert "FW-POL-005" not in {c.id for c in load_catalog("mikrotik")}
    assert "FW-UTM-001" not in {c.id for c in load_catalog("mikrotik")}
    assert {c.id for c in load_catalog("fortinet")} >= {
        "FW-ADM-004", "FW-SVC-003", "FW-NET-001", "FW-SNMP-003",
        "FW-LOG-003", "FW-LOG-004", "FW-POL-003", "FW-POL-004", "FW-POL-005",
        "FW-LIP-001", "FW-LIP-002", "FW-HA-001", "FW-HA-002",
        "FW-UTM-001", "FW-UTM-007", "FW-FAB-001",
        "FW-SYS-002", "FW-LIC-001", "FW-LIC-012",
        "FW-POL-006", "FW-POL-007", "FW-OBJ-001",
    }


def test_fortinet_hygiene_checks_are_low_and_fortinet_only():
    mt = {c.id for c in load_catalog("mikrotik")}
    by_id = {c.id: c for c in load_catalog("fortinet")}
    for check_id in ("FW-POL-006", "FW-POL-007", "FW-OBJ-001"):
        assert check_id not in mt
        assert by_id[check_id].severity == "low"
    assert by_id["FW-OBJ-001"].needs == ("object_usage",)
    assert by_id["FW-POL-007"].needs == ("object_usage", "firewall_filter")


def test_fortinet_policy_any_any_is_medium_service_all_is_high():
    by_id = {c.id: c.severity for c in load_catalog("fortinet")}
    assert by_id["FW-POL-001"] == "medium"
    assert by_id["FW-POL-003"] == "high"


_FORTINET_LICENSE_SEVERITY = {
    "FW-LIC-001": "medium",
    "FW-LIC-002": "medium",
    "FW-LIC-003": "medium",
    "FW-LIC-004": "medium",
    "FW-LIC-005": "medium",
    "FW-LIC-006": "medium",
    "FW-LIC-007": "medium",
    "FW-LIC-008": "low",
    "FW-LIC-009": "low",
    "FW-LIC-010": "low",
    "FW-LIC-011": "low",
    "FW-LIC-012": "low",
}


def test_fortinet_license_severities_are_medium_except_optional_low():
    by_id = {c.id: c.severity for c in load_catalog("fortinet")}
    license_ids = {check_id for check_id in by_id if check_id.startswith("FW-LIC-")}
    assert license_ids == set(_FORTINET_LICENSE_SEVERITY)
    for check_id, severity in _FORTINET_LICENSE_SEVERITY.items():
        assert by_id[check_id] == severity, check_id
    assert by_id["FW-SYS-002"] == "high"


def test_fortinet_license_and_lifecycle_checks_are_fortinet_only():
    mt = {c.id for c in load_catalog("mikrotik")}
    ft = {c.id for c in load_catalog("fortinet")}
    assert "FW-LIC-001" in ft
    assert "FW-LIC-001" not in mt
    assert "FW-SYS-002" in ft
    check = next(c for c in load_catalog("fortinet") if c.id == "FW-SYS-002")
    params = resolve_params(check, "fortinet")
    assert params["fortios_lifecycle"]["7.2"]["eoes"] == "2025-03-31"


def test_unknown_vendor_catalog_raises():
    with pytest.raises(ValueError, match="unknown vendor"):
        load_catalog("o365")


def test_profile_fills_unset_params():
    check = next(c for c in load_catalog("mikrotik") if c.id == "FW-ADM-003")
    params = resolve_params(check, "mikrotik")
    assert "MikroTik" in params["default_hostnames"]


def test_vendor_catalogs_are_separate_files():
    root = Path(__file__).resolve().parents[1] / "src" / "omf" / "baseline" / "vendors"
    assert (root / "mikrotik" / "catalog.yaml").is_file()
    assert (root / "fortinet" / "catalog.yaml").is_file()
    assert not (root.parent / "catalog.yaml").is_file()
