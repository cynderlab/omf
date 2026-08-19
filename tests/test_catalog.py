import re

from omf.baseline.loader import load_catalog, checks_for, resolve_params, mitigation_for

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
    by_id = {c.id: c.severity for c in checks_for("mikrotik")}
    assert by_id == _MIKROTIK_SEVERITY


def test_pol002_only_mikrotik():
    mt = {c.id for c in checks_for("mikrotik")}
    ft = {c.id for c in checks_for("fortinet")}
    assert "FW-POL-002" in mt
    assert "FW-POL-002" not in ft
    assert len(mt) == 24
    assert len(ft) == 41
    assert {"FW-UTM-001", "FW-UTM-007", "FW-FAB-001"} <= ft


def test_resolve_admin_mode_differs_by_vendor():
    check = next(c for c in load_catalog() if c.id == "FW-ADM-001")
    assert resolve_params(check, "mikrotik")["mode"] == "must_not_exist"
    assert resolve_params(check, "fortinet")["mode"] == "must_be_renamed"


def test_mitigation_falls_back_to_generic():
    check = next(c for c in load_catalog() if c.id == "FW-SYS-001")
    text = mitigation_for(check, "mikrotik")
    assert text


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
    for check in load_catalog():
        if check.id not in _CIS_L1_FORTINET:
            continue
        text = mitigation_for(check, "fortinet")
        assert "config " in text, check.id
        assert "end" in text, check.id


def test_idle_timeout_cli_is_fortinet_only():
    check = next(c for c in load_catalog() if c.id == "FW-ADM-002")
    assert "set admintimeout" in mitigation_for(check, "fortinet")
    assert "config system" not in mitigation_for(check, "mikrotik")


def test_new_admin_l1_checks_are_fortinet_only():
    from omf.baseline.loader import load_catalog, checks_for
    ids = {c.id for c in load_catalog()}
    assert "FW-ADM-004" in ids
    assert "FW-ADM-004" not in {c.id for c in checks_for("mikrotik")}
    assert "FW-ADM-004" in {c.id for c in checks_for("fortinet")}


def test_catalog_final_counts():
    assert len(load_catalog()) == 48
    assert len(checks_for("mikrotik")) == 24
    assert len(checks_for("fortinet")) == 41
    assert {"FW-ADM-006", "FW-ADM-009", "FW-ADM-011", "FW-POL-003"} <= {
        c.id for c in checks_for("mikrotik")
    }
    assert {
        "FW-L2-001", "FW-L2-002", "FW-SVC-004", "FW-SVC-005", "FW-VPN-001", "FW-SYS-002",
    } <= {c.id for c in checks_for("mikrotik")}
    assert "FW-POL-005" not in {c.id for c in checks_for("mikrotik")}
    assert "FW-UTM-001" not in {c.id for c in checks_for("mikrotik")}
    assert {c.id for c in load_catalog() if "fortinet" in c.applies_to} >= {
        "FW-ADM-004", "FW-SVC-003", "FW-NET-001", "FW-SNMP-003",
        "FW-LOG-003", "FW-LOG-004", "FW-POL-003", "FW-POL-004", "FW-POL-005",
        "FW-LIP-001", "FW-LIP-002", "FW-HA-001", "FW-HA-002",
        "FW-UTM-001", "FW-UTM-007", "FW-FAB-001",
    }
