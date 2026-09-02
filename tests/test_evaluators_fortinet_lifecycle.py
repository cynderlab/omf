from datetime import datetime, timezone

from omf.baseline.evaluators import evaluate
from omf.baseline.evaluators.license import license_active
from omf.baseline.evaluators.system import firmware_supported
from omf.baseline.loader import load_catalog
from omf.schema.capabilities import LicenseEntitlement, LicenseStatus, SystemInfo
from omf.schema.evidence import Evidence

_AS_OF = datetime(2026, 9, 1, tzinfo=timezone.utc)
_LIFECYCLE = {
    "8.0": {"eoes": "2029-04-21", "eos": "2030-10-21"},
    "7.6": {"eoes": "2028-07-25", "eos": "2030-01-25"},
    "7.4": {"eoes": "2027-05-11", "eos": "2028-11-11"},
    "7.2": {"eoes": "2025-03-31", "eos": "2026-09-30"},
    "7.0": {"eoes": "2024-03-30", "eos": "2025-09-30"},
    "6.4": {"eoes": "2023-03-31", "eos": "2024-09-30"},
    "6.2": {"eoes": "2022-03-28", "eos": "2023-09-28"},
    "6.0": {"eoes": "2021-03-29", "eos": "2022-09-29"},
}


def _system(firmware: str, collected_at: datetime = _AS_OF) -> dict:
    return {
        "system_info": Evidence(
            capability="system_info",
            vendor="fortinet",
            collected_at=collected_at,
            payload=SystemInfo(firmware=firmware),
        )
    }


def _run(firmware: str, collected_at: datetime = _AS_OF):
    return firmware_supported(
        _system(firmware, collected_at),
        {"fortios_lifecycle": _LIFECYCLE},
        "fortinet",
    )


def test_firmware_supported_current_branch_passes():
    assert _run("v7.4.4").status == "pass"


def test_firmware_supported_past_eoes_fails():
    r = _run("v7.2.10")
    assert r.status == "fail"
    assert "7.2" in r.diagnostic
    assert "2025-03-31" in r.diagnostic


def test_firmware_supported_fully_eos_fails():
    assert _run("v7.0.17").status == "fail"


def test_firmware_supported_older_than_table_fails():
    assert _run("v5.6.0").status == "fail"


def test_firmware_supported_newer_than_table_passes():
    assert _run("v8.2.0").status == "pass"


def test_firmware_supported_empty_firmware_fails():
    assert _run("").status == "fail"


def test_firmware_supported_uses_collected_at_not_wall_clock():
    as_of = datetime(2024, 1, 1, tzinfo=timezone.utc)
    assert _run("v7.2.10", collected_at=as_of).status == "pass"


def _licenses(*items: LicenseEntitlement, collected_at: datetime = _AS_OF) -> dict:
    return {
        "licenses": Evidence(
            capability="licenses",
            vendor="fortinet",
            collected_at=collected_at,
            payload=LicenseStatus(entitlements=items),
        )
    }


def test_license_active_required_licensed_passes():
    r = license_active(
        _licenses(LicenseEntitlement(key="ips", status="licensed", expires="2027-01-01")),
        {"key": "ips", "required": True},
        "fortinet",
    )
    assert r.status == "pass"


def test_license_active_required_expired_fails():
    r = license_active(
        _licenses(LicenseEntitlement(key="ips", status="expired", expires="2024-07-07")),
        {"key": "ips", "required": True},
        "fortinet",
    )
    assert r.status == "fail"
    assert "expired" in r.diagnostic
    assert "2024-07-07" in r.diagnostic


def test_license_active_required_unlicensed_fails():
    r = license_active(
        _licenses(LicenseEntitlement(key="ips", status="unlicensed")),
        {"key": "ips", "required": True},
        "fortinet",
    )
    assert r.status == "fail"


def test_license_active_optional_unlicensed_passes():
    r = license_active(
        _licenses(LicenseEntitlement(key="antispam", status="unlicensed")),
        {"key": "antispam", "required": False},
        "fortinet",
    )
    assert r.status == "pass"


def test_license_active_optional_expired_fails():
    r = license_active(
        _licenses(LicenseEntitlement(key="antispam", status="expired", expires="2024-07-07")),
        {"key": "antispam", "required": False},
        "fortinet",
    )
    assert r.status == "fail"


def test_license_active_past_expires_is_expired():
    r = license_active(
        _licenses(LicenseEntitlement(key="ips", status="licensed", expires="2024-07-07")),
        {"key": "ips", "required": True},
        "fortinet",
    )
    assert r.status == "fail"
    assert "expired" in r.diagnostic


def test_license_active_missing_key_is_unlicensed():
    r = license_active(
        _licenses(),
        {"key": "ips", "required": True},
        "fortinet",
    )
    assert r.status == "fail"


def test_evaluate_fw_sys_002_uses_profile_table():
    check = next(c for c in load_catalog("fortinet") if c.id == "FW-SYS-002")
    r = evaluate(check, _system("v7.2.10"), "fortinet")
    assert r.check_id == "FW-SYS-002"
    assert r.status == "fail"
    assert r.severity == "high"


def test_evaluate_optional_email_license_passes_when_unlicensed():
    check = next(c for c in load_catalog("fortinet") if c.id == "FW-LIC-006")
    r = evaluate(
        check,
        _licenses(LicenseEntitlement(key="antispam", status="unlicensed")),
        "fortinet",
    )
    assert r.check_id == "FW-LIC-006"
    assert r.status == "pass"
    assert r.severity == "medium"

