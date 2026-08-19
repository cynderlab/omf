from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from omf.schema.capabilities import User, UserList
from omf.schema.evidence import CheckResult, Evidence


def test_userlist_frozen():
    users = UserList(users=(User(name="admin", enabled=True, groups=("full",)),))
    with pytest.raises(Exception):
        users.users[0].name = "x"  # type: ignore[misc]


def test_evidence_wraps_payload():
    payload = UserList(users=())
    ev = Evidence(
        capability="users",
        vendor="mikrotik",
        collected_at=datetime.now(timezone.utc),
        payload=payload,
    )
    assert ev.schema_version == 1
    assert ev.payload is payload


def test_user_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        User(name="a", enabled=True, groups=(), password="nope")


def test_check_result_status_enum():
    CheckResult(
        check_id="FW-ADM-001",
        status="fail",
        severity="high",
        diagnostic="default admin present",
        capability_refs=("users",),
        observed={"names": ["admin"]},
    )
    with pytest.raises(ValidationError):
        CheckResult(
            check_id="x",
            status="warn",
            severity="high",
            diagnostic="",
            capability_refs=(),
            observed={},
        )


from omf.schema.capabilities import (
    ALL_CAPABILITIES,
    CORE_CAPABILITIES,
    FORTINET_EXTRAS,
    MIKROTIK_EXTRAS,
    AdminSettings,
    HaConfig,
    L2Access,
    LocalInPolicy,
    Policy,
    Service,
    SnmpConfig,
    UtmConfig,
    UtmProfile,
    Zone,
    ZoneList,
)


def test_core_capabilities_are_the_original_nine():
    assert CORE_CAPABILITIES == (
        "users",
        "admin_settings",
        "services",
        "ntp",
        "dns",
        "logging",
        "snmp",
        "firewall_filter",
        "system_info",
    )
    assert FORTINET_EXTRAS == ("zones", "local_in", "ha", "utm")
    assert MIKROTIK_EXTRAS == ("l2_access",)
    assert ALL_CAPABILITIES == CORE_CAPABILITIES + FORTINET_EXTRAS + MIKROTIK_EXTRAS


def test_admin_settings_optional_l1_defaults():
    settings = AdminSettings(hostname="fw")
    assert settings.pre_login_banner is None
    assert settings.password_min_length is None
    assert settings.admin_https_ssl_versions == ()


def test_service_on_wan_defaults_false():
    svc = Service(name="https", enabled=True, port=443, listen="restricted")
    assert svc.on_wan is False


def test_new_capability_models_are_frozen():
    zones = ZoneList(zones=(Zone(name="DMZ", intrazone="deny"),))
    assert zones.zones[0].intrazone == "deny"
    ha = HaConfig(mode="standalone")
    assert ha.monitor_interfaces == ()
    utm = UtmConfig(profiles=(UtmProfile(name="default", kind="dnsfilter", log_all=True),))
    assert utm.stitches == ()
    lip = LocalInPolicy(id="1", enabled=True, action="accept", virtual_patch=False)
    assert lip.virtual_patch is False
    l2 = L2Access(
        discover_interface_list="none",
        mac_telnet_interface_list="none",
        mac_winbox_interface_list="none",
        mac_ping_enabled=False,
    )
    assert l2.discover_interface_list == "none"
