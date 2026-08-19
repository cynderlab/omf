from datetime import datetime, timezone

from omf.baseline.evaluators.admin import admin_ports_changed, idle_timeout_set
from omf.baseline.evaluators.policy import (
    explicit_deny_present,
    no_any_any_accept,
    no_unrestricted_service,
)
from omf.baseline.evaluators.snmp import no_default_snmp_community, snmp_not_legacy
from omf.baseline.evaluators.system import firmware_present
from omf.baseline.loader import checks_for, load_catalog
from omf.schema.capabilities import (
    AdminSettings,
    Policy,
    PolicyList,
    SnmpCommunity,
    SnmpConfig,
    SystemInfo,
    User,
    UserList,
)
from omf.schema.evidence import Evidence


def ev(capability, payload, vendor="mikrotik"):
    return Evidence(
        capability=capability,
        vendor=vendor,
        collected_at=datetime.now(timezone.utc),
        payload=payload,
    )


_PER_USER = {"mode": "per_user", "policies": ["logout", "lockscreen", "lock"]}


def test_idle_timeout_per_user_fails_when_policy_is_none():
    evidence = {
        "users": ev(
            "users",
            UserList(
                users=(
                    User(
                        name="admin",
                        enabled=True,
                        groups=("full",),
                        inactivity_timeout_seconds=600,
                        inactivity_policy="none",
                    ),
                )
            ),
        )
    }
    assert idle_timeout_set(evidence, _PER_USER, "mikrotik").status == "fail"


def test_idle_timeout_per_user_passes_logout_with_timeout():
    evidence = {
        "users": ev(
            "users",
            UserList(
                users=(
                    User(
                        name="alice",
                        enabled=True,
                        groups=("full",),
                        inactivity_timeout_seconds=120,
                        inactivity_policy="logout",
                    ),
                    User(
                        name="old",
                        enabled=False,
                        groups=("full",),
                        inactivity_timeout_seconds=None,
                        inactivity_policy="none",
                    ),
                )
            ),
        )
    }
    assert idle_timeout_set(evidence, _PER_USER, "mikrotik").status == "pass"


def test_admin_ports_ignore_disabled_www_on_80():
    evidence = {
        "admin_settings": ev(
            "admin_settings",
            AdminSettings(
                hostname="fw",
                admin_http_port=80,
                admin_http_enabled=False,
                admin_https_port=8443,
                admin_https_enabled=True,
                admin_https_redirect=False,
            ),
        )
    }
    assert admin_ports_changed(evidence, {"forbidden_http": 80, "forbidden_https": 443}, "mikrotik").status == "pass"


def test_admin_ports_fail_enabled_www_ssl_on_443():
    evidence = {
        "admin_settings": ev(
            "admin_settings",
            AdminSettings(
                hostname="fw",
                admin_http_port=80,
                admin_http_enabled=False,
                admin_https_port=443,
                admin_https_enabled=True,
                admin_https_redirect=False,
            ),
        )
    }
    assert admin_ports_changed(evidence, {"forbidden_http": 80, "forbidden_https": 443}, "mikrotik").status == "fail"


def test_snmp_legacy_only_security_none():
    v3 = ev(
        "snmp",
        SnmpConfig(
            enabled=True,
            communities=(SnmpCommunity(name="monitor", version="private", read_access=False),),
        ),
    )
    assert snmp_not_legacy({"snmp": v3}, {"legacy_versions": ["none"]}, "mikrotik").status == "pass"
    open_ = ev(
        "snmp",
        SnmpConfig(
            enabled=True,
            communities=(SnmpCommunity(name="public", version="none", read_access=True),),
        ),
    )
    assert snmp_not_legacy({"snmp": open_}, {"legacy_versions": ["none"]}, "mikrotik").status == "fail"


def test_snmp_default_community_requires_read_access():
    write_only = ev(
        "snmp",
        SnmpConfig(
            enabled=True,
            communities=(SnmpCommunity(name="public", version="none", read_access=False),),
        ),
    )
    assert (
        no_default_snmp_community(
            {"snmp": write_only},
            {"forbidden": ["public", "private"], "require_read_access": True},
            "mikrotik",
        ).status
        == "pass"
    )
    readable = ev(
        "snmp",
        SnmpConfig(
            enabled=True,
            communities=(SnmpCommunity(name="public", version="none", read_access=True),),
        ),
    )
    assert (
        no_default_snmp_community(
            {"snmp": readable},
            {"forbidden": ["public", "private"], "require_read_access": True},
            "mikrotik",
        ).status
        == "fail"
    )


def test_unrestricted_accept_skips_established_any_chain_and_interface_scope():
    payload = PolicyList(
        policies=(
            Policy(
                id="*8",
                enabled=True,
                action="accept",
                src=("any",),
                dst=("any",),
                service=("any",),
                chain="forward",
                connection_state=("established", "related"),
            ),
            Policy(
                id="*2",
                enabled=True,
                action="accept",
                src=("any",),
                dst=("any",),
                service=("any",),
                chain="input",
                connection_state=("established", "related"),
            ),
            Policy(
                id="*7",
                enabled=True,
                action="accept",
                src=("any",),
                dst=("any",),
                service=("any",),
                chain="forward",
                in_interface="Lan/Lan",
                out_interface="pppoe-out",
            ),
            Policy(
                id="open",
                enabled=True,
                action="accept",
                src=("any",),
                dst=("any",),
                service=("any",),
                chain="forward",
            ),
        )
    )
    evidence = {"firewall_filter": ev("firewall_filter", payload)}
    params = {"skip_established": True, "skip_interface_scoped": True}
    assert no_any_any_accept(evidence, params, "mikrotik").observed["policy_ids"] == ["open"]
    assert no_unrestricted_service(evidence, {**params, "actions": ["accept"]}, "mikrotik").observed[
        "policy_ids"
    ] == ["open"]


def test_explicit_deny_requires_unrestricted_drop_on_input_and_forward():
    params = {"chains": ["input", "forward"], "unrestricted_only": True}
    only_output = {
        "firewall_filter": ev(
            "firewall_filter",
            PolicyList(
                policies=(
                    Policy(
                        id="x",
                        enabled=True,
                        action="drop",
                        src=("any",),
                        dst=("any",),
                        service=("any",),
                        chain="output",
                    ),
                )
            ),
        )
    }
    assert explicit_deny_present(only_output, params, "mikrotik").status == "fail"
    both = {
        "firewall_filter": ev(
            "firewall_filter",
            PolicyList(
                policies=(
                    Policy(
                        id="i",
                        enabled=True,
                        action="drop",
                        src=("any",),
                        dst=("any",),
                        service=("any",),
                        chain="input",
                    ),
                    Policy(
                        id="f",
                        enabled=True,
                        action="drop",
                        src=("any",),
                        dst=("any",),
                        service=("any",),
                        chain="forward",
                    ),
                )
            ),
        )
    }
    assert explicit_deny_present(both, params, "mikrotik").status == "pass"


def test_firmware_match_current_ignores_channel_suffix():
    mismatch = {
        "system_info": ev(
            "system_info",
            SystemInfo(firmware="7.21.5 (long-term)", current_firmware="7.20.0"),
        )
    }
    assert firmware_present(mismatch, {"match_current": True}, "mikrotik").status == "fail"
    aligned = {
        "system_info": ev(
            "system_info",
            SystemInfo(firmware="7.21.5 (long-term)", current_firmware="7.21.5"),
        )
    }
    assert firmware_present(aligned, {"match_current": True}, "mikrotik").status == "pass"


def test_pol005_not_on_mikrotik():
    ids = {c.id for c in checks_for("mikrotik")}
    assert "FW-POL-005" not in ids
    assert "FW-POL-005" in {c.id for c in load_catalog() if "fortinet" in c.applies_to}
