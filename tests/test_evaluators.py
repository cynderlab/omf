from datetime import datetime, timezone
from omf.schema.capabilities import (
    User, UserList, AdminSettings, Service, ServiceList,
    NtpConfig, DnsConfig, LoggingConfig, SnmpCommunity, SnmpConfig,
    Policy, PolicyList, SystemInfo,
)
from omf.schema.evidence import Evidence
from omf.baseline.evaluators.accounts import no_generic_accounts
from omf.baseline.evaluators.admin import idle_timeout_set, hostname_not_default
from omf.baseline.evaluators.services import insecure_services_disabled, services_not_unrestricted
from omf.baseline.evaluators.ntp_dns import ntp_configured, dns_configured
from omf.baseline.evaluators.logging import local_logging_enabled, remote_syslog_configured
from omf.baseline.evaluators.snmp import no_default_snmp_community, snmp_not_legacy
from omf.baseline.evaluators.policy import (
    no_any_any_accept,
    explicit_deny_present,
    no_unrestricted_service,
    policies_logged,
)
from omf.baseline.evaluators.system import firmware_present
from omf.baseline.evaluators import REGISTRY, evaluate
from omf.baseline.loader import load_catalog, resolve_params


def ev(capability, payload, vendor="mikrotik"):
    return Evidence(
        capability=capability,
        vendor=vendor,
        collected_at=datetime.now(timezone.utc),
        payload=payload,
    )


def test_no_generic_accounts_fail_enabled_admin():
    evidence = {"users": ev("users", UserList(users=(
        User(name="admin", enabled=True, groups=()),
    )))}
    r = no_generic_accounts(evidence, {"names": ["admin"], "mode": "must_not_exist"}, "mikrotik")
    assert r.status == "fail"


def test_no_generic_accounts_pass_renamed():
    evidence = {"users": ev("users", UserList(users=(
        User(name="alice", enabled=True, groups=()),
    )))}
    r = no_generic_accounts(evidence, {"names": ["admin"], "mode": "must_be_renamed"}, "fortinet")
    assert r.status == "pass"


def test_no_generic_accounts_ignores_disabled_default():
    evidence = {"users": ev("users", UserList(users=(
        User(name="admin", enabled=False, groups=()),
    )))}
    r = no_generic_accounts(evidence, {"names": ["admin"], "mode": "must_not_exist"}, "mikrotik")
    assert r.status == "pass"


def test_idle_timeout_zero_fails():
    evidence = {"admin_settings": ev("admin_settings", AdminSettings(hostname="fw", idle_timeout_seconds=0))}
    assert idle_timeout_set(evidence, {}, "mikrotik").status == "fail"


def test_idle_timeout_above_max_fails():
    evidence = {"admin_settings": ev("admin_settings", AdminSettings(hostname="fw", idle_timeout_seconds=1200))}
    assert idle_timeout_set(evidence, {"max_seconds": 900}, "fortinet").status == "fail"


def test_hostname_default_fails():
    evidence = {"admin_settings": ev("admin_settings", AdminSettings(hostname="MikroTik"))}
    r = hostname_not_default(evidence, {"default_hostnames": ["MikroTik", ""]}, "mikrotik")
    assert r.status == "fail"


def test_insecure_telnet_fails():
    evidence = {"services": ev("services", ServiceList(services=(
        Service(name="telnet", enabled=True, port=23, listen="restricted"),
    )))}
    r = insecure_services_disabled(evidence, {"forbidden": ["telnet", "ftp", "www"]}, "mikrotik")
    assert r.status == "fail"


def test_mgmt_unknown_listen_fails():
    evidence = {"services": ev("services", ServiceList(services=(
        Service(name="www-ssl", enabled=True, port=443, listen="unknown"),
    )))}
    r = services_not_unrestricted(evidence, {"mgmt": ["www-ssl", "ssh"]}, "mikrotik")
    assert r.status == "fail"


def test_ntp_and_dns():
    assert ntp_configured({"ntp": ev("ntp", NtpConfig(enabled=True, servers=("1.1.1.1",)))}, {}, "m").status == "pass"
    assert ntp_configured({"ntp": ev("ntp", NtpConfig(enabled=True, servers=()))}, {}, "m").status == "fail"
    assert dns_configured({"dns": ev("dns", DnsConfig(servers=()))}, {}, "m").status == "fail"


def test_logging():
    lg = ev("logging", LoggingConfig(local_enabled=True, remote_targets=()))
    assert local_logging_enabled({"logging": lg}, {}, "m").status == "pass"
    assert remote_syslog_configured({"logging": lg}, {}, "m").status == "fail"


def test_snmp():
    enabled_public = ev("snmp", SnmpConfig(enabled=True, communities=(
        SnmpCommunity(name="public", version="2"),
    )))
    assert no_default_snmp_community({"snmp": enabled_public}, {"forbidden": ["public", "private"]}, "m").status == "fail"
    disabled = ev("snmp", SnmpConfig(enabled=False, communities=()))
    assert snmp_not_legacy({"snmp": disabled}, {}, "m").status == "pass"


def test_policies():
    bad = ev("firewall_filter", PolicyList(policies=(
        Policy(id="1", enabled=True, action="accept", src=("any",), dst=("any",), service=("any",)),
    )))
    assert no_any_any_accept({"firewall_filter": bad}, {}, "m").status == "fail"
    deny = ev("firewall_filter", PolicyList(policies=(
        Policy(id="9", enabled=True, action="drop", src=("any",), dst=("any",), service=("any",)),
    )))
    assert explicit_deny_present({"firewall_filter": deny}, {}, "mikrotik").status == "pass"
    assert no_unrestricted_service({"firewall_filter": deny}, {"actions": ["accept"]}, "mikrotik").status == "pass"
    assert no_unrestricted_service({"firewall_filter": deny}, {}, "fortinet").status == "fail"
    logged = ev("firewall_filter", PolicyList(policies=(
        Policy(id="1", enabled=True, action="accept", src=("lan",), dst=("wan",), service=("tcp/443",), log=True),
    )))
    logging = ev("logging", LoggingConfig(local_enabled=True, remote_targets=(), implicit_policy_logged=None))
    assert policies_logged({"firewall_filter": logged, "logging": logging}, {"require_implicit": False}, "mikrotik").status == "pass"
    assert policies_logged({"firewall_filter": logged, "logging": logging}, {}, "fortinet").status == "fail"


def test_firmware():
    assert firmware_present({"system_info": ev("system_info", SystemInfo(firmware="7.16"))}, {}, "m").status == "pass"
    assert firmware_present({"system_info": ev("system_info", SystemInfo(firmware="  "))}, {}, "m").status == "fail"


def test_registry_covers_catalog():
    for check in load_catalog():
        assert check.evaluator in REGISTRY


def test_evaluate_missing_capability_is_error():
    check = next(c for c in load_catalog() if c.id == "FW-NTP-001")
    r = evaluate(check, {}, "mikrotik")
    assert r.status == "error"
    assert "ntp" in r.diagnostic
