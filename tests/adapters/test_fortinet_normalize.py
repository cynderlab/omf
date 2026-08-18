import json
from pathlib import Path
from omf.adapters.fortinet import (
    forti_users, forti_admin_settings, forti_services, forti_ntp, forti_dns,
    forti_logging, forti_snmp, forti_filter, forti_system, forti_unwrap,
)

FIX = Path(__file__).parent / "fixtures" / "fortinet"

def load(name: str):
    return json.loads((FIX / name).read_text())

def test_users_default_admin():
    assert forti_users(load("admin.json")).users[0].name == "admin"

def test_services_listen_unknown_without_trusthost():
    svc = forti_services(load("interface.json"), load("admin.json"))
    by_name = {s.name: s for s in svc.services}
    assert by_name["https"].enabled is True
    assert by_name["https"].listen == "unknown"
    assert by_name["http"].enabled is True

def test_services_listen_all_with_any_trusthost():
    svc = forti_services(load("interface.json"), load("admin_unrestricted.json"))
    by_name = {s.name: s for s in svc.services}
    assert by_name["https"].listen == "all"

def test_filter_all_becomes_any():
    policies = forti_filter(load("policy.json"))
    assert policies.policies[0].src == ("any",)
    assert policies.policies[0].dst == ("any",)
    assert policies.policies[0].service == ("any",)
    assert policies.policies[0].action == "accept"

def test_ntp_dns_log_snmp_system_admin():
    assert forti_ntp(load("ntp.json")).enabled is True
    assert forti_dns(load("dns.json")).servers[0] == "1.1.1.1"
    log = forti_logging(load("syslogd.json"), None)
    assert log.remote_targets
    assert forti_snmp(load("snmp_sysinfo.json"), load("snmp_community.json")).communities[0].name == "public"
    sysinfo = forti_system(load("status.json"))
    assert sysinfo.firmware.startswith("v7.4")
    assert sysinfo.model == "FortiGate"
    admin = forti_admin_settings(load("global.json"), load("admin.json"))
    assert admin.hostname == "FortiGate"
    assert admin.idle_timeout_seconds == 300


def test_unwrap_results_and_passthrough():
    assert forti_unwrap({"results": [{"name": "admin"}]}) == [{"name": "admin"}]
    assert forti_unwrap({"version": "v7.4.4"}) == {"version": "v7.4.4"}
    assert forti_unwrap([{"name": "admin"}]) == [{"name": "admin"}]


def test_users_groups_and_disable():
    users = forti_users(load("admin.json"))
    assert users.users[0].groups == ("super_admin",)
    assert users.users[0].enabled is True
    disabled = forti_users({"results": [{"name": "ops", "accprofile": "prof_admin", "status": "disable"}]})
    assert disabled.users[0].enabled is False


def test_services_listen_restricted_and_unknown():
    iface = load("interface.json")
    restricted = forti_services(iface, {"results": [{"name": "admin", "trusthost1": "10.0.0.0/24"}]})
    assert {s.name: s.listen for s in restricted.services}["https"] == "restricted"
    any_host = forti_services(iface, {"results": [{"name": "admin", "trusthost1": "0.0.0.0/0"}]})
    assert {s.name: s.listen for s in any_host.services}["https"] == "all"
    unknown = forti_services(iface, {"results": []})
    assert {s.name: s.listen for s in unknown.services}["https"] == "unknown"
    by_name = {s.name: s for s in forti_services(iface, load("admin.json")).services}
    assert by_name["ssh"].enabled is True
    assert by_name["telnet"].enabled is False
    assert by_name["ftp"].enabled is False


def test_logging_local_syslogd2_and_snmp_ntp_dns_filter():
    log = forti_logging(load("syslogd.json"), {"results": {"status": "enable", "server": "10.0.0.10"}})
    assert log.local_enabled is True
    assert log.remote_targets == ("10.0.0.9", "10.0.0.10")
    assert forti_logging({"results": {"status": "disable", "server": "10.0.0.9"}}, None).remote_targets == ()
    ntp = forti_ntp(load("ntp.json"))
    assert ntp.servers == ("1.1.1.1",)
    assert forti_dns(load("dns.json")).servers == ("1.1.1.1", "8.8.8.8")
    snmp = forti_snmp(load("snmp_sysinfo.json"), {"results": [{"name": "public", "query-v1-status": "enable", "query-v2c-status": "enable"}]})
    assert snmp.enabled is True
    assert snmp.communities[0].version == "1/2"
    policy = forti_filter(load("policy.json")).policies[0]
    assert policy.id == "1"
    assert policy.enabled is True


def test_forti_system_envelope_version_wins():
    info = forti_system({
        "results": {"model_name": "FortiGate-60F", "version": "v6.0.0"},
        "version": "v7.4.4",
        "serial": "FG60FTK20000000",
    })
    assert info.firmware == "v7.4.4"
    assert info.model == "FortiGate-60F"
    from_results = forti_system({"results": {"version": "v7.4.1", "model": "FGT_VM64"}})
    assert from_results.firmware == "v7.4.1"
    assert from_results.model == "FGT_VM64"


def test_admin_settings_l1_fields():
    admin = forti_admin_settings(load("global.json"), load("admin.json"), load("password_policy.json"))
    assert admin.pre_login_banner is False
    assert admin.post_login_banner is False
    assert admin.timezone == "US/Pacific"
    assert admin.admin_https_ssl_versions == ("tlsv1-2", "tlsv1-3")
    assert admin.log_single_cpu_high is False
    assert admin.password_policy_enabled is False
    assert admin.password_min_length == 8
    assert admin.admin_lockout_threshold == 5
    assert admin.admin_lockout_duration == 1800
    assert admin.admin_http_port == 80
    assert admin.admin_https_port == 443
    assert admin.admin_https_redirect is True

