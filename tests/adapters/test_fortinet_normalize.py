import json
from pathlib import Path
from omf.adapters.fortinet import (
    forti_users, forti_admin_settings, forti_services, forti_ntp, forti_dns,
    forti_licenses, forti_logging, forti_snmp, forti_filter, forti_system, forti_unwrap,
    forti_object_usage,
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
    assert by_name["http"].interfaces == ("wan1",)
    assert by_name["https"].interfaces == ("wan1", "lan")
    assert by_name["telnet"].interfaces == ()

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


def test_filter_l1_fields():
    policy = forti_filter(load("policy.json")).policies[0]
    assert policy.service == ("any",)
    assert policy.log is False
    assert policy.internet_src == ()
    assert policy.ips_sensor is None

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
    space_mask = forti_services(iface, {"results": [{"name": "admin", "trusthost1": "0.0.0.0 0.0.0.0"}]})
    assert {s.name: s.listen for s in space_mask.services}["https"] == "all"
    unknown = forti_services(iface, {"results": []})
    assert {s.name: s.listen for s in unknown.services}["https"] == "unknown"
    by_name = {s.name: s for s in forti_services(iface, load("admin.json")).services}
    assert by_name["ssh"].enabled is True
    assert by_name["telnet"].enabled is False
    assert by_name["ftp"].enabled is False


def test_services_listen_nested_trusthost_table():
    iface = load("interface.json")
    nested = forti_services(
        iface,
        {"results": [{"name": "admin", "trusthost": [{"ipv4-trusthost": "10.0.0.0 255.255.255.0"}]}]},
    )
    assert {s.name: s.listen for s in nested.services}["https"] == "restricted"
    open_nested = forti_services(
        iface,
        {"results": [{"name": "admin", "trusthost": [{"ipv4-trusthost": "0.0.0.0 0.0.0.0"}]}]},
    )
    assert {s.name: s.listen for s in open_nested.services}["https"] == "all"


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


def test_services_on_wan_and_zones():
    svc = forti_services(load("interface.json"), load("admin.json"))
    by_name = {s.name: s for s in svc.services}
    assert by_name["https"].on_wan is True
    assert by_name["telnet"].on_wan is False
    from omf.adapters.fortinet import forti_zones
    zones = forti_zones(load("zone.json"))
    assert zones.zones[0].name == "DMZ"
    assert zones.zones[0].intrazone == "allow"


def test_snmp_traps_and_logging_crypto():
    snmp = forti_snmp(load("snmp_sysinfo.json"), load("snmp_community.json"), load("snmp_user.json"))
    assert snmp.users == ()
    assert snmp.trap_free_memory_threshold == 0
    log = forti_logging(load("syslogd.json"), None, load("fortianalyzer.json"), load("log_setting.json"))
    assert log.syslog_reliable is False
    assert log.syslog_enc_high is False
    assert log.faz_enabled is True
    assert log.faz_enc_high is False
    assert log.implicit_policy_logged is False


def test_local_in_virtual_patch_disabled():
    from omf.adapters.fortinet import forti_local_in
    policies = forti_local_in(load("local_in_policy.json"), None).policies
    assert policies[0].action == "accept"
    assert policies[0].virtual_patch is False


def test_ha_strips_password_and_reads_monitor():
    from omf.adapters.fortinet import forti_ha
    ha = forti_ha(load("ha.json"))
    assert ha.mode == "a-p"
    assert ha.monitor_interfaces == ("port6", "port7")
    assert ha.ha_mgmt_status is True
    assert ha.ha_mgmt_interfaces == ("port6",)
    dumped = ha.model_dump()
    assert "password" not in dumped
    assert "super-secret" not in str(dumped)


def test_ha_standalone_defaults():
    from omf.adapters.fortinet import forti_ha
    ha = forti_ha(load("ha_standalone.json"))
    assert ha.mode == "standalone"
    assert ha.monitor_interfaces == ()
    assert ha.ha_mgmt_status is False
    assert ha.ha_mgmt_interfaces == ()


def test_utm_normalize():
    from omf.adapters.fortinet import forti_utm
    utm = forti_utm(load("dnsfilter.json"), load("webfilter.json"), load("application_list.json"), load("automation_stitch.json"))
    dns = next(p for p in utm.profiles if p.kind == "dnsfilter")
    assert dns.log_all is False
    web = next(p for p in utm.profiles if p.kind == "webfilter")
    assert "malicious" in web.blocked_categories
    app = next(p for p in utm.profiles if p.kind == "appctrl")
    assert "proxy" in app.allowed_categories
    assert utm.stitches[0].enabled is False


def test_utm_normalize_string_names_and_envelope():
    from omf.adapters.fortinet import forti_utm
    utm = forti_utm(
        {"results": [{"name": "logall", "log-all": "enable"}]},
        {
            "results": [
                {
                    "name": "wf",
                    "ftgd-wf": {
                        "filters": {"": [{"category": "Malicious Websites", "action": "deny"}]},
                    },
                }
            ]
        },
        {
            "results": [
                {
                    "name": "app",
                    "entries": {"": [{"category": "P2P", "action": "block"}, {"category": "Proxy", "action": "pass"}]},
                }
            ]
        },
        {"results": [{"name": "Compromised Host Quarantine", "status": "enable"}]},
    )
    dns = next(p for p in utm.profiles if p.kind == "dnsfilter")
    assert dns.log_all is True
    web = next(p for p in utm.profiles if p.kind == "webfilter")
    assert "malicious" in web.blocked_categories
    app = next(p for p in utm.profiles if p.kind == "appctrl")
    assert "p2p" in app.blocked_categories
    assert "proxy" in app.allowed_categories
    assert utm.stitches[0].enabled is True


def test_forti_licenses_drops_account_and_normalizes_status():
    payload = forti_licenses(load("license_status.json"))
    by_key = {item.key: item for item in payload.entitlements}
    assert "ops@example.com" not in str(payload.model_dump())
    assert by_key["forticare"].status == "licensed"
    assert by_key["forticare"].expires == "2026-11-13"
    assert by_key["firmware_updates"].status == "expired"
    assert by_key["firmware_updates"].expires == "2024-07-07"
    assert by_key["ips"].status == "expired"
    assert by_key["antivirus"].status == "expired"
    assert by_key["web_filtering"].status == "expired"
    assert by_key["antispam"].status == "expired"
    assert by_key["outbreak_prevention"].status == "expired"
    assert by_key["sdwan_network_monitor"].status == "unlicensed"
    assert by_key["security_rating"].status == "unlicensed"
    assert by_key["industrial_db"].status == "unlicensed"
    assert by_key["iot_detection"].status == "unlicensed"
    assert by_key["forticloud"].status == "licensed"


def test_forti_licenses_registered_with_empty_support_is_licensed():
    # FortiOS 7.2 GUI "FortiCare Support: Registered" is status=registered
    # with an empty support object, not nested support.enhanced.
    payload = forti_licenses({
        "results": {
            "forticare": {
                "type": "cloud_service_status",
                "status": "registered",
                "registration_status": "registered",
                "registration_supported": True,
                "account": "ops@example.com",
                "support": {},
            }
        }
    })
    by_key = {item.key: item for item in payload.entitlements}
    assert by_key["forticare"].status == "licensed"
    assert "ops@example.com" not in str(payload.model_dump())


def test_forti_licenses_unregistered_is_unlicensed():
    payload = forti_licenses({
        "results": {"forticare": {"status": "unregistered", "support": {}}}
    })
    by_key = {item.key: item for item in payload.entitlements}
    assert by_key["forticare"].status == "unlicensed"


def test_forti_licenses_firmware_updates_falls_back_to_fmwr_entitlement():
    payload = forti_licenses({
        "results": {
            "appctrl": {
                "status": "expired",
                "expires": 1720310400,
                "entitlement": "FMWR",
            }
        }
    })
    by_key = {item.key: item for item in payload.entitlements}
    assert by_key["firmware_updates"].status == "expired"
    assert by_key["firmware_updates"].expires == "2024-07-07"


def test_forti_licenses_forticloud_cloud_logged_in_is_licensed():
    payload = forti_licenses({
        "results": {"forticloud": {"status": "cloud_logged_in"}}
    })
    by_key = {item.key: item for item in payload.entitlements}
    assert by_key["forticloud"].status == "licensed"


def test_object_usage_keeps_used_unused_and_static():
    payload = forti_object_usage(
        address_raw=load("address.json"),
        addrgrp_raw=load("addrgrp.json"),
        service_raw=load("service_custom.json"),
        service_group_raw=load("service_group.json"),
        vip_raw=load("vip.json"),
        ippool_raw=load("ippool.json"),
        policy_stats_raw=load("policy_stats.json"),
    )
    by_key = {(item.kind, item.name): item for item in payload.items}
    assert by_key[("address", "HOST_OLD")].refs == 0
    assert by_key[("address", "HOST_OLD")].static is False
    assert by_key[("address", "all")].refs == 12
    assert by_key[("address", "all")].static is True
    assert by_key[("addrgrp", "GRP_DEAD")].refs == 0
    assert by_key[("service", "TCP_DEAD")].refs == 0
    assert by_key[("service_group", "SVC_DEAD")].refs == 0
    assert by_key[("vip", "VIP_OLD")].refs == 0
    assert by_key[("ippool", "POOL_OLD")].refs == 0
    assert by_key[("policy", "1")].hit_count == 100
    assert by_key[("policy", "2")].hit_count == 0
    assert by_key[("policy", "2")].last_used is None


def test_object_usage_optional_tables_empty():
    payload = forti_object_usage(
        address_raw=load("address.json"),
        policy_stats_raw=load("policy_stats.json"),
    )
    kinds = {item.kind for item in payload.items}
    assert kinds == {"address", "policy"}



