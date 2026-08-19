import json
from pathlib import Path
from omf.adapters.normalize import as_any_token
from omf.adapters.mikrotik import (
    mikrotik_users, mikrotik_services, mikrotik_ntp, mikrotik_dns,
    mikrotik_admin_settings, mikrotik_logging, mikrotik_snmp,
    mikrotik_filter, mikrotik_system, mikrotik_l2_access,
)

FIX = Path(__file__).parent / "fixtures" / "mikrotik"

def load(name: str):
    return json.loads((FIX / name).read_text())

def test_users():
    users = mikrotik_users(load("user.json"))
    assert users.users[0].name == "admin"
    assert users.users[0].enabled is True
    assert users.users[0].groups == ("full",)
    assert users.users[0].inactivity_timeout_seconds == 600
    assert users.users[0].inactivity_policy == "none"

def test_services_listen():
    svc = mikrotik_services(load("ip_service.json"))
    by_name = {s.name: s for s in svc.services}
    assert by_name["www"].listen == "all"
    assert by_name["www-ssl"].listen == "restricted"

def test_ntp_dns_system():
    assert mikrotik_ntp(load("ntp_client.json")).servers == ("1.1.1.1",)
    assert mikrotik_dns(load("ip_dns.json")).servers == ("8.8.8.8", "1.1.1.1")
    info = mikrotik_system(load("system_resource.json"), load("system_routerboard.json"))
    assert info.firmware.startswith("7.16")
    assert info.current_firmware == "7.16.1"

def test_filter_any_and_drop():
    policies = mikrotik_filter(load("ip_firewall_filter.json"))
    assert policies.policies[0].src == ("any",)
    assert policies.policies[0].action == "accept"
    assert policies.policies[0].log is False
    assert policies.policies[0].chain == "forward"
    assert policies.policies[0].connection_state == ("established", "related")
    assert policies.policies[0].in_interface == ""
    assert policies.policies[1].action == "drop"
    lan = mikrotik_filter(
        {
            "chain": "forward",
            "action": "accept",
            "in-interface": "Lan/Lan",
            "out-interface": "pppoe-out",
        }
    ).policies[0]
    assert lan.in_interface == "Lan/Lan"
    assert lan.out_interface == "pppoe-out"


def test_admin_l1_timezone_password_and_ports():
    admin = mikrotik_admin_settings(
        load("system_identity.json"),
        {"minimum-timeout": "10m", "minimum-password-length": 14},
        {"time-zone-name": "Europe/Madrid"},
        load("ip_service.json"),
    )
    assert admin.timezone == "Europe/Madrid"
    assert admin.password_policy_enabled is True
    assert admin.password_min_length == 14
    assert admin.password_apply_to == ("admin-password",)
    assert admin.admin_http_port == 80
    assert admin.admin_https_port == 443
    assert admin.admin_http_enabled is True
    assert admin.admin_https_enabled is True
    assert admin.admin_https_redirect is False

def test_admin_and_logging_and_snmp():
    admin = mikrotik_admin_settings(load("system_identity.json"), load("user_settings.json"))
    assert admin.hostname == "MikroTik"
    assert admin.idle_timeout_seconds == 600
    log = mikrotik_logging(load("system_logging.json"), load("system_logging_action.json"))
    assert log.local_enabled is True
    assert log.remote_targets == ("10.0.0.9",)
    unused = mikrotik_logging(
        [{"topics": "info", "action": "memory"}],
        [{"name": "remote", "target": "remote", "remote": "0.0.0.0"}],
    )
    assert unused.remote_targets == ()
    placeholder_rule = mikrotik_logging(
        [{"topics": "info", "action": "remote"}],
        [{"name": "remote", "target": "remote", "remote": "0.0.0.0"}],
    )
    assert placeholder_rule.remote_targets == ()
    snmp = mikrotik_snmp(load("snmp.json"), load("snmp_community.json"))
    assert snmp.communities[0].name == "public"
    assert snmp.communities[0].version == "none"
    assert snmp.communities[0].read_access is True


def test_as_any_token():
    for value in ("", "*", "all", "ANY", "0.0.0.0/0", "::/0", None):
        assert as_any_token(value) == "any"
    assert as_any_token("10.0.0.1") == "10.0.0.1"


def test_timeout_units_and_singleton_payloads():
    assert mikrotik_admin_settings({"name": "fw"}, {"session-timeout": "30s"}).idle_timeout_seconds == 30
    assert mikrotik_admin_settings({"name": "fw"}, {"minimum-timeout": "1h"}).idle_timeout_seconds == 3600
    assert mikrotik_admin_settings({"name": "fw"}, {"minimum-timeout": 15}).idle_timeout_seconds == 15
    user = mikrotik_users({"name": "bob", "group": "read", "disabled": True}).users[0]
    assert user.name == "bob"
    assert user.enabled is False
    assert mikrotik_filter({"action": "reject"}).policies[0].action == "deny"


def test_l2_access_factory_defaults():
    l2 = mikrotik_l2_access(
        {"discover-interface-list": "static"},
        {"allowed-interface-list": "all"},
        {"allowed-interface-list": "all"},
        {"enabled": "true"},
    )
    assert l2.discover_interface_list == "static"
    assert l2.mac_telnet_interface_list == "all"
    assert l2.mac_winbox_interface_list == "all"
    assert l2.mac_ping_enabled is True


def test_l2_access_hardened():
    l2 = mikrotik_l2_access(
        load("neighbor_discovery.json"),
        load("mac_server.json"),
        load("mac_winbox.json"),
        load("mac_ping.json"),
    )
    assert l2.discover_interface_list == "none"
    assert l2.mac_telnet_interface_list == "none"
    assert l2.mac_winbox_interface_list == "none"
    assert l2.mac_ping_enabled is False


def test_services_merge_aux_and_pptp():
    svc = mikrotik_services(
        load("ip_service.json"),
        {
            "bandwidth-server": {"enabled": "true"},
            "proxy": {"enabled": "false"},
            "socks": {"enabled": "no"},
            "upnp": {"enabled": "false"},
            "cloud": {"ddns-enabled": "true", "update-time": "false"},
            "pptp": {"enabled": "yes"},
        },
    )
    by_name = {s.name: s for s in svc.services}
    assert by_name["bandwidth-server"].enabled is True
    assert by_name["proxy"].enabled is False
    assert by_name["cloud-ddns"].enabled is True
    assert by_name["cloud-update-time"].enabled is False
    assert by_name["pptp"].enabled is True


def test_admin_ssh_strong_crypto():
    admin = mikrotik_admin_settings(
        load("system_identity.json"),
        load("user_settings.json"),
        ssh_raw={"strong-crypto": "true"},
    )
    assert admin.ssh_strong_crypto is True


def test_system_package_update():
    info = mikrotik_system(
        load("system_resource.json"),
        load("system_routerboard.json"),
        {"status": "System is already up to date", "installed-version": "7.16.1", "latest-version": "7.16.1"},
    )
    assert info.update_status == "System is already up to date"
    assert info.installed_version == "7.16.1"
    assert info.latest_version == "7.16.1"
