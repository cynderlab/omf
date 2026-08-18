import json
from pathlib import Path
from omf.adapters.normalize import as_any_token
from omf.adapters.mikrotik import (
    mikrotik_users, mikrotik_services, mikrotik_ntp, mikrotik_dns,
    mikrotik_admin_settings, mikrotik_logging, mikrotik_snmp,
    mikrotik_filter, mikrotik_system,
)

FIX = Path(__file__).parent / "fixtures" / "mikrotik"

def load(name: str):
    return json.loads((FIX / name).read_text())

def test_users():
    users = mikrotik_users(load("user.json"))
    assert users.users[0].name == "admin"
    assert users.users[0].enabled is True
    assert users.users[0].groups == ("full",)

def test_services_listen():
    svc = mikrotik_services(load("ip_service.json"))
    by_name = {s.name: s for s in svc.services}
    assert by_name["www"].listen == "all"
    assert by_name["www-ssl"].listen == "restricted"

def test_ntp_dns_system():
    assert mikrotik_ntp(load("ntp_client.json")).servers == ("1.1.1.1",)
    assert mikrotik_dns(load("ip_dns.json")).servers == ("8.8.8.8", "1.1.1.1")
    info = mikrotik_system(load("system_resource.json"))
    assert info.firmware.startswith("7.16")

def test_filter_any_and_drop():
    policies = mikrotik_filter(load("ip_firewall_filter.json"))
    assert policies.policies[0].src == ("any",)
    assert policies.policies[0].action == "accept"
    assert policies.policies[1].action == "drop"

def test_admin_and_logging_and_snmp():
    admin = mikrotik_admin_settings(load("system_identity.json"), load("user_settings.json"))
    assert admin.hostname == "MikroTik"
    assert admin.idle_timeout_seconds == 600
    log = mikrotik_logging(load("system_logging.json"), load("system_logging_action.json"))
    assert log.local_enabled is True
    assert log.remote_targets
    snmp = mikrotik_snmp(load("snmp.json"), load("snmp_community.json"))
    assert snmp.communities[0].name == "public"


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
