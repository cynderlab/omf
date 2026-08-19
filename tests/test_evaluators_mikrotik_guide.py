from datetime import datetime, timezone

from omf.baseline.evaluators.admin import flag_enabled
from omf.baseline.evaluators.l2 import l2_surfaces_closed
from omf.baseline.evaluators.services import named_services_disabled
from omf.baseline.evaluators.system import firmware_update_current
from omf.schema.capabilities import AdminSettings, L2Access, Service, ServiceList, SystemInfo
from omf.schema.evidence import Evidence


def ev(capability, payload, vendor="mikrotik"):
    return Evidence(
        capability=capability,
        vendor=vendor,
        collected_at=datetime.now(timezone.utc),
        payload=payload,
    )


def _l2(**overrides) -> L2Access:
    base = dict(
        discover_interface_list="none",
        mac_telnet_interface_list="none",
        mac_winbox_interface_list="none",
        mac_ping_enabled=False,
    )
    base.update(overrides)
    return L2Access(**base)


def test_neighbor_discovery_none_passes():
    evidence = {"l2_access": ev("l2_access", _l2())}
    r = l2_surfaces_closed(evidence, {"lists": ["discover_interface_list"]}, "mikrotik")
    assert r.status == "pass"


def test_neighbor_discovery_static_fails():
    evidence = {"l2_access": ev("l2_access", _l2(discover_interface_list="static"))}
    r = l2_surfaces_closed(evidence, {"lists": ["discover_interface_list"]}, "mikrotik")
    assert r.status == "fail"
    assert "static" in r.diagnostic


def test_neighbor_discovery_custom_list_fails():
    evidence = {"l2_access": ev("l2_access", _l2(discover_interface_list="LAN"))}
    r = l2_surfaces_closed(evidence, {"lists": ["discover_interface_list"]}, "mikrotik")
    assert r.status == "fail"


def test_mac_access_closed_passes():
    evidence = {"l2_access": ev("l2_access", _l2())}
    r = l2_surfaces_closed(
        evidence,
        {
            "lists": ["mac_telnet_interface_list", "mac_winbox_interface_list"],
            "flags_off": ["mac_ping_enabled"],
        },
        "mikrotik",
    )
    assert r.status == "pass"


def test_mac_access_fails_open_winbox_or_ping():
    lists = ["mac_telnet_interface_list", "mac_winbox_interface_list"]
    flags = ["mac_ping_enabled"]
    winbox = l2_surfaces_closed(
        {"l2_access": ev("l2_access", _l2(mac_winbox_interface_list="all"))},
        {"lists": lists, "flags_off": flags},
        "mikrotik",
    )
    ping = l2_surfaces_closed(
        {"l2_access": ev("l2_access", _l2(mac_ping_enabled=True))},
        {"lists": lists, "flags_off": flags},
        "mikrotik",
    )
    assert winbox.status == "fail"
    assert ping.status == "fail"


def test_named_aux_services_fail_when_enabled():
    evidence = {"services": ev("services", ServiceList(services=(
        Service(name="bandwidth-server", enabled=True, port=0, listen="restricted"),
        Service(name="proxy", enabled=False, port=0, listen="restricted"),
    )))}
    r = named_services_disabled(
        evidence,
        {"names": ["bandwidth-server", "proxy", "socks", "upnp", "cloud-ddns", "cloud-update-time"]},
        "mikrotik",
    )
    assert r.status == "fail"
    assert r.observed["names"] == ["bandwidth-server"]


def test_named_aux_services_pass_when_disabled():
    evidence = {"services": ev("services", ServiceList(services=(
        Service(name="bandwidth-server", enabled=False, port=0, listen="restricted"),
        Service(name="pptp", enabled=False, port=0, listen="restricted"),
    )))}
    r = named_services_disabled(evidence, {"names": ["bandwidth-server", "pptp"]}, "mikrotik")
    assert r.status == "pass"


def test_pptp_server_enabled_fails():
    evidence = {"services": ev("services", ServiceList(services=(
        Service(name="pptp", enabled=True, port=0, listen="restricted"),
    )))}
    r = named_services_disabled(evidence, {"names": ["pptp"]}, "mikrotik")
    assert r.status == "fail"


def test_ssh_strong_crypto_flag():
    bad = {"admin_settings": ev("admin_settings", AdminSettings(hostname="fw", ssh_strong_crypto=False))}
    good = {"admin_settings": ev("admin_settings", AdminSettings(hostname="fw", ssh_strong_crypto=True))}
    assert flag_enabled(bad, {"field": "ssh_strong_crypto"}, "mikrotik").status == "fail"
    assert flag_enabled(good, {"field": "ssh_strong_crypto"}, "mikrotik").status == "pass"


def test_firmware_update_current_status_up_to_date():
    evidence = {"system_info": ev("system_info", SystemInfo(
        firmware="7.16.1",
        update_status="System is already up to date",
        installed_version="7.16.1",
        latest_version="7.16.1",
    ))}
    assert firmware_update_current(evidence, {}, "mikrotik").status == "pass"


def test_firmware_update_current_newer_available_fails():
    evidence = {"system_info": ev("system_info", SystemInfo(
        firmware="7.16.1",
        update_status="New version is available",
        installed_version="7.16.1",
        latest_version="7.16.2",
    ))}
    r = firmware_update_current(evidence, {}, "mikrotik")
    assert r.status == "fail"
    assert "7.16.2" in r.diagnostic


def test_firmware_update_current_never_checked_fails():
    evidence = {"system_info": ev("system_info", SystemInfo(firmware="7.16.1"))}
    r = firmware_update_current(evidence, {}, "mikrotik")
    assert r.status == "fail"
    assert "no update check" in r.diagnostic.lower()
