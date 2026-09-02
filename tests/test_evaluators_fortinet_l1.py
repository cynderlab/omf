from datetime import datetime, timezone

from omf.baseline.evaluators.admin import (
    admin_ports_changed,
    flag_enabled,
    lockout_configured,
    password_policy_strong,
    timezone_set,
    tls_versions_allowed,
)
from omf.baseline.evaluators.logging import faz_encrypted, syslog_encrypted
from omf.baseline.evaluators.ha import ha_monitors_set, ha_reserved_mgmt
from omf.baseline.evaluators.local_in import local_in_present, virtual_patch_on_accept
from omf.baseline.evaluators.network import intrazone_denied
from omf.baseline.evaluators.policy import (
    isdb_denies_present,
    no_unrestricted_service,
    policies_logged,
)
from omf.baseline.evaluators.services import wan_mgmt_disabled
from omf.baseline.evaluators.snmp import snmp_memory_traps, snmp_not_legacy
from omf.baseline.evaluators.utm import (
    stitch_enabled,
    utm_on_accept,
    utm_profile_blocks,
    utm_profile_log_all,
    utm_profile_no_allow,
)
from omf.schema.capabilities import (
    AdminSettings,
    AutomationStitch,
    HaConfig,
    LocalInPolicy,
    LocalInPolicyList,
    LoggingConfig,
    Policy,
    PolicyList,
    Service,
    ServiceList,
    SnmpConfig,
    SnmpUser,
    UtmConfig,
    UtmProfile,
    Zone,
    ZoneList,
)
from omf.schema.evidence import Evidence


def ev(capability, payload):
    return Evidence(
        capability=capability,
        vendor="fortinet",
        collected_at=datetime.now(timezone.utc),
        payload=payload,
    )


def settings(**kwargs):
    base = {"hostname": "hq-fw"}
    base.update(kwargs)
    return ev("admin_settings", AdminSettings(**base))


def test_pre_login_banner_fail_when_disabled():
    r = flag_enabled({"admin_settings": settings(pre_login_banner=False)}, {"field": "pre_login_banner"}, "fortinet")
    assert r.status == "fail"


def test_timezone_pass_when_set():
    r = timezone_set({"admin_settings": settings(timezone="US/Eastern")}, {}, "fortinet")
    assert r.status == "pass"


def test_tls_fail_when_v12_present():
    r = tls_versions_allowed(
        {"admin_settings": settings(admin_https_ssl_versions=("tlsv1-2", "tlsv1-3"))},
        {"allowed": ["tlsv1-3"]},
        "fortinet",
    )
    assert r.status == "fail"


def test_tls_pass_v13_only():
    r = tls_versions_allowed(
        {"admin_settings": settings(admin_https_ssl_versions=("tlsv1-3",))},
        {"allowed": ["tlsv1-3"]},
        "fortinet",
    )
    assert r.status == "pass"


def test_password_policy_requires_length_14():
    weak = settings(password_policy_enabled=True, password_min_length=8, password_apply_to=("admin-password",))
    assert password_policy_strong({"admin_settings": weak}, {"min_length": 14, "apply_to": ["admin-password"]}, "fortinet").status == "fail"
    strong = settings(password_policy_enabled=True, password_min_length=14, password_apply_to=("admin-password", "ipsec-preshared-key"))
    assert password_policy_strong({"admin_settings": strong}, {"min_length": 14, "apply_to": ["admin-password"]}, "fortinet").status == "pass"


def test_lockout_bounds():
    bad = settings(admin_lockout_threshold=5, admin_lockout_duration=1800)
    assert lockout_configured({"admin_settings": bad}, {"max_threshold": 3, "max_duration": 900}, "fortinet").status == "fail"
    good = settings(admin_lockout_threshold=3, admin_lockout_duration=900)
    assert lockout_configured({"admin_settings": good}, {"max_threshold": 3, "max_duration": 900}, "fortinet").status == "pass"


def test_admin_ports_and_cpu_flag():
    bad = settings(admin_http_port=80, admin_https_port=443, admin_https_redirect=True, log_single_cpu_high=False)
    assert admin_ports_changed({"admin_settings": bad}, {"forbidden_http": 80, "forbidden_https": 443}, "fortinet").status == "fail"
    assert flag_enabled({"admin_settings": bad}, {"field": "log_single_cpu_high"}, "fortinet").status == "fail"
    good = settings(admin_http_port=8082, admin_https_port=4343, admin_https_redirect=False, log_single_cpu_high=True)
    assert admin_ports_changed({"admin_settings": good}, {"forbidden_http": 80, "forbidden_https": 443}, "fortinet").status == "pass"
    assert flag_enabled({"admin_settings": good}, {"field": "log_single_cpu_high"}, "fortinet").status == "pass"


def test_wan_mgmt_disabled_fails_for_https_on_wan():
    services = ev(
        "services",
        ServiceList(
            services=(
                Service(name="https", enabled=True, port=443, listen="restricted", on_wan=True),
                Service(name="telnet", enabled=False, port=23, listen="unknown", on_wan=False),
            )
        ),
    )
    r = wan_mgmt_disabled(
        {"services": services},
        {"wan_mgmt": ["https", "http", "ping", "ssh", "snmp", "radius-acct"]},
        "fortinet",
    )
    assert r.status == "fail"
    assert any(row["name"] == "https" for row in r.observed["services"])
    assert r.observed["services"][0]["on_wan"] is True


def test_intrazone_denied_fail_allow_pass_deny():
    allow = ev("zones", ZoneList(zones=(Zone(name="DMZ", intrazone="allow"),)))
    deny = ev("zones", ZoneList(zones=(Zone(name="DMZ", intrazone="deny"),)))
    assert intrazone_denied({"zones": allow}, {}, "fortinet").status == "fail"
    assert intrazone_denied({"zones": deny}, {}, "fortinet").status == "pass"


def test_snmp_require_v3_user():
    no_users = ev("snmp", SnmpConfig(enabled=True, communities=()))
    assert snmp_not_legacy({"snmp": no_users}, {"require_v3_user": True}, "fortinet").status == "fail"
    with_user = ev(
        "snmp",
        SnmpConfig(
            enabled=True,
            communities=(),
            users=(SnmpUser(name="monitor", security_level="auth-priv"),),
        ),
    )
    assert snmp_not_legacy({"snmp": with_user}, {"require_v3_user": True}, "fortinet").status == "pass"
    disabled = ev("snmp", SnmpConfig(enabled=False, communities=()))
    assert snmp_not_legacy({"snmp": disabled}, {"require_v3_user": True}, "fortinet").status == "pass"


def test_snmp_memory_traps():
    disabled = ev("snmp", SnmpConfig(enabled=False, communities=()))
    assert snmp_memory_traps({"snmp": disabled}, {}, "fortinet").status == "pass"
    zero = ev(
        "snmp",
        SnmpConfig(
            enabled=True,
            communities=(),
            trap_free_memory_threshold=0,
            trap_freeable_memory_threshold=0,
        ),
    )
    assert snmp_memory_traps({"snmp": zero}, {}, "fortinet").status == "fail"
    ok = ev(
        "snmp",
        SnmpConfig(
            enabled=True,
            communities=(),
            trap_free_memory_threshold=20,
            trap_freeable_memory_threshold=50,
        ),
    )
    assert snmp_memory_traps({"snmp": ok}, {}, "fortinet").status == "pass"


def test_syslog_and_faz_encrypted():
    no_remotes = ev("logging", LoggingConfig(local_enabled=True, remote_targets=()))
    assert syslog_encrypted({"logging": no_remotes}, {}, "fortinet").status == "pass"
    bad_syslog = ev(
        "logging",
        LoggingConfig(
            local_enabled=True,
            remote_targets=("10.0.0.9",),
            syslog_reliable=False,
            syslog_enc_high=False,
        ),
    )
    assert syslog_encrypted({"logging": bad_syslog}, {}, "fortinet").status == "fail"
    faz_off = ev("logging", LoggingConfig(local_enabled=True, remote_targets=(), faz_enabled=False))
    assert faz_encrypted({"logging": faz_off}, {}, "fortinet").status == "pass"
    faz_bad = ev(
        "logging",
        LoggingConfig(
            local_enabled=True,
            remote_targets=(),
            faz_enabled=True,
            faz_reliable=False,
            faz_enc_high=False,
        ),
    )
    assert faz_encrypted({"logging": faz_bad}, {}, "fortinet").status == "fail"


def test_no_unrestricted_service_fails_on_any():
    bad = ev(
        "firewall_filter",
        PolicyList(
            policies=(
                Policy(
                    id="1",
                    enabled=True,
                    action="accept",
                    src=("any",),
                    dst=("any",),
                    service=("any",),
                    log=False,
                ),
            )
        ),
    )
    assert no_unrestricted_service({"firewall_filter": bad}, {}, "fortinet").status == "fail"


def test_policies_logged_requires_policy_and_implicit():
    unlogged = ev(
        "firewall_filter",
        PolicyList(
            policies=(
                Policy(
                    id="1",
                    enabled=True,
                    action="accept",
                    src=("lan",),
                    dst=("wan",),
                    service=("HTTPS",),
                    log=False,
                ),
            )
        ),
    )
    implicit_off = ev("logging", LoggingConfig(local_enabled=True, remote_targets=(), implicit_policy_logged=False))
    assert policies_logged({"firewall_filter": unlogged, "logging": implicit_off}, {}, "fortinet").status == "fail"
    logged = ev(
        "firewall_filter",
        PolicyList(
            policies=(
                Policy(
                    id="1",
                    enabled=True,
                    action="accept",
                    src=("lan",),
                    dst=("wan",),
                    service=("HTTPS",),
                    log=True,
                ),
            )
        ),
    )
    assert policies_logged({"firewall_filter": logged, "logging": implicit_off}, {}, "fortinet").status == "fail"
    implicit_on = ev("logging", LoggingConfig(local_enabled=True, remote_targets=(), implicit_policy_logged=True))
    assert policies_logged({"firewall_filter": logged, "logging": implicit_on}, {}, "fortinet").status == "pass"


def test_isdb_denies_present():
    params = {
        "isdb_inbound": ["Tor-Exit.Node", "Shodan-Scanner"],
        "isdb_outbound": ["Tor-Relay.Node", "Botnet-C&C.Server"],
    }
    empty = ev(
        "firewall_filter",
        PolicyList(
            policies=(
                Policy(
                    id="1",
                    enabled=True,
                    action="deny",
                    src=("any",),
                    dst=("any",),
                    service=("any",),
                    internet_src=(),
                    internet_dst=(),
                ),
            )
        ),
    )
    assert isdb_denies_present({"firewall_filter": empty}, params, "fortinet").status == "fail"
    covered = ev(
        "firewall_filter",
        PolicyList(
            policies=(
                Policy(
                    id="10",
                    enabled=True,
                    action="deny",
                    src=("any",),
                    dst=("any",),
                    service=("ALL",),
                    internet_src=("Tor-Exit.Node", "Shodan-Scanner", "Extra"),
                ),
                Policy(
                    id="11",
                    enabled=True,
                    action="drop",
                    src=("any",),
                    dst=("any",),
                    service=("ALL",),
                    internet_dst=("Tor-Relay.Node", "Botnet-C&C.Server"),
                ),
            )
        ),
    )
    assert isdb_denies_present({"firewall_filter": covered}, params, "fortinet").status == "pass"


def test_local_in_present_and_virtual_patch():
    empty = ev("local_in", LocalInPolicyList(policies=()))
    assert local_in_present({"local_in": empty}, {}, "fortinet").status == "fail"
    no_patch = ev(
        "local_in",
        LocalInPolicyList(
            policies=(LocalInPolicy(id="1", enabled=True, action="accept", virtual_patch=False),)
        ),
    )
    assert local_in_present({"local_in": no_patch}, {}, "fortinet").status == "pass"
    assert virtual_patch_on_accept({"local_in": no_patch}, {}, "fortinet").status == "fail"
    patched = ev(
        "local_in",
        LocalInPolicyList(
            policies=(LocalInPolicy(id="1", enabled=True, action="accept", virtual_patch=True),)
        ),
    )
    assert virtual_patch_on_accept({"local_in": patched}, {}, "fortinet").status == "pass"
    deny_only = ev(
        "local_in",
        LocalInPolicyList(
            policies=(LocalInPolicy(id="2", enabled=True, action="deny", virtual_patch=False),)
        ),
    )
    assert virtual_patch_on_accept({"local_in": deny_only}, {}, "fortinet").status == "pass"


def test_ha_checks_standalone_and_active():
    standalone = ev("ha", HaConfig(mode="standalone"))
    assert ha_monitors_set({"ha": standalone}, {}, "fortinet").status == "pass"
    assert ha_reserved_mgmt({"ha": standalone}, {}, "fortinet").status == "pass"
    empty_mon = ev(
        "ha",
        HaConfig(mode="a-p", monitor_interfaces=(), ha_mgmt_status=True, ha_mgmt_interfaces=("port6",)),
    )
    assert ha_monitors_set({"ha": empty_mon}, {}, "fortinet").status == "fail"
    no_mgmt = ev(
        "ha",
        HaConfig(mode="a-p", monitor_interfaces=("port6",), ha_mgmt_status=False, ha_mgmt_interfaces=()),
    )
    assert ha_reserved_mgmt({"ha": no_mgmt}, {}, "fortinet").status == "fail"
    ok = ev(
        "ha",
        HaConfig(
            mode="a-p",
            monitor_interfaces=("port6", "port7"),
            ha_mgmt_status=True,
            ha_mgmt_interfaces=("port6",),
        ),
    )
    assert ha_monitors_set({"ha": ok}, {}, "fortinet").status == "pass"
    assert ha_reserved_mgmt({"ha": ok}, {}, "fortinet").status == "pass"


def _policy(field, value):
    kwargs = {
        "id": "1",
        "enabled": True,
        "action": "accept",
        "src": ("lan",),
        "dst": ("wan",),
        "service": ("HTTPS",),
        field: value,
    }
    return ev("firewall_filter", PolicyList(policies=(Policy(**kwargs),)))


def test_utm_on_accept_ips_dns_app():
    missing = ev(
        "firewall_filter",
        PolicyList(
            policies=(
                Policy(
                    id="1",
                    enabled=True,
                    action="accept",
                    src=("lan",),
                    dst=("wan",),
                    service=("HTTPS",),
                ),
            )
        ),
    )
    assert utm_on_accept({"firewall_filter": missing}, {"field": "ips_sensor"}, "fortinet").status == "fail"
    assert utm_on_accept({"firewall_filter": missing}, {"field": "dnsfilter_profile"}, "fortinet").status == "fail"
    assert utm_on_accept({"firewall_filter": missing}, {"field": "application_list"}, "fortinet").status == "fail"
    assert utm_on_accept({"firewall_filter": _policy("ips_sensor", "default")}, {"field": "ips_sensor"}, "fortinet").status == "pass"
    assert utm_on_accept({"firewall_filter": _policy("dnsfilter_profile", "default")}, {"field": "dnsfilter_profile"}, "fortinet").status == "pass"
    assert utm_on_accept({"firewall_filter": _policy("application_list", "default")}, {"field": "application_list"}, "fortinet").status == "pass"


def test_utm_profile_log_all():
    off = ev("utm", UtmConfig(profiles=(UtmProfile(name="default", kind="dnsfilter", log_all=False),)))
    assert utm_profile_log_all({"utm": off}, {}, "fortinet").status == "fail"
    on = ev("utm", UtmConfig(profiles=(UtmProfile(name="default", kind="dnsfilter", log_all=True),)))
    assert utm_profile_log_all({"utm": on}, {}, "fortinet").status == "pass"


def test_utm_profile_blocks_web_and_app():
    web_partial = ev(
        "utm",
        UtmConfig(profiles=(UtmProfile(name="default", kind="webfilter", blocked_categories=("malicious",)),)),
    )
    assert utm_profile_blocks(
        {"utm": web_partial},
        {"kind": "webfilter", "webfilter_block": ["malicious", "phishing", "spam"]},
        "fortinet",
    ).status == "fail"
    web_ok = ev(
        "utm",
        UtmConfig(
            profiles=(
                UtmProfile(
                    name="default",
                    kind="webfilter",
                    blocked_categories=("malicious", "phishing", "spam", "dynamic-dns"),
                ),
            )
        ),
    )
    assert utm_profile_blocks(
        {"utm": web_ok},
        {"kind": "webfilter", "webfilter_block": ["malicious", "phishing", "spam"]},
        "fortinet",
    ).status == "pass"
    app_partial = ev(
        "utm",
        UtmConfig(profiles=(UtmProfile(name="default", kind="appctrl", blocked_categories=("p2p",)),)),
    )
    assert utm_profile_blocks(
        {"utm": app_partial},
        {"kind": "appctrl", "appctrl_block": ["p2p", "proxy"]},
        "fortinet",
    ).status == "fail"
    app_ok = ev(
        "utm",
        UtmConfig(profiles=(UtmProfile(name="default", kind="appctrl", blocked_categories=("p2p", "proxy")),)),
    )
    assert utm_profile_blocks(
        {"utm": app_ok},
        {"kind": "appctrl", "appctrl_block": ["p2p", "proxy"]},
        "fortinet",
    ).status == "pass"


def test_utm_profile_no_allow():
    allowed = ev(
        "utm",
        UtmConfig(profiles=(UtmProfile(name="default", kind="appctrl", allowed_categories=("proxy",)),)),
    )
    assert utm_profile_no_allow({"utm": allowed}, {}, "fortinet").status == "fail"
    blocked_only = ev(
        "utm",
        UtmConfig(profiles=(UtmProfile(name="default", kind="appctrl", blocked_categories=("p2p", "proxy")),)),
    )
    assert utm_profile_no_allow({"utm": blocked_only}, {}, "fortinet").status == "pass"


def test_stitch_enabled():
    off = ev(
        "utm",
        UtmConfig(stitches=(AutomationStitch(name="Compromised Host Quarantine", enabled=False),)),
    )
    assert stitch_enabled({"utm": off}, {}, "fortinet").status == "fail"
    missing = ev("utm", UtmConfig())
    assert stitch_enabled({"utm": missing}, {}, "fortinet").status == "fail"
    on = ev(
        "utm",
        UtmConfig(stitches=(AutomationStitch(name="compromised host quarantine", enabled=True),)),
    )
    assert stitch_enabled({"utm": on}, {}, "fortinet").status == "pass"

