from datetime import datetime, timezone

from omf.baseline.evaluators.admin import (
    admin_ports_changed,
    banner_enabled,
    flag_enabled,
    lockout_configured,
    password_policy_strong,
    timezone_set,
    tls_versions_allowed,
)
from omf.baseline.evaluators.network import intrazone_denied
from omf.baseline.evaluators.services import wan_mgmt_disabled
from omf.schema.capabilities import AdminSettings, Service, ServiceList, Zone, ZoneList
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
    r = banner_enabled({"admin_settings": settings(pre_login_banner=False)}, {"field": "pre_login_banner"}, "fortinet")
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
    assert "https" in r.observed["names"]


def test_intrazone_denied_fail_allow_pass_deny():
    allow = ev("zones", ZoneList(zones=(Zone(name="DMZ", intrazone="allow"),)))
    deny = ev("zones", ZoneList(zones=(Zone(name="DMZ", intrazone="deny"),)))
    assert intrazone_denied({"zones": allow}, {}, "fortinet").status == "fail"
    assert intrazone_denied({"zones": deny}, {}, "fortinet").status == "pass"
