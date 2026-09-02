"""Fortinet FortiOS REST normalizers."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from omf.adapters.normalize import as_any_token
from omf.schema.capabilities import (
    AdminSettings,
    AutomationStitch,
    DnsConfig,
    HaConfig,
    Listen,
    LicenseEntitlement,
    LicenseStatus,
    LocalInPolicy,
    LocalInPolicyList,
    LoggingConfig,
    NtpConfig,
    Policy,
    PolicyAction,
    PolicyList,
    Service,
    ServiceList,
    SnmpCommunity,
    SnmpConfig,
    SnmpUser,
    SystemInfo,
    User,
    UserList,
    UsageItem,
    UsageList,
    UtmConfig,
    UtmProfile,
    Zone,
    ZoneList,
)

_TRUE = frozenset({"true", "yes", "1", "on", "enable", "enabled"})
_FALSE = frozenset({"false", "no", "0", "off", "disable", "disabled", ""})
_ACTION_MAP: dict[str, PolicyAction] = {
    "accept": "accept",
    "deny": "deny",
    "drop": "drop",
    "reject": "deny",
}
_MGMT_PROTOCOLS: tuple[tuple[str, int], ...] = (
    ("https", 443),
    ("ssh", 22),
    ("http", 80),
    ("telnet", 23),
    ("ftp", 21),
    ("ping", 0),
    ("snmp", 161),
    ("radius-acct", 1813),
)
_WAN_NAME = re.compile(r"^wan\d*$", re.IGNORECASE)
_UNRESTRICTED_TRUSTHOSTS = frozenset({"0.0.0.0 0.0.0.0", "::/0 ::/0"})


def forti_unwrap(raw: object) -> object:
    if isinstance(raw, dict) and "results" in raw:
        return raw["results"]
    return raw


def _as_records(raw: object) -> list[dict[str, Any]]:
    payload = forti_unwrap(raw)
    if payload is None:
        return []
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        return [payload]
    return []


def _as_record(raw: object) -> dict[str, Any]:
    records = _as_records(raw)
    return records[0] if records else {}


def _as_bool(value: object, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    return default


def _admin_enabled(item: dict[str, Any]) -> bool:
    if "status" not in item:
        return True
    return _as_bool(item.get("status"), default=True)


def _allowaccess_tokens(value: object) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, (list, tuple)):
        parts = [str(item).strip().lower() for item in value]
    else:
        text = str(value).replace(",", " ")
        parts = [part.strip().lower() for part in text.split()]
    return {part for part in parts if part}


def _is_wan(item: dict[str, Any]) -> bool:
    role = str(item.get("role") or "").strip().lower()
    if role == "wan":
        return True
    return bool(_WAN_NAME.fullmatch(str(item.get("name") or "").strip()))


def _is_trusthost_key(key: object) -> bool:
    return str(key).lower().startswith("trusthost")


def _has_trusthost_keys(item: dict[str, Any]) -> bool:
    return any(_is_trusthost_key(key) for key in item)


def _trusthost_leaves(value: object) -> list[object]:
    if isinstance(value, dict):
        leaves: list[object] = []
        for key, inner in value.items():
            low = str(key).lower()
            if low in {"ipv4-trusthost", "ipv6-trusthost", "ip"} or _is_trusthost_key(key):
                leaves.extend(_trusthost_leaves(inner))
        return leaves or [value]
    if isinstance(value, (list, tuple)):
        leaves: list[object] = []
        for item in value:
            leaves.extend(_trusthost_leaves(item))
        return leaves
    return [value]


def _trusthost_values(item: dict[str, Any]) -> list[object]:
    leaves: list[object] = []
    for key, value in item.items():
        if _is_trusthost_key(key):
            leaves.extend(_trusthost_leaves(value))
    return leaves


def _trusthost_is_restricted(value: object) -> bool:
    if value in (None, ""):
        return False
    text = str(value).strip()
    if not text:
        return False
    if text in _UNRESTRICTED_TRUSTHOSTS:
        return False
    return as_any_token(text) != "any"


def _services_listen(admins: list[dict[str, Any]]) -> Listen:
    if not any(_has_trusthost_keys(item) for item in admins):
        return "unknown"
    enabled = [item for item in admins if _admin_enabled(item)]
    if not enabled:
        return "unknown"
    for admin in enabled:
        if not any(_trusthost_is_restricted(value) for value in _trusthost_values(admin)):
            return "all"
    return "restricted"


def _named_tokens(value: object) -> tuple[str, ...]:
    if value is None:
        return ("any",)
    if isinstance(value, (list, tuple)):
        if not value:
            return ("any",)
        tokens: list[str] = []
        for item in value:
            if isinstance(item, dict):
                tokens.append(as_any_token(item.get("name")))
            else:
                tokens.append(as_any_token(item))
        return tuple(tokens)
    if isinstance(value, dict):
        return (as_any_token(value.get("name")),)
    return (as_any_token(value),)


def _dns_servers(item: dict[str, Any]) -> tuple[str, ...]:
    servers: list[str] = []
    for key in ("primary", "secondary"):
        value = item.get(key)
        if value in (None, ""):
            continue
        text = str(value).strip()
        if text:
            servers.append(text)
    return tuple(servers)


def _ntp_servers(item: dict[str, Any]) -> tuple[str, ...]:
    raw = item.get("ntpserver", item.get("server"))
    if raw is None:
        return ()
    if isinstance(raw, str):
        text = raw.strip()
        return (text,) if text else ()
    if isinstance(raw, (list, tuple)):
        servers: list[str] = []
        for entry in raw:
            if isinstance(entry, dict):
                value = entry.get("server")
            else:
                value = entry
            if value in (None, ""):
                continue
            text = str(value).strip()
            if text:
                servers.append(text)
        return tuple(servers)
    text = str(raw).strip()
    return (text,) if text else ()


def _syslog_targets(raw: object) -> tuple[str, ...]:
    if raw is None:
        return ()
    item = _as_record(raw)
    if not _as_bool(item.get("status"), default=False):
        return ()
    server = item.get("server")
    if server in (None, ""):
        return ()
    text = str(server).strip()
    return (text,) if text else ()


def _snmp_version(item: dict[str, Any]) -> str:
    versions: list[str] = []
    if _as_bool(item.get("query-v1-status"), default=False):
        versions.append("1")
    if _as_bool(item.get("query-v2c-status"), default=False) or _as_bool(
        item.get("query-v2-status"), default=False
    ):
        versions.append("2")
    if _as_bool(item.get("query-v3-status"), default=False):
        versions.append("3")
    if versions:
        return "/".join(versions)
    version = item.get("version")
    return "" if version is None else str(version)


def _idle_timeout_seconds(value: object) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value) * 60
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(float(text)) * 60
    except ValueError:
        return None


def forti_users(raw: object) -> UserList:
    users: list[User] = []
    for item in _as_records(raw):
        profile = item.get("accprofile")
        groups = (str(profile),) if profile not in (None, "") else ()
        users.append(
            User(
                name=str(item.get("name") or ""),
                enabled=_admin_enabled(item),
                groups=groups,
            )
        )
    return UserList(users=tuple(users))


def _tokens(value: object) -> tuple[str, ...]:
    if value in (None, ""):
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(str(item).strip() for item in value if str(item).strip())
    return tuple(part for part in str(value).replace(",", " ").split() if part)


def _as_int(value: object) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(float(text))
    except ValueError:
        return None


def forti_admin_settings(
    global_raw: object,
    admin_raw: object,
    password_policy_raw: object | None = None,
) -> AdminSettings:
    _ = admin_raw
    item = _as_record(global_raw)
    policy = _as_record(password_policy_raw)
    timeout_raw = item.get("admintimeout")
    return AdminSettings(
        hostname=str(item.get("hostname") or ""),
        idle_timeout_seconds=_idle_timeout_seconds(timeout_raw) if timeout_raw is not None else None,
        pre_login_banner=_as_bool(item.get("pre-login-banner"), default=False) if "pre-login-banner" in item else None,
        post_login_banner=_as_bool(item.get("post-login-banner"), default=False) if "post-login-banner" in item else None,
        timezone=(str(item.get("timezone")).strip() if item.get("timezone") not in (None, "") else None),
        admin_https_ssl_versions=_tokens(item.get("admin-https-ssl-versions")),
        log_single_cpu_high=_as_bool(item.get("log-single-cpu-high"), default=False) if "log-single-cpu-high" in item else None,
        password_policy_enabled=_as_bool(policy.get("status"), default=False) if policy else None,
        password_min_length=_as_int(policy.get("minimum-length")) if policy else None,
        password_apply_to=_tokens(policy.get("apply-to")) if policy else (),
        admin_lockout_threshold=_as_int(item.get("admin-lockout-threshold")),
        admin_lockout_duration=_as_int(item.get("admin-lockout-duration")),
        admin_http_port=_as_int(item.get("admin-port")),
        admin_https_port=_as_int(item.get("admin-sport")),
        admin_https_redirect=_as_bool(item.get("admin-https-redirect"), default=False) if "admin-https-redirect" in item else None,
    )


def _iface_names_for(interfaces: list[dict[str, Any]], protocol: str) -> tuple[str, ...]:
    names: list[str] = []
    for iface in interfaces:
        if protocol not in _allowaccess_tokens(iface.get("allowaccess")):
            continue
        name = str(iface.get("name") or "").strip()
        if name and name not in names:
            names.append(name)
    return tuple(names)


def forti_services(interface_raw: object, admin_raw: object) -> ServiceList:
    interfaces = _as_records(interface_raw)
    listen = _services_listen(_as_records(admin_raw))
    enabled_protocols: set[str] = set()
    wan_protocols: set[str] = set()
    for iface in interfaces:
        tokens = _allowaccess_tokens(iface.get("allowaccess"))
        enabled_protocols.update(tokens)
        if _is_wan(iface):
            wan_protocols.update(tokens)
    services = [
        Service(
            name=name,
            enabled=name in enabled_protocols,
            port=port,
            listen=listen,
            on_wan=name in wan_protocols,
            interfaces=_iface_names_for(interfaces, name),
        )
        for name, port in _MGMT_PROTOCOLS
    ]
    return ServiceList(services=tuple(services))


def forti_zones(raw: object) -> ZoneList:
    zones = []
    for item in _as_records(raw):
        raw_intra = str(item.get("intrazone") or "").strip().lower()
        if raw_intra in {"allow", "permit"}:
            intra = "allow"
        elif raw_intra in {"deny", "block"}:
            intra = "deny"
        else:
            intra = "unknown"
        zones.append(Zone(name=str(item.get("name") or ""), intrazone=intra))
    return ZoneList(zones=tuple(zones))


def forti_local_in(raw: object, raw6: object | None = None) -> LocalInPolicyList:
    policies: list[LocalInPolicy] = []
    for source in (raw, raw6):
        for index, item in enumerate(_as_records(source)):
            raw_id = item.get("policyid", item.get("id"))
            policies.append(
                LocalInPolicy(
                    id=str(index) if raw_id is None else str(raw_id),
                    enabled=_as_bool(item.get("status"), default=True),
                    action=_ACTION_MAP.get(str(item.get("action") or "").strip().lower(), "other"),
                    virtual_patch=_as_bool(item.get("virtual-patch"), default=False),
                )
            )
    return LocalInPolicyList(policies=tuple(policies))


_HA_SECRET_KEYS = frozenset({"password", "passwd", "secret"})


def _drop_secrets(obj: object) -> object:
    if isinstance(obj, dict):
        return {k: _drop_secrets(v) for k, v in obj.items() if str(k).lower() not in _HA_SECRET_KEYS}
    if isinstance(obj, list):
        return [_drop_secrets(v) for v in obj]
    return obj


def forti_ha(raw: object) -> HaConfig:
    item = _as_record(_drop_secrets(raw))
    monitors = _tokens(item.get("monitor"))
    mgmt = item.get("ha-mgmt-interfaces")
    entries = _as_records(mgmt if not isinstance(mgmt, dict) else [mgmt])
    ifaces: list[str] = []
    for entry in entries:
        name = entry.get("interface") or entry.get("name")
        if name not in (None, ""):
            ifaces.append(str(name))
    mode = str(item.get("mode") or "standalone").strip().lower()
    return HaConfig(
        mode=mode,
        monitor_interfaces=monitors,
        ha_mgmt_status=_as_bool(item.get("ha-mgmt-status"), default=False),
        ha_mgmt_interfaces=tuple(dict.fromkeys(ifaces)),
    )


def forti_ntp(raw: object) -> NtpConfig:
    item = _as_record(raw)
    return NtpConfig(
        enabled=_as_bool(item.get("ntpsync"), default=False),
        servers=_ntp_servers(item),
    )


def forti_dns(raw: object) -> DnsConfig:
    return DnsConfig(servers=_dns_servers(_as_record(raw)))


def _enc_high(value: object) -> bool:
    return str(value or "").strip().lower() in {"high", "highs", "high-ssl"}


def forti_logging(
    syslogd_raw: object,
    syslogd2_raw: object | None,
    faz_raw: object | None = None,
    log_setting_raw: object | None = None,
) -> LoggingConfig:
    remotes = [*_syslog_targets(syslogd_raw), *_syslog_targets(syslogd2_raw)]
    syslog = _as_record(syslogd_raw)
    faz = _as_record(faz_raw)
    setting = _as_record(log_setting_raw)
    return LoggingConfig(
        local_enabled=True,
        remote_targets=tuple(remotes),
        syslog_reliable=_as_bool(syslog.get("reliable"), default=False) if remotes else None,
        syslog_enc_high=_enc_high(syslog.get("enc-algorithm")) if remotes else None,
        faz_enabled=_as_bool(faz.get("status"), default=False) if faz else None,
        faz_reliable=_as_bool(faz.get("reliable"), default=False) if faz else None,
        faz_enc_high=_enc_high(faz.get("enc-algorithm")) if faz else None,
        implicit_policy_logged=_as_bool(setting.get("fwpolicy-implicit-log"), default=False) if setting else None,
    )


def forti_snmp(sysinfo_raw: object, community_raw: object, user_raw: object | None = None) -> SnmpConfig:
    info = _as_record(sysinfo_raw)
    communities = [
        SnmpCommunity(name=str(item.get("name") or ""), version=_snmp_version(item))
        for item in _as_records(community_raw)
    ]
    users = [
        SnmpUser(
            name=str(item.get("name") or ""),
            security_level=str(item.get("security-level") or ""),
        )
        for item in _as_records(user_raw)
    ]
    return SnmpConfig(
        enabled=_as_bool(info.get("status"), default=False),
        communities=tuple(communities),
        users=tuple(users),
        trap_free_memory_threshold=_as_int(info.get("trap-free-memory-threshold")),
        trap_freeable_memory_threshold=_as_int(info.get("trap-freeable-memory-threshold")),
    )


def _optional_name(value: object) -> str | None:
    if value in (None, "", "none"):
        return None
    if isinstance(value, (list, tuple)):
        if not value:
            return None
        value = value[0]
    if isinstance(value, dict):
        text = str(value.get("name") or "").strip()
        return text or None
    text = str(value).strip()
    return text or None


def _internet_names(item: dict[str, Any], *keys: str) -> tuple[str, ...]:
    names: list[str] = []
    for key in keys:
        raw = item.get(key)
        if raw in (None, "", False, 0):
            continue
        if isinstance(raw, (list, tuple)):
            for entry in raw:
                if isinstance(entry, dict):
                    text = str(entry.get("name") or entry.get("internet-service-name") or "").strip()
                else:
                    text = str(entry).strip()
                if text:
                    names.append(text)
        elif isinstance(raw, dict):
            text = str(raw.get("name") or "").strip()
            if text:
                names.append(text)
        else:
            text = str(raw).strip()
            if text and text.lower() not in {"enable", "disable", "true", "false"}:
                names.append(text)
    return tuple(names)


def forti_filter(raw: object) -> PolicyList:
    policies: list[Policy] = []
    for index, item in enumerate(_as_records(raw)):
        raw_id = item.get("policyid", item.get("id"))
        log_raw = str(item.get("logtraffic") or "").strip().lower()
        log = None if "logtraffic" not in item else log_raw in {"all", "utm", "enable", "true"}
        if str(item.get("action") or "").strip().lower() == "accept":
            if "logtraffic" in item:
                log = log_raw == "all"
        policies.append(
            Policy(
                id=str(index) if raw_id is None else str(raw_id),
                enabled=_as_bool(item.get("status"), default=True),
                action=_ACTION_MAP.get(str(item.get("action") or "").strip().lower(), "other"),
                src=_named_tokens(item.get("srcaddr")),
                dst=_named_tokens(item.get("dstaddr")),
                service=_named_tokens(item.get("service")),
                log=log,
                ips_sensor=_optional_name(item.get("ips-sensor")),
                dnsfilter_profile=_optional_name(item.get("dnsfilter-profile")),
                webfilter_profile=_optional_name(item.get("webfilter-profile")),
                application_list=_optional_name(item.get("application-list")),
                internet_src=_internet_names(
                    item, "internet-service-src-name", "internet-service-src", "internet-service-src-id"
                ),
                internet_dst=_internet_names(
                    item, "internet-service-name", "internet-service", "internet-service-id"
                ),
            )
        )
    return PolicyList(policies=tuple(policies))


def _first_present(*values: object) -> str | None:
    for value in values:
        if value in (None, ""):
            continue
        text = str(value).strip()
        if text:
            return text
    return None


_WEB_CAT = {
    "26": "malicious",
    "61": "phishing",
    "86": "spam",
    "7": "dynamic-dns",
}
_APP_CAT = {
    "2": "p2p",
    "6": "proxy",
}
_CAT_ALIASES = (
    ("malicious", "malicious"),
    ("phishing", "phishing"),
    ("spam", "spam"),
    ("dynamic-dns", "dynamic-dns"),
    ("dynamic dns", "dynamic-dns"),
    ("p2p", "p2p"),
    ("proxy", "proxy"),
)
_BLOCK_ACTIONS = frozenset({"block", "deny"})
_ALLOW_ACTIONS = frozenset({"allow", "pass"})


def _table_rows(raw: object) -> list[dict[str, Any]]:
    if isinstance(raw, dict):
        nested = raw.get("")
        if isinstance(nested, list):
            return _as_records(nested)
        if raw and all(str(key) == "" or str(key).isdigit() for key in raw):
            return _as_records([value for value in raw.values() if isinstance(value, dict)])
    return _as_records(raw)


def _cat_token(value: object, mapping: dict[str, str]) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return mapping.get(str(int(value)))
    text = str(value).strip()
    if not text:
        return None
    if text in mapping:
        return mapping[text]
    lowered = text.lower()
    tokens = set(mapping.values())
    if lowered in tokens:
        return lowered
    for needle, token in _CAT_ALIASES:
        if needle in lowered and token in tokens:
            return token
    return None


def _split_categories(
    rows: list[dict[str, Any]],
    mapping: dict[str, str],
    *,
    allow: bool,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    blocked: list[str] = []
    allowed: list[str] = []
    for row in rows:
        token = _cat_token(row.get("category"), mapping)
        if token is None:
            continue
        action = str(row.get("action") or "").strip().lower()
        if action in _BLOCK_ACTIONS:
            blocked.append(token)
        elif allow and action in _ALLOW_ACTIONS:
            allowed.append(token)
    return tuple(dict.fromkeys(blocked)), tuple(dict.fromkeys(allowed))


def forti_utm(
    dnsfilter_raw: object,
    webfilter_raw: object,
    application_list_raw: object,
    automation_stitch_raw: object,
) -> UtmConfig:
    profiles: list[UtmProfile] = []
    for item in _as_records(dnsfilter_raw):
        log_all = _as_bool(item.get("log-all-domain"), default=False) or _as_bool(
            item.get("log-all"), default=False
        )
        profiles.append(
            UtmProfile(name=str(item.get("name") or ""), kind="dnsfilter", log_all=log_all)
        )
    for item in _as_records(webfilter_raw):
        ftgd = item.get("ftgd-wf") if isinstance(item.get("ftgd-wf"), dict) else {}
        blocked, _allowed = _split_categories(_table_rows(ftgd.get("filters")), _WEB_CAT, allow=False)
        profiles.append(
            UtmProfile(
                name=str(item.get("name") or ""),
                kind="webfilter",
                blocked_categories=blocked,
            )
        )
    for item in _as_records(application_list_raw):
        blocked, allowed = _split_categories(_table_rows(item.get("entries")), _APP_CAT, allow=True)
        profiles.append(
            UtmProfile(
                name=str(item.get("name") or ""),
                kind="appctrl",
                blocked_categories=blocked,
                allowed_categories=allowed,
            )
        )
    stitches = [
        AutomationStitch(
            name=str(item.get("name") or ""),
            enabled=_as_bool(item.get("status"), default=False),
        )
        for item in _as_records(automation_stitch_raw)
    ]
    return UtmConfig(profiles=tuple(profiles), stitches=tuple(stitches))


def forti_system(raw: object) -> SystemInfo:
    # FortiOS monitor envelopes keep version/serial next to results.
    envelope = raw if isinstance(raw, dict) else {}
    item = _as_record(raw)
    firmware = _first_present(envelope.get("version"), item.get("version")) or ""
    model = _first_present(
        envelope.get("model_name"),
        envelope.get("model"),
        item.get("model_name"),
        item.get("model"),
    )
    return SystemInfo(firmware=firmware, model=model)


_LICENSE_SOURCES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("forticare", ("forticare",)),
    ("firmware_updates", ("firmware_updates",)),
    ("ips", ("ips",)),
    ("antivirus", ("antivirus",)),
    ("web_filtering", ("web_filtering",)),
    ("antispam", ("antispam",)),
    ("outbreak_prevention", ("outbreak_prevention",)),
    ("sdwan_network_monitor", ("sdwan_network_monitor",)),
    ("security_rating", ("security_rating",)),
    ("industrial_db", ("industrial_db", "icdb")),
    ("iot_detection", ("iot_detection",)),
    ("forticloud", ("forticloud",)),
)
_LICENSED_STATUS = frozenset({
    "licensed",
    "registered",
    "activated",
    "free",
    "free_license",
    "cloud_logged_in",
})
_EXPIRED_STATUS = frozenset({"expired"})
_ENTITLEMENT_FALLBACK = {"firmware_updates": "FMWR"}


def _normalize_license_status(value: object) -> str:
    text = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    if text in _EXPIRED_STATUS:
        return "expired"
    if text in _LICENSED_STATUS:
        return "licensed"
    return "unlicensed"


def _expires_iso(value: object) -> str | None:
    if value in (None, "", 0, False):
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(int(value), timezone.utc).date().isoformat()
    text = str(value).strip().replace("/", "-")
    match = re.match(r"^(\d{4}-\d{2}-\d{2})", text)
    return match.group(1) if match else None


def _support_contract(item: dict[str, Any]) -> dict[str, Any] | None:
    support = item.get("support")
    if not isinstance(support, dict):
        return None
    enhanced = support.get("enhanced")
    if isinstance(enhanced, dict):
        return enhanced
    for value in support.values():
        if isinstance(value, dict) and "status" in value:
            return value
    return None


def _item_by_entitlement(bucket: dict[str, Any], code: str) -> dict[str, Any] | None:
    needle = code.upper()
    for value in bucket.values():
        if isinstance(value, dict) and str(value.get("entitlement") or "").upper() == needle:
            return value
    return None


def _entitlement_from_item(key: str, item: dict[str, Any] | None) -> LicenseEntitlement:
    if not item:
        return LicenseEntitlement(key=key, status="unlicensed")
    if key == "forticare":
        # GUI "FortiCare Support: Registered" is status/registration_status.
        # support.enhanced is optional; FortiOS 7.2 often returns support: {}.
        status = _normalize_license_status(item.get("registration_status") or item.get("status"))
        expires = _expires_iso(item.get("expires"))
        contract = _support_contract(item)
        if contract is not None:
            expires = _expires_iso(contract.get("expires")) or expires
            if status == "unlicensed":
                status = _normalize_license_status(contract.get("status"))
        return LicenseEntitlement(key=key, status=status, expires=expires)
    return LicenseEntitlement(
        key=key,
        status=_normalize_license_status(item.get("status")),
        expires=_expires_iso(item.get("expires")),
    )


def _as_optional_int(value: object) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _cmdb_usage_items(raw: object, kind: str) -> list[UsageItem]:
    items: list[UsageItem] = []
    for item in _as_records(raw):
        name = str(item.get("name") or item.get("q_origin_key") or "").strip()
        if not name:
            continue
        items.append(
            UsageItem(
                kind=kind,
                name=name,
                refs=_as_optional_int(item.get("q_ref")),
                static=_as_bool(item.get("q_static")) or _as_bool(item.get("q_no_edit")),
            )
        )
    return items


def forti_object_usage(
    address_raw: object | None = None,
    addrgrp_raw: object | None = None,
    service_raw: object | None = None,
    service_group_raw: object | None = None,
    vip_raw: object | None = None,
    ippool_raw: object | None = None,
    policy_stats_raw: object | None = None,
) -> UsageList:
    items: list[UsageItem] = []
    items.extend(_cmdb_usage_items(address_raw, "address"))
    items.extend(_cmdb_usage_items(addrgrp_raw, "addrgrp"))
    items.extend(_cmdb_usage_items(service_raw, "service"))
    items.extend(_cmdb_usage_items(service_group_raw, "service_group"))
    items.extend(_cmdb_usage_items(vip_raw, "vip"))
    items.extend(_cmdb_usage_items(ippool_raw, "ippool"))
    for item in _as_records(policy_stats_raw):
        raw_id = item.get("policyid", item.get("id"))
        if raw_id in (None, ""):
            continue
        items.append(
            UsageItem(
                kind="policy",
                name=str(raw_id),
                hit_count=_as_optional_int(item.get("hit_count")),
                last_used=_as_optional_int(item.get("last_used")),
            )
        )
    return UsageList(items=tuple(items))


def forti_licenses(raw: object) -> LicenseStatus:
    results = forti_unwrap(raw)
    bucket = results if isinstance(results, dict) else {}
    entitlements: list[LicenseEntitlement] = []
    for key, aliases in _LICENSE_SOURCES:
        item = None
        for alias in aliases:
            candidate = bucket.get(alias)
            if isinstance(candidate, dict):
                item = candidate
                break
        if item is None:
            fallback = _ENTITLEMENT_FALLBACK.get(key)
            if fallback:
                item = _item_by_entitlement(bucket, fallback)
        entitlements.append(_entitlement_from_item(key, item))
    return LicenseStatus(entitlements=tuple(entitlements))

