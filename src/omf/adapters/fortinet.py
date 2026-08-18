from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Literal, NoReturn

import httpx

from omf.adapters.base import CollectError, ProbeError
from omf.adapters.normalize import as_any_token
from omf.schema.capabilities import (
    ALL_CAPABILITIES,
    AdminSettings,
    AutomationStitch,
    DnsConfig,
    HaConfig,
    Listen,
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
    UtmConfig,
    UtmProfile,
    Zone,
    ZoneList,
)
from omf.schema.evidence import Evidence
from omf.session import Session

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


def _trusthost_values(item: dict[str, Any]) -> list[object]:
    return [value for key, value in item.items() if _is_trusthost_key(key)]


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
    ifaces: list[str] = []
    for entry in _as_records(mgmt) if not isinstance(mgmt, dict) else [mgmt]:
        name = entry.get("interface") or entry.get("name")
        if name not in (None, ""):
            ifaces.append(str(name))
    if isinstance(mgmt, (list, tuple)):
        for entry in mgmt:
            if isinstance(entry, dict):
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


class FortinetAdapter:
    vendor: Literal["fortinet"] = "fortinet"

    def __init__(self, session: Session, client: httpx.Client) -> None:
        self._session = session
        self._client = client
        self.last_call: dict = {}
        self._logged_in = False

    def probe(self) -> None:
        self._ensure_session()
        self._get("/api/v2/monitor/system/status")

    def collect(self, capability: str) -> tuple[Evidence, object]:
        try:
            self._ensure_session(capability=capability)
            if capability == "users":
                raw: object = self._get("/api/v2/cmdb/system/admin", capability=capability)
                payload: object = forti_users(raw)
            elif capability == "admin_settings":
                global_raw = self._get("/api/v2/cmdb/system/global", capability=capability)
                admin_raw = self._get("/api/v2/cmdb/system/admin", capability=capability)
                password_policy_raw = self._get(
                    "/api/v2/cmdb/system/password-policy",
                    capability=capability,
                )
                raw = {
                    "/api/v2/cmdb/system/global": global_raw,
                    "/api/v2/cmdb/system/admin": admin_raw,
                    "/api/v2/cmdb/system/password-policy": password_policy_raw,
                }
                payload = forti_admin_settings(global_raw, admin_raw, password_policy_raw)
            elif capability == "services":
                interface_raw = self._get("/api/v2/cmdb/system/interface", capability=capability)
                admin_raw = self._get("/api/v2/cmdb/system/admin", capability=capability)
                raw = {
                    "/api/v2/cmdb/system/interface": interface_raw,
                    "/api/v2/cmdb/system/admin": admin_raw,
                }
                payload = forti_services(interface_raw, admin_raw)
            elif capability == "ntp":
                raw = self._get("/api/v2/cmdb/system/ntp", capability=capability)
                payload = forti_ntp(raw)
            elif capability == "dns":
                raw = self._get("/api/v2/cmdb/system/dns", capability=capability)
                payload = forti_dns(raw)
            elif capability == "logging":
                syslogd = self._get("/api/v2/cmdb/log.syslogd/setting", capability=capability)
                syslogd2 = self._get(
                    "/api/v2/cmdb/log.syslogd2/setting",
                    capability=capability,
                    optional=True,
                )
                faz = self._get(
                    "/api/v2/cmdb/log.fortianalyzer/setting",
                    capability=capability,
                    optional=True,
                )
                log_setting = self._get(
                    "/api/v2/cmdb/log.setting",
                    capability=capability,
                    optional=True,
                )
                raw = {"/api/v2/cmdb/log.syslogd/setting": syslogd}
                if syslogd2 is not None:
                    raw["/api/v2/cmdb/log.syslogd2/setting"] = syslogd2
                if faz is not None:
                    raw["/api/v2/cmdb/log.fortianalyzer/setting"] = faz
                if log_setting is not None:
                    raw["/api/v2/cmdb/log.setting"] = log_setting
                payload = forti_logging(syslogd, syslogd2, faz, log_setting)
            elif capability == "snmp":
                community_raw = self._get(
                    "/api/v2/cmdb/system/snmp/community",
                    capability=capability,
                )
                sysinfo_raw = self._get(
                    "/api/v2/cmdb/system/snmp/sysinfo",
                    capability=capability,
                )
                user_raw = self._get(
                    "/api/v2/cmdb/system/snmp/user",
                    capability=capability,
                )
                raw = {
                    "/api/v2/cmdb/system/snmp/community": community_raw,
                    "/api/v2/cmdb/system/snmp/sysinfo": sysinfo_raw,
                    "/api/v2/cmdb/system/snmp/user": user_raw,
                }
                payload = forti_snmp(sysinfo_raw, community_raw, user_raw)
            elif capability == "firewall_filter":
                raw = self._get("/api/v2/cmdb/firewall/policy", capability=capability)
                payload = forti_filter(raw)
            elif capability == "zones":
                raw = self._get("/api/v2/cmdb/system/zone", capability=capability)
                payload = forti_zones(raw)
            elif capability == "local_in":
                local_in_raw = self._get(
                    "/api/v2/cmdb/firewall/local-in-policy",
                    capability=capability,
                )
                local_in6_raw = self._get(
                    "/api/v2/cmdb/firewall/local-in-policy6",
                    capability=capability,
                    optional=True,
                )
                raw = {"/api/v2/cmdb/firewall/local-in-policy": local_in_raw}
                if local_in6_raw is not None:
                    raw["/api/v2/cmdb/firewall/local-in-policy6"] = local_in6_raw
                payload = forti_local_in(local_in_raw, local_in6_raw)
            elif capability == "ha":
                raw = _drop_secrets(self._get("/api/v2/cmdb/system/ha", capability=capability))
                payload = forti_ha(raw)
            elif capability == "utm":
                dns_raw = self._get(
                    "/api/v2/cmdb/dnsfilter/profile",
                    capability=capability,
                    optional=True,
                )
                web_raw = self._get(
                    "/api/v2/cmdb/webfilter/profile",
                    capability=capability,
                    optional=True,
                )
                app_raw = self._get(
                    "/api/v2/cmdb/application/list",
                    capability=capability,
                    optional=True,
                )
                stitch_raw = self._get(
                    "/api/v2/cmdb/system/automation-stitch",
                    capability=capability,
                    optional=True,
                )
                raw = {}
                if dns_raw is not None:
                    raw["/api/v2/cmdb/dnsfilter/profile"] = dns_raw
                if web_raw is not None:
                    raw["/api/v2/cmdb/webfilter/profile"] = web_raw
                if app_raw is not None:
                    raw["/api/v2/cmdb/application/list"] = app_raw
                if stitch_raw is not None:
                    raw["/api/v2/cmdb/system/automation-stitch"] = stitch_raw
                payload = forti_utm(dns_raw, web_raw, app_raw, stitch_raw)
            elif capability == "system_info":
                raw = self._get("/api/v2/monitor/system/status", capability=capability)
                payload = forti_system(raw)
            else:
                raise CollectError(capability, "", None, f"unknown capability: {capability}")
        except CollectError:
            raise
        except Exception as exc:
            raise _normalize_failed(capability, self.last_call, exc) from exc
        return (
            Evidence(
                capability=capability,
                vendor=self.vendor,
                collected_at=datetime.now(timezone.utc),
                payload=payload,
            ),
            raw,
        )

    def implemented(self) -> frozenset[str]:
        return frozenset(ALL_CAPABILITIES)

    def close(self) -> None:
        if self._logged_in:
            try:
                self._request("GET", "/logout")
            except httpx.RequestError:
                pass
        self._client.close()

    def _has_token(self) -> bool:
        return bool(self._session.token)

    def _ensure_session(self, *, capability: str | None = None) -> None:
        if self._has_token() or self._logged_in:
            return
        try:
            # FortiOS logincheck expects form fields username + secretkey.
            response = self._request(
                "POST",
                "/logincheck",
                data={
                    "username": self._session.username,
                    "secretkey": self._session.password,
                },
            )
        except httpx.RequestError as exc:
            _raise_http("/logincheck", None, str(exc), capability)
        if not 200 <= response.status_code < 300:
            _raise_http(
                "/logincheck",
                response.status_code,
                f"POST /logincheck returned {response.status_code}",
                capability,
            )
        self._logged_in = True

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        headers = dict(kwargs.pop("headers", None) or {})
        if self._has_token():
            headers.setdefault("Authorization", f"Bearer {self._session.token}")
        started = time.perf_counter()
        status: int | None = None
        try:
            response = self._client.request(method, path, headers=headers, **kwargs)
            status = response.status_code
            return response
        finally:
            self.last_call = {
                "method": method,
                "path": path,
                "status": status,
                "ms": int((time.perf_counter() - started) * 1000),
            }

    def _get(
        self,
        path: str,
        *,
        capability: str | None = None,
        optional: bool = False,
    ) -> object:
        try:
            response = self._request("GET", path)
        except httpx.RequestError as exc:
            _raise_http(path, None, str(exc), capability)
        if optional and response.status_code == 404:
            return None
        if not 200 <= response.status_code < 300:
            _raise_http(
                path,
                response.status_code,
                f"GET {path} returned {response.status_code}",
                capability,
            )
        return _decode_json(response, path, capability)


def _decode_json(response: httpx.Response, path: str, capability: str | None) -> object:
    try:
        return response.json()
    except json.JSONDecodeError as exc:
        _raise_http(path, response.status_code, f"GET {path} returned invalid JSON: {exc}", capability)


def _normalize_failed(capability: str, last_call: object, exc: Exception) -> CollectError:
    path = ""
    status: int | None = None
    if isinstance(last_call, dict):
        path = str(last_call.get("path") or "")
        raw_status = last_call.get("status")
        if isinstance(raw_status, int):
            status = raw_status
    return CollectError(capability, path, status, f"normalize failed: {exc}")


def _raise_http(
    path: str,
    status: int | None,
    message: str,
    capability: str | None,
) -> NoReturn:
    if capability is None:
        raise ProbeError(path, status, message)
    raise CollectError(capability, path, status, message)


__all__ = [
    "FortinetAdapter",
    "forti_admin_settings",
    "forti_dns",
    "forti_filter",
    "forti_ha",
    "forti_local_in",
    "forti_logging",
    "forti_ntp",
    "forti_services",
    "forti_snmp",
    "forti_system",
    "forti_unwrap",
    "forti_users",
    "forti_utm",
    "forti_zones",
]
