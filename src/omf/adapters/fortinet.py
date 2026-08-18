from __future__ import annotations

from typing import Any

from omf.adapters.normalize import as_any_token
from omf.schema.capabilities import (
    AdminSettings,
    DnsConfig,
    Listen,
    LoggingConfig,
    NtpConfig,
    Policy,
    PolicyAction,
    PolicyList,
    Service,
    ServiceList,
    SnmpCommunity,
    SnmpConfig,
    SystemInfo,
    User,
    UserList,
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
)
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


def _trusthost_values(item: dict[str, Any]) -> list[object]:
    return [value for key, value in item.items() if str(key).lower().startswith("trusthost")]


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


def forti_admin_settings(global_raw: object, admin_raw: object) -> AdminSettings:
    _ = admin_raw
    item = _as_record(global_raw)
    timeout_raw = item.get("admintimeout")
    return AdminSettings(
        hostname=str(item.get("hostname") or ""),
        idle_timeout_seconds=_idle_timeout_seconds(timeout_raw)
        if timeout_raw is not None
        else None,
    )


def forti_services(interface_raw: object, admin_raw: object) -> ServiceList:
    interfaces = _as_records(interface_raw)
    listen = _services_listen(_as_records(admin_raw))
    enabled_protocols: set[str] = set()
    for iface in interfaces:
        enabled_protocols.update(_allowaccess_tokens(iface.get("allowaccess")))
    services = [
        Service(
            name=name,
            enabled=name in enabled_protocols,
            port=port,
            listen=listen,
        )
        for name, port in _MGMT_PROTOCOLS
    ]
    return ServiceList(services=tuple(services))


def forti_ntp(raw: object) -> NtpConfig:
    item = _as_record(raw)
    return NtpConfig(
        enabled=_as_bool(item.get("ntpsync"), default=False),
        servers=_ntp_servers(item),
    )


def forti_dns(raw: object) -> DnsConfig:
    return DnsConfig(servers=_dns_servers(_as_record(raw)))


def forti_logging(syslogd_raw: object, syslogd2_raw: object | None) -> LoggingConfig:
    remotes = [*_syslog_targets(syslogd_raw), *_syslog_targets(syslogd2_raw)]
    return LoggingConfig(local_enabled=True, remote_targets=tuple(remotes))


def forti_snmp(sysinfo_raw: object, community_raw: object) -> SnmpConfig:
    communities = [
        SnmpCommunity(name=str(item.get("name") or ""), version=_snmp_version(item))
        for item in _as_records(community_raw)
    ]
    return SnmpConfig(
        enabled=_as_bool(_as_record(sysinfo_raw).get("status"), default=False),
        communities=tuple(communities),
    )


def forti_filter(raw: object) -> PolicyList:
    policies: list[Policy] = []
    for index, item in enumerate(_as_records(raw)):
        raw_id = item.get("policyid", item.get("id"))
        policies.append(
            Policy(
                id=str(index) if raw_id is None else str(raw_id),
                enabled=_as_bool(item.get("status"), default=True),
                action=_ACTION_MAP.get(str(item.get("action") or "").strip().lower(), "other"),
                src=_named_tokens(item.get("srcaddr")),
                dst=_named_tokens(item.get("dstaddr")),
                service=_named_tokens(item.get("service")),
            )
        )
    return PolicyList(policies=tuple(policies))


def forti_system(raw: object) -> SystemInfo:
    item = _as_record(raw)
    model = item.get("model")
    return SystemInfo(
        firmware=str(item.get("version") or ""),
        model=None if model in (None, "") else str(model),
    )


__all__ = [
    "forti_admin_settings",
    "forti_dns",
    "forti_filter",
    "forti_logging",
    "forti_ntp",
    "forti_services",
    "forti_snmp",
    "forti_system",
    "forti_unwrap",
    "forti_users",
]
