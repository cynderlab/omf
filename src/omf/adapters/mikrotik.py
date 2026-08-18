from __future__ import annotations

import re
from typing import Any

from omf.adapters.normalize import as_any_token
from omf.schema.capabilities import (
    AdminSettings,
    DnsConfig,
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

_TIMEOUT_RE = re.compile(r"^(\d+)([smhSMH])?$")
_TRUE = frozenset({"true", "yes", "1", "on"})
_FALSE = frozenset({"false", "no", "0", "off", ""})
_ACTION_MAP: dict[str, PolicyAction] = {
    "accept": "accept",
    "drop": "drop",
    "reject": "deny",
    "deny": "deny",
}


def _as_records(raw: object) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if isinstance(raw, dict):
        return [raw]
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


def _enabled(item: dict[str, Any]) -> bool:
    return not _as_bool(item.get("disabled"), default=False)


def _parse_timeout(value: object) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    if not text:
        return None
    match = _TIMEOUT_RE.fullmatch(text)
    if not match:
        return None
    amount = int(match.group(1))
    unit = (match.group(2) or "s").lower()
    if unit == "m":
        return amount * 60
    if unit == "h":
        return amount * 3600
    return amount


def _servers(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(part.strip() for part in value.split(",") if part.strip())
    if isinstance(value, (list, tuple)):
        out: list[str] = []
        for item in value:
            out.extend(_servers(item))
        return tuple(out)
    text = str(value).strip()
    return (text,) if text else ()


def _address_tokens(value: object) -> tuple[str, ...]:
    if isinstance(value, (list, tuple)):
        if not value:
            return ("any",)
        return tuple(as_any_token(item) for item in value)
    return (as_any_token(value),)


def _service_tokens(item: dict[str, Any]) -> tuple[str, ...]:
    protocol = item.get("protocol")
    dst_port = item.get("dst-port")
    proto_missing = protocol is None or (isinstance(protocol, str) and not str(protocol).strip())
    port_missing = dst_port is None or (isinstance(dst_port, str) and not str(dst_port).strip())
    if proto_missing and port_missing:
        return ("any",)
    if proto_missing:
        return (as_any_token(dst_port),)
    if port_missing:
        return (as_any_token(protocol),)
    proto = as_any_token(protocol)
    port = as_any_token(dst_port)
    if proto == "any" and port == "any":
        return ("any",)
    if proto == "any":
        return (port,)
    if port == "any":
        return (proto,)
    return (f"{proto}/{port}",)


def mikrotik_users(raw: object) -> UserList:
    users: list[User] = []
    for item in _as_records(raw):
        group = item.get("group")
        groups = (str(group),) if group not in (None, "") else ()
        users.append(
            User(
                name=str(item.get("name") or ""),
                enabled=_enabled(item),
                groups=groups,
            )
        )
    return UserList(users=tuple(users))


def mikrotik_admin_settings(identity_raw: object, settings_raw: object) -> AdminSettings:
    identity = _as_record(identity_raw)
    settings = _as_record(settings_raw)
    timeout_raw = settings.get("minimum-timeout")
    if timeout_raw is None:
        timeout_raw = settings.get("session-timeout")
    return AdminSettings(
        hostname=str(identity.get("name") or ""),
        idle_timeout_seconds=_parse_timeout(timeout_raw) if timeout_raw is not None else None,
    )


def mikrotik_services(raw: object) -> ServiceList:
    services: list[Service] = []
    for item in _as_records(raw):
        address = item.get("address")
        listen = "all" if as_any_token(address) == "any" else "restricted"
        services.append(
            Service(
                name=str(item.get("name") or ""),
                enabled=_enabled(item),
                port=int(item.get("port") or 0),
                listen=listen,
            )
        )
    return ServiceList(services=tuple(services))


def mikrotik_ntp(raw: object) -> NtpConfig:
    item = _as_record(raw)
    servers = _servers(item.get("servers")) or _servers(item.get("server"))
    return NtpConfig(enabled=_as_bool(item.get("enabled"), default=False), servers=servers)


def mikrotik_dns(raw: object) -> DnsConfig:
    return DnsConfig(servers=_servers(_as_record(raw).get("servers")))


def mikrotik_logging(logging_raw: object, actions_raw: object) -> LoggingConfig:
    rules = _as_records(logging_raw)
    actions = _as_records(actions_raw)
    local_names = {"memory", "disk"}
    action_by_name = {str(action.get("name") or ""): action for action in actions}
    local_enabled = False
    for rule in rules:
        action_name = str(rule.get("action") or "").strip().lower()
        if action_name in local_names:
            local_enabled = True
            break
        target = str(action_by_name.get(action_name, {}).get("target") or "").strip().lower()
        if target in local_names:
            local_enabled = True
            break
    remotes: list[str] = []
    for action in actions:
        target = str(action.get("target") or "").strip().lower()
        remote = action.get("remote")
        has_remote = remote not in (None, "")
        if target == "remote" or has_remote:
            token = str(remote).strip() if has_remote else str(action.get("name") or "remote")
            if token:
                remotes.append(token)
    return LoggingConfig(local_enabled=local_enabled, remote_targets=tuple(remotes))


def mikrotik_snmp(snmp_raw: object, communities_raw: object) -> SnmpConfig:
    communities: list[SnmpCommunity] = []
    for item in _as_records(communities_raw):
        version = item.get("version")
        if version is None:
            version = item.get("security")
        communities.append(
            SnmpCommunity(
                name=str(item.get("name") or ""),
                version="" if version is None else str(version),
            )
        )
    return SnmpConfig(
        enabled=_as_bool(_as_record(snmp_raw).get("enabled"), default=False),
        communities=tuple(communities),
    )


def mikrotik_filter(raw: object) -> PolicyList:
    policies: list[Policy] = []
    for index, item in enumerate(_as_records(raw)):
        raw_id = item.get(".id", item.get("id"))
        policies.append(
            Policy(
                id=str(index) if raw_id is None else str(raw_id),
                enabled=_enabled(item),
                action=_ACTION_MAP.get(str(item.get("action") or "").strip().lower(), "other"),
                src=_address_tokens(item.get("src-address")),
                dst=_address_tokens(item.get("dst-address")),
                service=_service_tokens(item),
            )
        )
    return PolicyList(policies=tuple(policies))


def mikrotik_system(raw: object) -> SystemInfo:
    item = _as_record(raw)
    model = item.get("board-name")
    return SystemInfo(
        firmware=str(item.get("version") or ""),
        model=None if model in (None, "") else str(model),
    )


__all__ = [
    "mikrotik_admin_settings",
    "mikrotik_dns",
    "mikrotik_filter",
    "mikrotik_logging",
    "mikrotik_ntp",
    "mikrotik_services",
    "mikrotik_snmp",
    "mikrotik_system",
    "mikrotik_users",
]
