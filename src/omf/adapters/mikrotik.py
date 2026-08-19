"""MikroTik RouterOS 7+ REST adapter (`/rest/...`, HTTP Basic)."""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Literal, NoReturn

import httpx

from omf.adapters.base import CollectError, ProbeError
from omf.adapters.normalize import as_any_token
from omf.log import get_logger, http_target
from omf.schema.capabilities import (
    CORE_CAPABILITIES,
    MIKROTIK_EXTRAS,
    AdminSettings,
    DnsConfig,
    L2Access,
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
from omf.schema.evidence import Evidence
from omf.session import Session

# Official RouterOS REST API (www/www-ssl), not the binary API on 8728/8729:
# https://help.mikrotik.com/docs/spaces/ROS/pages/47579162/REST+API

_log = get_logger("omf.http")
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


def _csv_tokens(value: object) -> tuple[str, ...]:
    if value in (None, ""):
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(str(item).strip().lower() for item in value if str(item).strip())
    return tuple(part.strip().lower() for part in str(value).split(",") if part.strip())


def mikrotik_users(raw: object) -> UserList:
    users: list[User] = []
    for item in _as_records(raw):
        group = item.get("group")
        groups = (str(group),) if group not in (None, "") else ()
        policy = item.get("inactivity-policy")
        users.append(
            User(
                name=str(item.get("name") or ""),
                enabled=_enabled(item),
                groups=groups,
                inactivity_timeout_seconds=_parse_timeout(item.get("inactivity-timeout")),
                inactivity_policy=None if policy in (None, "") else str(policy).strip().lower(),
            )
        )
    return UserList(users=tuple(users))


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


def _find_service(services: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    for item in services:
        if str(item.get("name") or "").strip().lower() == name:
            return item
    return None


def _service_port(services: list[dict[str, Any]], name: str) -> int | None:
    item = _find_service(services, name)
    return None if item is None else _as_int(item.get("port"))


def _service_enabled(services: list[dict[str, Any]], name: str) -> bool | None:
    item = _find_service(services, name)
    return None if item is None else _enabled(item)


def mikrotik_admin_settings(
    identity_raw: object,
    settings_raw: object,
    clock_raw: object | None = None,
    service_raw: object | None = None,
    ssh_raw: object | None = None,
) -> AdminSettings:
    identity = _as_record(identity_raw)
    settings = _as_record(settings_raw)
    clock = _as_record(clock_raw)
    timeout_raw = settings.get("minimum-timeout")
    if timeout_raw is None:
        timeout_raw = settings.get("session-timeout")
    min_length = _as_int(settings.get("minimum-password-length"))
    zone = clock.get("time-zone-name")
    if zone in (None, ""):
        zone = clock.get("time-zone")
    services = _as_records(service_raw)
    ssh = _as_record(ssh_raw)
    ssh_strong = None
    if "strong-crypto" in ssh:
        ssh_strong = _as_bool(ssh.get("strong-crypto"))
    return AdminSettings(
        hostname=str(identity.get("name") or ""),
        idle_timeout_seconds=_parse_timeout(timeout_raw) if timeout_raw is not None else None,
        timezone=None if zone in (None, "") else str(zone).strip(),
        password_policy_enabled=min_length is not None and min_length > 0,
        password_min_length=min_length,
        password_apply_to=("admin-password",) if min_length is not None and min_length > 0 else (),
        admin_http_port=_service_port(services, "www"),
        admin_https_port=_service_port(services, "www-ssl"),
        admin_http_enabled=_service_enabled(services, "www"),
        admin_https_enabled=_service_enabled(services, "www-ssl"),
        admin_https_redirect=False if services else None,
        ssh_strong_crypto=ssh_strong,
    )


def _synthetic_service(name: str, enabled: bool) -> Service:
    return Service(name=name, enabled=enabled, port=0, listen="restricted")


def _setting_enabled(raw: object, key: str = "enabled") -> bool:
    item = _as_record(raw)
    if key not in item:
        return False
    return _as_bool(item.get(key), default=False)


def mikrotik_services(raw: object, extras: dict[str, object] | None = None) -> ServiceList:
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
    extra = extras or {}
    for name, key in (
        ("bandwidth-server", "bandwidth-server"),
        ("proxy", "proxy"),
        ("socks", "socks"),
        ("upnp", "upnp"),
        ("pptp", "pptp"),
    ):
        if key in extra and extra[key] is not None:
            services.append(_synthetic_service(name, _setting_enabled(extra[key])))
    if extra.get("cloud") is not None:
        cloud = _as_record(extra.get("cloud"))
        services.append(_synthetic_service("cloud-ddns", _as_bool(cloud.get("ddns-enabled"))))
        services.append(_synthetic_service("cloud-update-time", _as_bool(cloud.get("update-time"))))
    return ServiceList(services=tuple(services))


def mikrotik_ntp(raw: object, servers_raw: object | None = None) -> NtpConfig:
    item = _as_record(raw)
    servers = list(_servers(item.get("servers")) or _servers(item.get("server")))
    for rec in _as_records(servers_raw):
        extra = _servers(rec.get("address") or rec.get("server") or rec.get("name"))
        for host in extra:
            if host not in servers:
                servers.append(host)
    return NtpConfig(enabled=_as_bool(item.get("enabled"), default=False), servers=tuple(servers))


def mikrotik_dns(raw: object) -> DnsConfig:
    return DnsConfig(servers=_servers(_as_record(raw).get("servers")))


_PLACEHOLDER_REMOTES = frozenset({"0.0.0.0", "::", "none"})


def _remote_host(value: object) -> str | None:
    if value in (None, ""):
        return None
    token = str(value).strip()
    if not token or token.lower() in _PLACEHOLDER_REMOTES or as_any_token(token) == "any":
        return None
    return token


def mikrotik_logging(logging_raw: object, actions_raw: object) -> LoggingConfig:
    rules = _as_records(logging_raw)
    actions = _as_records(actions_raw)
    local_names = {"memory", "disk"}
    action_by_name = {str(action.get("name") or ""): action for action in actions}
    used_actions = {
        str(rule.get("action") or "").strip().lower()
        for rule in rules
        if _enabled(rule) and rule.get("action") not in (None, "")
    }
    local_enabled = False
    for rule in rules:
        if not _enabled(rule):
            continue
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
        name = str(action.get("name") or "").strip().lower()
        if name not in used_actions:
            continue
        target = str(action.get("target") or "").strip().lower()
        host = _remote_host(action.get("remote"))
        if target == "remote" or host:
            token = host or None
            if token and token not in remotes:
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
                read_access=(
                    _as_bool(item.get("read-access"), default=False) if "read-access" in item else None
                ),
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
                log=_as_bool(item.get("log"), default=False) if "log" in item else False,
                chain=str(item.get("chain") or "").strip().lower(),
                connection_state=_csv_tokens(item.get("connection-state")),
                in_interface=str(item.get("in-interface") or "").strip(),
                out_interface=str(item.get("out-interface") or "").strip(),
                in_interface_list=str(item.get("in-interface-list") or "").strip(),
                out_interface_list=str(item.get("out-interface-list") or "").strip(),
            )
        )
    return PolicyList(policies=tuple(policies))


def _optional_text(item: dict[str, Any], key: str) -> str | None:
    value = item.get(key)
    if value in (None, ""):
        return None
    return str(value).strip()


def mikrotik_system(
    raw: object,
    routerboard_raw: object | None = None,
    update_raw: object | None = None,
) -> SystemInfo:
    item = _as_record(raw)
    model = item.get("board-name")
    current = _as_record(routerboard_raw).get("current-firmware")
    update = _as_record(update_raw)
    return SystemInfo(
        firmware=str(item.get("version") or ""),
        model=None if model in (None, "") else str(model),
        current_firmware=None if current in (None, "") else str(current).strip(),
        update_status=_optional_text(update, "status"),
        installed_version=_optional_text(update, "installed-version"),
        latest_version=_optional_text(update, "latest-version"),
    )


def _interface_list(raw: object, *keys: str) -> str:
    item = _as_record(raw)
    for key in keys:
        value = item.get(key)
        if value not in (None, ""):
            return str(value).strip()
    return ""


def mikrotik_l2_access(
    discover_raw: object,
    telnet_raw: object,
    winbox_raw: object,
    ping_raw: object,
) -> L2Access:
    ping = _as_record(ping_raw)
    return L2Access(
        discover_interface_list=_interface_list(
            discover_raw, "discover-interface-list", "interface-list", "interface"
        ),
        mac_telnet_interface_list=_interface_list(
            telnet_raw, "allowed-interface-list", "interface-list", "interface"
        ),
        mac_winbox_interface_list=_interface_list(
            winbox_raw, "allowed-interface-list", "interface-list", "interface"
        ),
        mac_ping_enabled=_as_bool(ping.get("enabled"), default=True) if ping else True,
    )


class MikrotikAdapter:
    vendor: Literal["mikrotik"] = "mikrotik"

    def __init__(self, session: Session, client: httpx.Client) -> None:
        self._session = session
        self._client = client
        self.last_call: dict = {}

    def probe(self) -> None:
        self._get("/rest/system/identity")

    def collect(self, capability: str) -> tuple[Evidence, object]:
        try:
            if capability == "users":
                raw: object = self._get("/rest/user", capability=capability)
                payload: object = mikrotik_users(raw)
            elif capability == "admin_settings":
                identity = self._get("/rest/system/identity", capability=capability)
                settings = self._get("/rest/user/settings", capability=capability)
                clock = self._get("/rest/system/clock", capability=capability)
                services = self._get("/rest/ip/service", capability=capability)
                ssh = self._get_optional("/rest/ip/ssh", capability=capability)
                raw = {
                    "/rest/system/identity": identity,
                    "/rest/user/settings": settings,
                    "/rest/system/clock": clock,
                    "/rest/ip/service": services,
                    "/rest/ip/ssh": ssh,
                }
                payload = mikrotik_admin_settings(identity, settings, clock, services, ssh)
            elif capability == "services":
                ip_service = self._get("/rest/ip/service", capability=capability)
                extras = {
                    "bandwidth-server": self._get_optional(
                        "/rest/tool/bandwidth-server", capability=capability
                    ),
                    "proxy": self._get_optional("/rest/ip/proxy", capability=capability),
                    "socks": self._get_optional("/rest/ip/socks", capability=capability),
                    "upnp": self._get_optional("/rest/ip/upnp", capability=capability),
                    "cloud": self._get_optional("/rest/ip/cloud", capability=capability),
                    "pptp": self._get_optional(
                        "/rest/interface/pptp-server/server", capability=capability
                    ),
                }
                raw = {
                    "/rest/ip/service": ip_service,
                    "/rest/tool/bandwidth-server": extras["bandwidth-server"],
                    "/rest/ip/proxy": extras["proxy"],
                    "/rest/ip/socks": extras["socks"],
                    "/rest/ip/upnp": extras["upnp"],
                    "/rest/ip/cloud": extras["cloud"],
                    "/rest/interface/pptp-server/server": extras["pptp"],
                }
                payload = mikrotik_services(ip_service, extras)
            elif capability == "ntp":
                client = self._get("/rest/system/ntp/client", capability=capability)
                servers = self._get_optional("/rest/system/ntp/client/servers", capability=capability)
                raw = {
                    "/rest/system/ntp/client": client,
                    "/rest/system/ntp/client/servers": servers,
                }
                payload = mikrotik_ntp(client, servers)
            elif capability == "dns":
                raw = self._get("/rest/ip/dns", capability=capability)
                payload = mikrotik_dns(raw)
            elif capability == "logging":
                rules = self._get("/rest/system/logging", capability=capability)
                actions = self._get("/rest/system/logging/action", capability=capability)
                raw = {
                    "/rest/system/logging": rules,
                    "/rest/system/logging/action": actions,
                }
                payload = mikrotik_logging(rules, actions)
            elif capability == "snmp":
                snmp = self._get("/rest/snmp", capability=capability)
                communities = self._get("/rest/snmp/community", capability=capability)
                raw = {"/rest/snmp": snmp, "/rest/snmp/community": communities}
                payload = mikrotik_snmp(snmp, communities)
            elif capability == "firewall_filter":
                raw = self._get("/rest/ip/firewall/filter", capability=capability)
                payload = mikrotik_filter(raw)
            elif capability == "system_info":
                resource = self._get("/rest/system/resource", capability=capability)
                routerboard = self._get_optional("/rest/system/routerboard", capability=capability)
                update = self._get_optional("/rest/system/package/update", capability=capability)
                raw = {
                    "/rest/system/resource": resource,
                    "/rest/system/routerboard": routerboard,
                    "/rest/system/package/update": update,
                }
                payload = mikrotik_system(resource, routerboard, update)
            elif capability == "l2_access":
                discover = self._get(
                    "/rest/ip/neighbor/discovery-settings", capability=capability
                )
                mac = self._get("/rest/tool/mac-server", capability=capability)
                winbox = self._get("/rest/tool/mac-server/mac-winbox", capability=capability)
                ping = self._get("/rest/tool/mac-server/ping", capability=capability)
                raw = {
                    "/rest/ip/neighbor/discovery-settings": discover,
                    "/rest/tool/mac-server": mac,
                    "/rest/tool/mac-server/mac-winbox": winbox,
                    "/rest/tool/mac-server/ping": ping,
                }
                payload = mikrotik_l2_access(discover, mac, winbox, ping)
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
        return frozenset(CORE_CAPABILITIES + MIKROTIK_EXTRAS)

    def close(self) -> None:
        self._client.close()

    def _request(self, method: str, path: str) -> httpx.Response:
        started = time.perf_counter()
        status: int | None = None
        try:
            response = self._client.request(
                method,
                path,
                auth=httpx.BasicAuth(self._session.username, self._session.password),  # AuthScheme "basic"
            )
            status = response.status_code
            return response
        finally:
            elapsed = int((time.perf_counter() - started) * 1000)
            self.last_call = {
                "method": method,
                "path": path,
                "status": status,
                "ms": elapsed,
            }
            _log.debug(
                "%s %s -> %s (%sms)",
                method,
                http_target(self._client.base_url, path),
                status,
                elapsed,
            )

    def _get(self, path: str, *, capability: str | None = None) -> object:
        try:
            response = self._request("GET", path)
        except httpx.RequestError as exc:
            _raise_http(path, None, str(exc), capability)
        if not 200 <= response.status_code < 300:
            _raise_http(
                path,
                response.status_code,
                f"GET {path} returned {response.status_code}",
                capability,
            )
        return _decode_json(response, path, capability)

    def _get_optional(self, path: str, *, capability: str) -> object | None:
        try:
            response = self._request("GET", path)
        except httpx.RequestError as exc:
            _raise_http(path, None, str(exc), capability)
        if response.status_code == 404:
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
    "MikrotikAdapter",
    "mikrotik_admin_settings",
    "mikrotik_dns",
    "mikrotik_filter",
    "mikrotik_l2_access",
    "mikrotik_logging",
    "mikrotik_ntp",
    "mikrotik_services",
    "mikrotik_snmp",
    "mikrotik_system",
    "mikrotik_users",
]
