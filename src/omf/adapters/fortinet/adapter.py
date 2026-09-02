"""Fortinet FortiOS REST adapter (`/api/v2/...`, Bearer token or session login)."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any, Literal, NoReturn

import httpx

from omf.adapters.base import CollectError, ProbeError
from .normalize import (
    _drop_secrets,
    forti_admin_settings,
    forti_dns,
    forti_filter,
    forti_ha,
    forti_licenses,
    forti_local_in,
    forti_logging,
    forti_ntp,
    forti_object_usage,
    forti_services,
    forti_snmp,
    forti_system,
    forti_utm,
    forti_users,
    forti_zones,
)
from omf.log import get_logger, http_target
from omf.schema.capabilities import CORE_CAPABILITIES, FORTINET_EXTRAS
from omf.schema.evidence import Evidence
from omf.session import Session

_CMDB_USAGE: tuple[tuple[str, str, bool], ...] = (
    ("address_raw", "/api/v2/cmdb/firewall/address", False),
    ("addrgrp_raw", "/api/v2/cmdb/firewall/addrgrp", True),
    ("service_raw", "/api/v2/cmdb/firewall.service/custom", True),
    ("service_group_raw", "/api/v2/cmdb/firewall.service/group", True),
    ("vip_raw", "/api/v2/cmdb/firewall/vip", True),
    ("ippool_raw", "/api/v2/cmdb/firewall/ippool", True),
)


def _raise_if_truncated(raw: object, path: str, capability: str) -> None:
    if isinstance(raw, dict) and raw.get("limit_reached") is True:
        raise CollectError(
            capability,
            path,
            200,
            f"GET {path} truncated (limit_reached)",
        )


_log = get_logger("omf.http")


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
                raw: object = self._get(
                    "/api/v2/cmdb/system/admin",
                    capability=capability,
                    query={"exclude-default-values": "false"},
                )
                payload: object = forti_users(raw)
            elif capability == "admin_settings":
                global_raw = self._get("/api/v2/cmdb/system/global", capability=capability)
                admin_raw = self._get(
                    "/api/v2/cmdb/system/admin",
                    capability=capability,
                    query={"exclude-default-values": "false"},
                )
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
                admin_raw = self._get(
                    "/api/v2/cmdb/system/admin",
                    capability=capability,
                    query={"exclude-default-values": "false"},
                )
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
                    "/api/v2/cmdb/log/setting",
                    capability=capability,
                    optional=True,
                )
                raw = {"/api/v2/cmdb/log.syslogd/setting": syslogd}
                if syslogd2 is not None:
                    raw["/api/v2/cmdb/log.syslogd2/setting"] = syslogd2
                if faz is not None:
                    raw["/api/v2/cmdb/log.fortianalyzer/setting"] = faz
                if log_setting is not None:
                    raw["/api/v2/cmdb/log/setting"] = log_setting
                payload = forti_logging(syslogd, syslogd2, faz, log_setting)
            elif capability == "snmp":
                community_raw = self._get(
                    "/api/v2/cmdb/system.snmp/community",
                    capability=capability,
                )
                sysinfo_raw = self._get(
                    "/api/v2/cmdb/system.snmp/sysinfo",
                    capability=capability,
                )
                user_raw = self._get(
                    "/api/v2/cmdb/system.snmp/user",
                    capability=capability,
                )
                raw = {
                    "/api/v2/cmdb/system.snmp/community": community_raw,
                    "/api/v2/cmdb/system.snmp/sysinfo": sysinfo_raw,
                    "/api/v2/cmdb/system.snmp/user": user_raw,
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
            elif capability == "object_usage":
                usage_kwargs: dict[str, object] = {}
                stats_path = "/api/v2/monitor/firewall/policy"
                policy_stats_raw = self._get(stats_path, capability=capability)
                _raise_if_truncated(policy_stats_raw, stats_path, capability)
                raw = {stats_path: policy_stats_raw}
                usage_kwargs["policy_stats_raw"] = policy_stats_raw
                for key, path, optional in _CMDB_USAGE:
                    table_raw = self._get(
                        path,
                        capability=capability,
                        optional=optional,
                        query={"with_meta": "1"},
                    )
                    if table_raw is None:
                        continue
                    _raise_if_truncated(table_raw, path, capability)
                    raw[path] = table_raw
                    usage_kwargs[key] = table_raw
                payload = forti_object_usage(**usage_kwargs)
            elif capability == "licenses":
                raw = self._get("/api/v2/monitor/license/status", capability=capability)
                payload = forti_licenses(raw)
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
        return frozenset(CORE_CAPABILITIES + FORTINET_EXTRAS)

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

    def _get(
        self,
        path: str,
        *,
        capability: str | None = None,
        optional: bool = False,
        query: dict[str, str] | None = None,
    ) -> object:
        try:
            response = self._request("GET", path, params=query)
        except httpx.RequestError as exc:
            _raise_http(path, None, str(exc), capability)
        # FortiOS missing/wrong CMDB tables return 400 or 405, not only 404.
        if optional and response.status_code in {400, 404, 405}:
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
