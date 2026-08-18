"""Canonical frozen payloads for the nine MVP capabilities."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

CapabilityName = Literal[
    "users",
    "admin_settings",
    "services",
    "ntp",
    "dns",
    "logging",
    "snmp",
    "firewall_filter",
    "system_info",
    "zones",
    "local_in",
    "ha",
    "utm",
]

CORE_CAPABILITIES: tuple[CapabilityName, ...] = (
    "users",
    "admin_settings",
    "services",
    "ntp",
    "dns",
    "logging",
    "snmp",
    "firewall_filter",
    "system_info",
)

ALL_CAPABILITIES: tuple[CapabilityName, ...] = CORE_CAPABILITIES + (
    "zones",
    "local_in",
    "ha",
    "utm",
)

Listen = Literal["all", "restricted", "unknown"]
PolicyAction = Literal["accept", "deny", "drop", "other"]
Intrazone = Literal["allow", "deny", "unknown"]
UtmKind = Literal["dnsfilter", "webfilter", "appctrl"]


class User(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    enabled: bool
    groups: tuple[str, ...]


class UserList(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    users: tuple[User, ...]


class AdminSettings(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    hostname: str
    idle_timeout_seconds: int | None = None
    pre_login_banner: bool | None = None
    post_login_banner: bool | None = None
    timezone: str | None = None
    admin_https_ssl_versions: tuple[str, ...] = ()
    log_single_cpu_high: bool | None = None
    password_policy_enabled: bool | None = None
    password_min_length: int | None = None
    password_apply_to: tuple[str, ...] = ()
    admin_lockout_threshold: int | None = None
    admin_lockout_duration: int | None = None
    admin_http_port: int | None = None
    admin_https_port: int | None = None
    admin_https_redirect: bool | None = None


class Service(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    enabled: bool
    port: int
    listen: Listen
    on_wan: bool = False


class ServiceList(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    services: tuple[Service, ...]


class NtpConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool
    servers: tuple[str, ...]


class DnsConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    servers: tuple[str, ...]


class LoggingConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    local_enabled: bool
    remote_targets: tuple[str, ...]
    syslog_reliable: bool | None = None
    syslog_enc_high: bool | None = None
    faz_enabled: bool | None = None
    faz_reliable: bool | None = None
    faz_enc_high: bool | None = None
    implicit_policy_logged: bool | None = None


class SnmpCommunity(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    version: str


class SnmpUser(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    security_level: str


class SnmpConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool
    communities: tuple[SnmpCommunity, ...]
    users: tuple[SnmpUser, ...] = ()
    trap_free_memory_threshold: int | None = None
    trap_freeable_memory_threshold: int | None = None


class Policy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    enabled: bool
    action: PolicyAction
    src: tuple[str, ...]
    dst: tuple[str, ...]
    service: tuple[str, ...]
    log: bool | None = None
    ips_sensor: str | None = None
    dnsfilter_profile: str | None = None
    webfilter_profile: str | None = None
    application_list: str | None = None
    internet_src: tuple[str, ...] = ()
    internet_dst: tuple[str, ...] = ()


class PolicyList(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    policies: tuple[Policy, ...]


class SystemInfo(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    firmware: str
    model: str | None = None


class Zone(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    intrazone: Intrazone


class ZoneList(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    zones: tuple[Zone, ...]


class LocalInPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    enabled: bool
    action: PolicyAction
    virtual_patch: bool = False


class LocalInPolicyList(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    policies: tuple[LocalInPolicy, ...]


class HaConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: str
    monitor_interfaces: tuple[str, ...] = ()
    ha_mgmt_status: bool = False
    ha_mgmt_interfaces: tuple[str, ...] = ()


class UtmProfile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    kind: UtmKind
    log_all: bool = False
    blocked_categories: tuple[str, ...] = ()
    allowed_categories: tuple[str, ...] = ()


class AutomationStitch(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    enabled: bool


class UtmConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    profiles: tuple[UtmProfile, ...] = ()
    stitches: tuple[AutomationStitch, ...] = ()
