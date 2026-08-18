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
]

ALL_CAPABILITIES: tuple[CapabilityName, ...] = (
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

Listen = Literal["all", "restricted", "unknown"]
PolicyAction = Literal["accept", "deny", "drop", "other"]


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


class Service(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    enabled: bool
    port: int
    listen: Listen


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


class SnmpCommunity(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    version: str


class SnmpConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool
    communities: tuple[SnmpCommunity, ...]


class Policy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    enabled: bool
    action: PolicyAction
    src: tuple[str, ...]
    dst: tuple[str, ...]
    service: tuple[str, ...]


class PolicyList(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    policies: tuple[Policy, ...]


class SystemInfo(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    firmware: str
    model: str | None = None
