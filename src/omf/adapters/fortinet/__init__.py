"""Fortinet FortiOS REST adapter (`/api/v2/...`, Bearer token or session login)."""

from .adapter import FortinetAdapter
from .normalize import (
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
    forti_unwrap,
    forti_users,
    forti_utm,
    forti_zones,
)

__all__ = [
    "FortinetAdapter",
    "forti_admin_settings",
    "forti_dns",
    "forti_filter",
    "forti_ha",
    "forti_licenses",
    "forti_local_in",
    "forti_logging",
    "forti_ntp",
    "forti_object_usage",
    "forti_services",
    "forti_snmp",
    "forti_system",
    "forti_unwrap",
    "forti_users",
    "forti_utm",
    "forti_zones",
]
