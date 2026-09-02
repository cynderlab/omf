"""Pure check evaluators. No HTTP, adapters, or secrets."""

from __future__ import annotations

from collections.abc import Callable, Mapping

from omf.baseline.evaluators.accounts import no_generic_accounts
from omf.baseline.evaluators.admin import (
    admin_ports_changed,
    flag_enabled,
    hostname_not_default,
    idle_timeout_set,
    lockout_configured,
    password_policy_strong,
    timezone_set,
    tls_versions_allowed,
)
from omf.baseline.evaluators.ha import ha_monitors_set, ha_reserved_mgmt
from omf.baseline.evaluators.hygiene import disabled_policies, unref_objects, zero_hit_policies
from omf.baseline.evaluators.l2 import l2_surfaces_closed
from omf.baseline.evaluators.license import license_active
from omf.baseline.evaluators.local_in import local_in_present, virtual_patch_on_accept
from omf.baseline.evaluators.logging import (
    faz_encrypted,
    local_logging_enabled,
    remote_syslog_configured,
    syslog_encrypted,
)
from omf.baseline.evaluators.network import intrazone_denied
from omf.baseline.evaluators.ntp_dns import dns_configured, ntp_configured
from omf.baseline.evaluators.policy import (
    explicit_deny_present,
    isdb_denies_present,
    no_any_any_accept,
    no_unrestricted_service,
    policies_logged,
)
from omf.baseline.evaluators.services import (
    insecure_services_disabled,
    named_services_disabled,
    services_not_unrestricted,
    wan_mgmt_disabled,
)
from omf.baseline.evaluators.snmp import no_default_snmp_community, snmp_memory_traps, snmp_not_legacy
from omf.baseline.evaluators.system import (
    firmware_present,
    firmware_supported,
    firmware_update_current,
)
from omf.baseline.evaluators.utm import (
    stitch_enabled,
    utm_on_accept,
    utm_profile_blocks,
    utm_profile_log_all,
    utm_profile_no_allow,
)
from omf.baseline.loader import CheckDef, resolve_params
from omf.schema.evidence import CheckResult, Evidence

Evaluator = Callable[[Mapping[str, Evidence], dict, str], CheckResult]

REGISTRY: dict[str, Evaluator] = {
    "no_generic_accounts": no_generic_accounts,
    "idle_timeout_set": idle_timeout_set,
    "hostname_not_default": hostname_not_default,
    "timezone_set": timezone_set,
    "tls_versions_allowed": tls_versions_allowed,
    "flag_enabled": flag_enabled,
    "password_policy_strong": password_policy_strong,
    "lockout_configured": lockout_configured,
    "admin_ports_changed": admin_ports_changed,
    "insecure_services_disabled": insecure_services_disabled,
    "named_services_disabled": named_services_disabled,
    "services_not_unrestricted": services_not_unrestricted,
    "wan_mgmt_disabled": wan_mgmt_disabled,
    "l2_surfaces_closed": l2_surfaces_closed,
    "ntp_configured": ntp_configured,
    "dns_configured": dns_configured,
    "local_logging_enabled": local_logging_enabled,
    "remote_syslog_configured": remote_syslog_configured,
    "syslog_encrypted": syslog_encrypted,
    "faz_encrypted": faz_encrypted,
    "no_default_snmp_community": no_default_snmp_community,
    "snmp_not_legacy": snmp_not_legacy,
    "snmp_memory_traps": snmp_memory_traps,
    "no_any_any_accept": no_any_any_accept,
    "explicit_deny_present": explicit_deny_present,
    "no_unrestricted_service": no_unrestricted_service,
    "isdb_denies_present": isdb_denies_present,
    "policies_logged": policies_logged,
    "firmware_present": firmware_present,
    "firmware_supported": firmware_supported,
    "firmware_update_current": firmware_update_current,
    "license_active": license_active,
    "intrazone_denied": intrazone_denied,
    "local_in_present": local_in_present,
    "virtual_patch_on_accept": virtual_patch_on_accept,
    "ha_monitors_set": ha_monitors_set,
    "ha_reserved_mgmt": ha_reserved_mgmt,
    "disabled_policies": disabled_policies,
    "zero_hit_policies": zero_hit_policies,
    "unref_objects": unref_objects,
    "utm_on_accept": utm_on_accept,
    "utm_profile_log_all": utm_profile_log_all,
    "utm_profile_blocks": utm_profile_blocks,
    "utm_profile_no_allow": utm_profile_no_allow,
    "stitch_enabled": stitch_enabled,
}


def evaluate(
    check: CheckDef,
    evidence: Mapping[str, Evidence],
    vendor: str,
) -> CheckResult:
    try:
        for need in check.needs:
            if need not in evidence:
                return CheckResult(
                    check_id=check.id,
                    status="error",
                    severity=check.severity,
                    diagnostic=f"missing capability {need}",
                    capability_refs=tuple(check.needs),
                    observed={},
                )
        raw = REGISTRY[check.evaluator](evidence, resolve_params(check, vendor), vendor)
        return raw.model_copy(
            update={
                "check_id": check.id,
                "severity": check.severity,
                "capability_refs": tuple(check.needs),
            }
        )
    except Exception as exc:
        return CheckResult(
            check_id=check.id,
            status="error",
            severity=check.severity,
            diagnostic=str(exc),
            capability_refs=tuple(check.needs),
            observed={},
        )


__all__ = [
    "REGISTRY",
    "Evaluator",
    "evaluate",
]
