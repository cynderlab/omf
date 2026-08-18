from __future__ import annotations

from collections.abc import Callable, Mapping

from omf.baseline.evaluators.accounts import no_generic_accounts
from omf.baseline.evaluators.admin import (
    admin_ports_changed,
    banner_enabled,
    flag_enabled,
    hostname_not_default,
    idle_timeout_set,
    lockout_configured,
    password_policy_strong,
    timezone_set,
    tls_versions_allowed,
)
from omf.baseline.evaluators.logging import local_logging_enabled, remote_syslog_configured
from omf.baseline.evaluators.network import intrazone_denied
from omf.baseline.evaluators.ntp_dns import dns_configured, ntp_configured
from omf.baseline.evaluators.policy import explicit_deny_present, no_any_any_accept
from omf.baseline.evaluators.services import (
    insecure_services_disabled,
    services_not_unrestricted,
    wan_mgmt_disabled,
)
from omf.baseline.evaluators.snmp import no_default_snmp_community, snmp_not_legacy
from omf.baseline.evaluators.system import firmware_present
from omf.baseline.loader import CheckDef, resolve_params
from omf.schema.evidence import CheckResult, Evidence

Evaluator = Callable[[Mapping[str, Evidence], dict, str], CheckResult]

REGISTRY: dict[str, Evaluator] = {
    "no_generic_accounts": no_generic_accounts,
    "idle_timeout_set": idle_timeout_set,
    "hostname_not_default": hostname_not_default,
    "banner_enabled": banner_enabled,
    "timezone_set": timezone_set,
    "tls_versions_allowed": tls_versions_allowed,
    "flag_enabled": flag_enabled,
    "password_policy_strong": password_policy_strong,
    "lockout_configured": lockout_configured,
    "admin_ports_changed": admin_ports_changed,
    "insecure_services_disabled": insecure_services_disabled,
    "services_not_unrestricted": services_not_unrestricted,
    "wan_mgmt_disabled": wan_mgmt_disabled,
    "ntp_configured": ntp_configured,
    "dns_configured": dns_configured,
    "local_logging_enabled": local_logging_enabled,
    "remote_syslog_configured": remote_syslog_configured,
    "no_default_snmp_community": no_default_snmp_community,
    "snmp_not_legacy": snmp_not_legacy,
    "no_any_any_accept": no_any_any_accept,
    "explicit_deny_present": explicit_deny_present,
    "firmware_present": firmware_present,
    "intrazone_denied": intrazone_denied,
}


def get_evaluator(name: str) -> Evaluator:
    return REGISTRY[name]


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
    "get_evaluator",
]
