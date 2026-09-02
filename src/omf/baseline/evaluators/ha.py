from __future__ import annotations

from omf.schema.evidence import CheckResult


def _ha_active(mode: str) -> bool:
    return mode not in {"", "standalone", "disable", "disabled"}


def ha_monitors_set(evidence, params, vendor) -> CheckResult:
    payload = evidence["ha"].payload
    if not _ha_active(payload.mode):
        return CheckResult(
            check_id="",
            status="pass",
            severity="medium",
            diagnostic="HA is not enabled",
            capability_refs=("ha",),
            observed={"mode": payload.mode},
        )
    failed = not payload.monitor_interfaces
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="medium",
        diagnostic="HA monitor interfaces are empty" if failed else "HA monitor interfaces are set",
        capability_refs=("ha",),
        observed={"mode": payload.mode, "monitor": list(payload.monitor_interfaces)},
    )


def ha_reserved_mgmt(evidence, params, vendor) -> CheckResult:
    payload = evidence["ha"].payload
    if not _ha_active(payload.mode):
        return CheckResult(
            check_id="",
            status="pass",
            severity="medium",
            diagnostic="HA is not enabled",
            capability_refs=("ha",),
            observed={"mode": payload.mode},
        )
    failed = (not payload.ha_mgmt_status) or (not payload.ha_mgmt_interfaces)
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="medium",
        diagnostic=(
            "HA reserved management is missing" if failed else "HA reserved management is configured"
        ),
        capability_refs=("ha",),
        observed={
            "ha_mgmt_status": payload.ha_mgmt_status,
            "interfaces": list(payload.ha_mgmt_interfaces),
        },
    )
