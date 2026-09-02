from __future__ import annotations

from collections.abc import Mapping

from omf.schema.capabilities import SnmpConfig
from omf.schema.evidence import CheckResult, Evidence

_V3 = {"3", "v3"}


def no_default_snmp_community(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    payload: SnmpConfig = evidence["snmp"].payload
    forbidden = {n.lower() for n in params.get("forbidden", ("public", "private"))}
    hits = (
        [
            c.name
            for c in payload.communities
            if c.name.lower() in forbidden
            and (not params.get("require_read_access") or c.read_access is True)
        ]
        if payload.enabled
        else []
    )
    return CheckResult(
        check_id="",
        status="fail" if hits else "pass",
        severity="high",
        diagnostic=(
            f"default SNMP communities {hits!r}" if hits else "no default SNMP communities"
        ),
        capability_refs=("snmp",),
        observed={"enabled": payload.enabled, "communities": hits},
    )


def snmp_not_legacy(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    payload: SnmpConfig = evidence["snmp"].payload
    legacy_versions = {str(v).lower() for v in params.get("legacy_versions", ())}
    hits = (
        [
            c.name
            for c in payload.communities
            if (
                str(c.version).lower() in legacy_versions
                if legacy_versions
                else str(c.version).lower() not in _V3
            )
        ]
        if payload.enabled
        else []
    )
    missing_user = bool(params.get("require_v3_user")) and payload.enabled and not payload.users
    failed = bool(hits) or missing_user
    if hits:
        diagnostic = f"legacy SNMP communities {hits!r}"
    elif missing_user:
        diagnostic = "SNMP enabled without an SNMPv3 user"
    else:
        diagnostic = "SNMP is disabled or v3-only"
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="medium",
        diagnostic=diagnostic,
        capability_refs=("snmp",),
        observed={"enabled": payload.enabled, "legacy": hits, "users": len(payload.users)},
    )


def snmp_memory_traps(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    payload: SnmpConfig = evidence["snmp"].payload
    free_ok = isinstance(payload.trap_free_memory_threshold, int) and payload.trap_free_memory_threshold > 0
    freeable_ok = (
        isinstance(payload.trap_freeable_memory_threshold, int)
        and payload.trap_freeable_memory_threshold > 0
    )
    failed = payload.enabled and not (free_ok and freeable_ok)
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="medium",
        diagnostic=(
            "SNMP memory trap thresholds are missing or zero"
            if failed
            else "SNMP is disabled or memory traps are configured"
        ),
        capability_refs=("snmp",),
        observed={
            "enabled": payload.enabled,
            "trap_free_memory_threshold": payload.trap_free_memory_threshold,
            "trap_freeable_memory_threshold": payload.trap_freeable_memory_threshold,
        },
    )
