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
        [c.name for c in payload.communities if c.name.lower() in forbidden]
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
    hits = (
        [c.name for c in payload.communities if str(c.version).lower() not in _V3]
        if payload.enabled
        else []
    )
    return CheckResult(
        check_id="",
        status="fail" if hits else "pass",
        severity="medium",
        diagnostic=(
            f"legacy SNMP communities {hits!r}" if hits else "SNMP is disabled or v3-only"
        ),
        capability_refs=("snmp",),
        observed={"enabled": payload.enabled, "legacy": hits},
    )
