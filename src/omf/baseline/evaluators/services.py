from __future__ import annotations

from collections.abc import Mapping

from omf.schema.capabilities import ServiceList
from omf.schema.evidence import CheckResult, Evidence


def insecure_services_disabled(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    payload: ServiceList = evidence["services"].payload
    forbidden = {
        n.lower()
        for n in (
            *params.get("forbidden", ()),
            *params.get("forbidden_services", ()),
        )
    }
    hits = [s.name for s in payload.services if s.enabled and s.name.lower() in forbidden]
    return CheckResult(
        check_id="",
        status="fail" if hits else "pass",
        severity="high",
        diagnostic=(
            f"enabled insecure services {hits!r}" if hits else "insecure services are disabled"
        ),
        capability_refs=("services",),
        observed={"names": hits},
    )


def services_not_unrestricted(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    payload: ServiceList = evidence["services"].payload
    mgmt = {
        n.lower()
        for n in (
            *params.get("mgmt", ()),
            *params.get("mgmt_services", ()),
        )
    }
    hits = [
        s.name
        for s in payload.services
        if s.enabled and s.name.lower() in mgmt and s.listen in {"all", "unknown"}
    ]
    return CheckResult(
        check_id="",
        status="fail" if hits else "pass",
        severity="high",
        diagnostic=(
            f"management services listen on all/unknown {hits!r}"
            if hits
            else "management services are restricted"
        ),
        capability_refs=("services",),
        observed={"names": hits},
    )


def wan_mgmt_disabled(evidence, params, vendor) -> CheckResult:
    payload = evidence["services"].payload
    names = {n.lower() for n in params.get("wan_mgmt", ())}
    hits = [s.name for s in payload.services if s.enabled and s.on_wan and s.name.lower() in names]
    return CheckResult(
        check_id="",
        status="fail" if hits else "pass",
        severity="high",
        diagnostic=f"WAN management services {hits!r}" if hits else "WAN has no management services",
        capability_refs=("services",),
        observed={"names": hits},
    )
