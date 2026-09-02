from __future__ import annotations

from collections.abc import Mapping

from omf.schema.capabilities import ServiceList
from omf.schema.evidence import CheckResult, Evidence


def _service_hit(service) -> dict:
    return {
        "name": service.name,
        "port": service.port,
        "listen": service.listen,
        "on_wan": service.on_wan,
        "interfaces": list(service.interfaces),
    }


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
    hits = [s for s in payload.services if s.enabled and s.name.lower() in forbidden]
    names = [s.name for s in hits]
    return CheckResult(
        check_id="",
        status="fail" if hits else "pass",
        severity="high",
        diagnostic=(
            f"enabled insecure services {names!r}" if hits else "insecure services are disabled"
        ),
        capability_refs=("services",),
        observed={"services": [_service_hit(s) for s in hits]},
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
        s
        for s in payload.services
        if s.enabled and s.name.lower() in mgmt and s.listen in {"all", "unknown"}
    ]
    names = [s.name for s in hits]
    return CheckResult(
        check_id="",
        status="fail" if hits else "pass",
        severity="high",
        diagnostic=(
            f"management services listen on all/unknown {names!r}"
            if hits
            else "management services are restricted"
        ),
        capability_refs=("services",),
        observed={"services": [_service_hit(s) for s in hits]},
    )


def named_services_disabled(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    payload: ServiceList = evidence["services"].payload
    names = {str(n).lower() for n in params.get("names", ())}
    hits = [s for s in payload.services if s.enabled and s.name.lower() in names]
    hit_names = [s.name for s in hits]
    return CheckResult(
        check_id="",
        status="fail" if hits else "pass",
        severity="medium",
        diagnostic=(
            f"enabled extra services {hit_names!r}" if hits else "named extra services are disabled"
        ),
        capability_refs=("services",),
        observed={"services": [_service_hit(s) for s in hits]},
    )


def wan_mgmt_disabled(evidence, params, vendor) -> CheckResult:
    payload = evidence["services"].payload
    names = {n.lower() for n in params.get("wan_mgmt", ())}
    hits = [s for s in payload.services if s.enabled and s.on_wan and s.name.lower() in names]
    hit_names = [s.name for s in hits]
    return CheckResult(
        check_id="",
        status="fail" if hits else "pass",
        severity="high",
        diagnostic=(
            f"WAN management services {hit_names!r}" if hits else "WAN has no management services"
        ),
        capability_refs=("services",),
        observed={"services": [_service_hit(s) for s in hits]},
    )
