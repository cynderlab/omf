from __future__ import annotations

from collections.abc import Mapping

from omf.schema.capabilities import PolicyList, UsageList
from omf.schema.evidence import CheckResult, Evidence

_SAMPLE = 8


def _sample(values: list[str]) -> str:
    if len(values) <= _SAMPLE:
        return repr(values)
    return repr(values[:_SAMPLE]) + f" ... ({len(values)} total)"


def disabled_policies(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    payload: PolicyList = evidence["firewall_filter"].payload
    hits = [p for p in payload.policies if not p.enabled]
    ids = [p.id for p in hits]
    return CheckResult(
        check_id="",
        status="fail" if hits else "pass",
        severity="low",
        diagnostic=(
            f"disabled firewall policies {_sample(ids)}" if hits else "no disabled firewall policy"
        ),
        capability_refs=("firewall_filter",),
        observed={"policies": [{"id": p.id} for p in hits]},
    )


def zero_hit_policies(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    usage: UsageList = evidence["object_usage"].payload
    disabled = {
        p.id for p in evidence["firewall_filter"].payload.policies if not p.enabled
    }
    hits = [
        item
        for item in usage.items
        if item.kind == "policy" and item.hit_count == 0 and item.name not in disabled
    ]
    ids = [item.name for item in hits]
    return CheckResult(
        check_id="",
        status="fail" if hits else "pass",
        severity="low",
        diagnostic=(
            f"zero-hit firewall policies {_sample(ids)}" if hits else "no zero-hit enabled policy"
        ),
        capability_refs=("object_usage", "firewall_filter"),
        observed={"policies": [{"id": item.name, "hit_count": item.hit_count} for item in hits]},
    )


def unref_objects(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    kinds = {str(k) for k in params.get("kinds", ())}
    skip_names = {str(n) for n in params.get("skip_names", ())}
    skip_static = params.get("skip_static", True)
    hits = []
    for item in evidence["object_usage"].payload.items:
        if item.kind == "policy":
            continue
        if kinds and item.kind not in kinds:
            continue
        if skip_static and item.static:
            continue
        if item.name in skip_names:
            continue
        if item.refs != 0:
            continue
        hits.append(item)
    names = [item.name for item in hits]
    return CheckResult(
        check_id="",
        status="fail" if hits else "pass",
        severity="low",
        diagnostic=(
            f"{len(hits)} unreferenced objects {_sample(names)}"
            if hits
            else "no unreferenced firewall object"
        ),
        capability_refs=("object_usage",),
        observed={"objects": [{"kind": item.kind, "name": item.name} for item in hits]},
    )
