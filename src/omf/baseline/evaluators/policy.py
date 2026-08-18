from __future__ import annotations

from collections.abc import Mapping

from omf.schema.capabilities import PolicyList
from omf.schema.evidence import CheckResult, Evidence


def _only_any(values: tuple[str, ...]) -> bool:
    return bool(values) and all(v.lower() == "any" for v in values)


def no_any_any_accept(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    payload: PolicyList = evidence["firewall_filter"].payload
    hits = [
        p.id
        for p in payload.policies
        if p.enabled
        and p.action == "accept"
        and _only_any(p.src)
        and _only_any(p.dst)
        and _only_any(p.service)
    ]
    return CheckResult(
        check_id="",
        status="fail" if hits else "pass",
        severity="high",
        diagnostic=(
            f"unrestricted accept policies {hits!r}" if hits else "no unrestricted accept policy"
        ),
        capability_refs=("firewall_filter",),
        observed={"policy_ids": hits},
    )


def explicit_deny_present(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    payload: PolicyList = evidence["firewall_filter"].payload
    denials = [p.id for p in payload.policies if p.enabled and p.action in {"deny", "drop"}]
    failed = not denials
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="medium",
        diagnostic=(
            "no enabled deny/drop policy" if failed else "explicit deny/drop policy is present"
        ),
        capability_refs=("firewall_filter",),
        observed={"policy_ids": denials},
    )


def no_unrestricted_service(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    hits = [
        p.id
        for p in evidence["firewall_filter"].payload.policies
        if p.enabled and _only_any(p.service)
    ]
    return CheckResult(
        check_id="",
        status="fail" if hits else "pass",
        severity="high",
        diagnostic=(
            f"policies with service any {hits!r}" if hits else "no policy uses unrestricted service"
        ),
        capability_refs=("firewall_filter",),
        observed={"policy_ids": hits},
    )


def isdb_denies_present(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    inbound = {str(x) for x in params.get("isdb_inbound", ())}
    outbound = {str(x) for x in params.get("isdb_outbound", ())}
    policies = [
        p
        for p in evidence["firewall_filter"].payload.policies
        if p.enabled and p.action in {"deny", "drop"}
    ]
    have_in = any(inbound.issubset(set(p.internet_src)) for p in policies)
    have_out = any(outbound.issubset(set(p.internet_dst)) for p in policies)
    failed = not (have_in and have_out)
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="high",
        diagnostic=(
            "missing ISDB deny coverage" if failed else "ISDB deny policies are present"
        ),
        capability_refs=("firewall_filter",),
        observed={"inbound_ok": have_in, "outbound_ok": have_out},
    )


def policies_logged(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    hits = [
        p.id
        for p in evidence["firewall_filter"].payload.policies
        if p.enabled and p.log is not True
    ]
    implicit = evidence["logging"].payload.implicit_policy_logged
    failed = bool(hits) or implicit is not True
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="medium",
        diagnostic=f"unlogged policies {hits!r} implicit={implicit!r}",
        capability_refs=("firewall_filter", "logging"),
        observed={"policy_ids": hits, "implicit_policy_logged": implicit},
    )
