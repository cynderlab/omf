from __future__ import annotations

from collections.abc import Mapping

from omf.schema.capabilities import PolicyList
from omf.schema.evidence import CheckResult, Evidence


def _only_any(values: tuple[str, ...]) -> bool:
    return bool(values) and all(v.lower() == "any" for v in values)


def _is_established(policy) -> bool:
    return "established" in {state.lower() for state in policy.connection_state}


def _is_interface_scoped(policy) -> bool:
    return bool(
        policy.in_interface
        or policy.out_interface
        or policy.in_interface_list
        or policy.out_interface_list
    )


def _skip_mikrotik_noise(policy, params: dict) -> bool:
    if params.get("skip_established") and _is_established(policy):
        return True
    if params.get("skip_established_forward") and policy.chain == "forward" and _is_established(policy):
        return True
    if params.get("skip_interface_scoped") and _is_interface_scoped(policy):
        return True
    return False


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
        and not _skip_mikrotik_noise(p, params)
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
    required = [str(c).strip().lower() for c in params.get("chains", ()) if str(c).strip()]
    unrestricted = bool(params.get("unrestricted_only"))
    denials = []
    for policy in payload.policies:
        if not policy.enabled or policy.action not in {"deny", "drop"}:
            continue
        if unrestricted and not (_only_any(policy.src) and _only_any(policy.dst) and _only_any(policy.service)):
            continue
        denials.append(policy.id)
    if required:
        have = {
            policy.chain
            for policy in payload.policies
            if policy.enabled
            and policy.action in {"deny", "drop"}
            and policy.id in denials
        }
        failed = not set(required).issubset(have)
    else:
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
    actions = {str(a).lower() for a in params.get("actions", ())}
    hits = [
        p.id
        for p in evidence["firewall_filter"].payload.policies
        if p.enabled
        and _only_any(p.service)
        and (not actions or p.action in actions)
        and not _skip_mikrotik_noise(p, params)
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
    require_implicit = params.get("require_implicit", True)
    failed = bool(hits) or (require_implicit and implicit is not True)
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="medium",
        diagnostic=f"unlogged policies {hits!r} implicit={implicit!r}",
        capability_refs=("firewall_filter", "logging"),
        observed={"policy_ids": hits, "implicit_policy_logged": implicit},
    )
