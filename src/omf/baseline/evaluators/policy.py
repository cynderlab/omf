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
