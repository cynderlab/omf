from __future__ import annotations

from omf.schema.evidence import CheckResult


def utm_on_accept(evidence, params, vendor) -> CheckResult:
    field = str(params.get("field"))
    hits = [
        p.id
        for p in evidence["firewall_filter"].payload.policies
        if p.enabled and p.action == "accept" and not getattr(p, field)
    ]
    return CheckResult(
        check_id="", status="fail" if hits else "pass", severity="high",
        diagnostic=f"accept policies missing {field} {hits!r}" if hits else f"{field} is set on accept policies",
        capability_refs=("firewall_filter",), observed={"policy_ids": hits},
    )


def utm_profile_log_all(evidence, params, vendor) -> CheckResult:
    kind = str(params.get("kind") or "dnsfilter")
    hits = [p.name for p in evidence["utm"].payload.profiles if p.kind == kind and p.log_all]
    failed = not hits
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="medium",
        diagnostic=(
            f"no {kind} profile logs all queries" if failed else f"{kind} profile logs all queries"
        ),
        capability_refs=("utm",),
        observed={"profiles": hits},
    )


def utm_profile_blocks(evidence, params, vendor) -> CheckResult:
    kind = str(params.get("kind") or "")
    if kind == "webfilter":
        required = [str(item) for item in params.get("webfilter_block", ("malicious", "phishing", "spam"))]
    else:
        required = [str(item) for item in params.get("appctrl_block", ("p2p", "proxy"))]
    need = set(required)
    matches = [
        p.name
        for p in evidence["utm"].payload.profiles
        if p.kind == kind and need.issubset(set(p.blocked_categories))
    ]
    failed = not matches
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="high",
        diagnostic=(
            f"no {kind} profile blocks {required!r}" if failed else f"{kind} profile blocks {required!r}"
        ),
        capability_refs=("utm",),
        observed={"required": required, "profiles": matches},
    )


def utm_profile_no_allow(evidence, params, vendor) -> CheckResult:
    kind = str(params.get("kind") or "appctrl")
    hits = [
        p.name
        for p in evidence["utm"].payload.profiles
        if p.kind == kind and p.allowed_categories
    ]
    return CheckResult(
        check_id="",
        status="fail" if hits else "pass",
        severity="high",
        diagnostic=(
            f"{kind} profiles allow categories {hits!r}" if hits else f"no {kind} profile allows categories"
        ),
        capability_refs=("utm",),
        observed={"profiles": hits},
    )


def stitch_enabled(evidence, params, vendor) -> CheckResult:
    want = str(params.get("name") or "compromised host quarantine").casefold()
    stitches = [s for s in evidence["utm"].payload.stitches if s.name.casefold() == want]
    failed = not any(s.enabled for s in stitches)
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="high",
        diagnostic=(
            "Compromised Host Quarantine stitch is not enabled"
            if failed
            else "Compromised Host Quarantine stitch is enabled"
        ),
        capability_refs=("utm",),
        observed={"names": [s.name for s in stitches], "enabled": [s.enabled for s in stitches]},
    )
