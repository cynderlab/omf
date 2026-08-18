from __future__ import annotations

from omf.schema.evidence import CheckResult


def intrazone_denied(evidence, params, vendor) -> CheckResult:
    payload = evidence["zones"].payload
    hits = [z.name for z in payload.zones if z.intrazone == "allow"]
    return CheckResult(
        check_id="",
        status="fail" if hits else "pass",
        severity="medium",
        diagnostic=f"zones allow intra-zone traffic {hits!r}" if hits else "intra-zone traffic is denied",
        capability_refs=("zones",),
        observed={"zones": hits},
    )
