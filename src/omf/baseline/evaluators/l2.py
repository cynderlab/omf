from __future__ import annotations

from collections.abc import Mapping

from omf.schema.capabilities import L2Access
from omf.schema.evidence import CheckResult, Evidence


def _list_value(payload: L2Access, field: str) -> str:
    return str(getattr(payload, field) or "").strip()


def l2_surfaces_closed(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    payload: L2Access = evidence["l2_access"].payload
    hits: list[str] = []
    for field in params.get("lists", ()):
        value = _list_value(payload, str(field))
        if value.lower() != "none":
            hits.append(f"{field}={value or 'unset'}")
    for field in params.get("flags_off", ()):
        if getattr(payload, str(field)) is True:
            hits.append(str(field))
    return CheckResult(
        check_id="",
        status="fail" if hits else "pass",
        severity="medium",
        diagnostic=(f"open L2 surfaces {hits}" if hits else "L2 surfaces are closed"),
        capability_refs=("l2_access",),
        observed={"hits": hits},
    )
