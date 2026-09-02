from __future__ import annotations

from collections.abc import Mapping
from datetime import date, datetime, timezone

from omf.schema.evidence import CheckResult, Evidence


def _as_of_date(value: datetime) -> date:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc).date()
    return value.astimezone(timezone.utc).date()


def license_active(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    key = str(params.get("key") or "")
    required = bool(params.get("required", True))
    as_of = _as_of_date(evidence["licenses"].collected_at)
    match = next(
        (item for item in evidence["licenses"].payload.entitlements if item.key == key),
        None,
    )
    status = match.status if match else "unlicensed"
    expires = match.expires if match else None
    if expires:
        try:
            if date.fromisoformat(expires) < as_of:
                status = "expired"
        except ValueError:
            pass
    failed = status != "licensed" if required else status == "expired"
    diagnostic = f"{key} is {status}"
    if expires:
        diagnostic = f"{diagnostic} (expires {expires})"
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="high",
        diagnostic=diagnostic,
        capability_refs=("licenses",),
        observed={"key": key, "status": status, "expires": expires},
    )
