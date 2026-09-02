from __future__ import annotations

from collections.abc import Mapping

from omf.schema.capabilities import UserList
from omf.schema.evidence import CheckResult, Evidence


def no_generic_accounts(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    names = {n.lower() for n in params.get("names", ("admin", "administrator", "root"))}
    payload: UserList = evidence["users"].payload
    hits = [u.name for u in payload.users if u.enabled and u.name.lower() in names]
    return CheckResult(
        check_id="",
        status="fail" if hits else "pass",
        severity="high",
        diagnostic=(
            f"enabled user matches vendor default name {hits!r}" if hits else "no generic admin names"
        ),
        capability_refs=("users",),
        observed={"names": hits},
    )
