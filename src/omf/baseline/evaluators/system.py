from __future__ import annotations

from collections.abc import Mapping

from omf.schema.capabilities import SystemInfo
from omf.schema.evidence import CheckResult, Evidence


def firmware_present(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    payload: SystemInfo = evidence["system_info"].payload
    failed = not payload.firmware.strip()
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="info",
        diagnostic="firmware version is missing" if failed else "firmware version is recorded",
        capability_refs=("system_info",),
        observed={"firmware": payload.firmware},
    )
