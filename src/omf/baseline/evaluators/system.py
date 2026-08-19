from __future__ import annotations

from collections.abc import Mapping

from omf.schema.capabilities import SystemInfo
from omf.schema.evidence import CheckResult, Evidence


def _firmware_core(value: str) -> str:
    return value.strip().split()[0].lower() if value.strip() else ""


def firmware_present(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    payload: SystemInfo = evidence["system_info"].payload
    current = (payload.current_firmware or "").strip()
    if params.get("match_current") and current:
        failed = _firmware_core(payload.firmware) != _firmware_core(current)
        return CheckResult(
            check_id="",
            status="fail" if failed else "pass",
            severity="info",
            diagnostic=(
                f"firmware {payload.firmware!r} != routerboard {current!r}"
                if failed
                else "firmware matches routerboard"
            ),
            capability_refs=("system_info",),
            observed={"firmware": payload.firmware, "current_firmware": current},
        )
    failed = not payload.firmware.strip()
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="info",
        diagnostic="firmware version is missing" if failed else "firmware version is recorded",
        capability_refs=("system_info",),
        observed={"firmware": payload.firmware},
    )


def firmware_update_current(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    payload: SystemInfo = evidence["system_info"].payload
    status_text = (payload.update_status or "").strip()
    installed = (payload.installed_version or "").strip()
    latest = (payload.latest_version or "").strip()
    observed = {
        "update_status": payload.update_status,
        "installed_version": payload.installed_version,
        "latest_version": payload.latest_version,
    }
    if latest and installed and _firmware_core(installed) == _firmware_core(latest):
        return CheckResult(
            check_id="",
            status="pass",
            severity="medium",
            diagnostic=f"RouterOS {installed} matches latest {latest}",
            capability_refs=("system_info",),
            observed=observed,
        )
    if "already up to date" in status_text.lower():
        return CheckResult(
            check_id="",
            status="pass",
            severity="medium",
            diagnostic=status_text,
            capability_refs=("system_info",),
            observed=observed,
        )
    if not latest and not status_text:
        return CheckResult(
            check_id="",
            status="fail",
            severity="medium",
            diagnostic="no update check on record",
            capability_refs=("system_info",),
            observed=observed,
        )
    return CheckResult(
        check_id="",
        status="fail",
        severity="medium",
        diagnostic=(
            f"RouterOS {installed or payload.firmware!r} latest {latest or 'unknown'!r}"
            + (f" ({status_text})" if status_text else "")
        ),
        capability_refs=("system_info",),
        observed=observed,
    )
