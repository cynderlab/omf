from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import date, datetime, timezone

from omf.schema.capabilities import SystemInfo
from omf.schema.evidence import CheckResult, Evidence

_BRANCH_RE = re.compile(r"(\d+)\.(\d+)")


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


def _branch(firmware: str) -> str | None:
    match = _BRANCH_RE.search(firmware)
    return f"{match.group(1)}.{match.group(2)}" if match else None


def _branch_tuple(branch: str) -> tuple[int, int] | None:
    match = _BRANCH_RE.fullmatch(branch.strip())
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)))


def _as_of_date(value: datetime) -> date:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc).date()
    return value.astimezone(timezone.utc).date()


def firmware_supported(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    payload: SystemInfo = evidence["system_info"].payload
    as_of = _as_of_date(evidence["system_info"].collected_at)
    raw_table = params.get("fortios_lifecycle") or {}
    table = {str(key): value for key, value in raw_table.items()} if isinstance(raw_table, dict) else {}
    firmware = payload.firmware or ""
    branch = _branch(firmware)
    observed: dict = {"firmware": firmware, "branch": branch, "as_of": as_of.isoformat()}
    if not firmware.strip() or branch is None:
        return CheckResult(
            check_id="",
            status="fail",
            severity="high",
            diagnostic="firmware version is missing" if not firmware.strip() else f"firmware {firmware!r} is unparsable",
            capability_refs=("system_info",),
            observed=observed,
        )
    parsed_keys = [item for item in (_branch_tuple(str(key)) for key in table) if item is not None]
    current = _branch_tuple(branch)
    if current is None:
        return CheckResult(
            check_id="",
            status="fail",
            severity="high",
            diagnostic=f"firmware {firmware!r} is unparsable",
            capability_refs=("system_info",),
            observed=observed,
        )
    if parsed_keys and current > max(parsed_keys):
        return CheckResult(
            check_id="",
            status="pass",
            severity="high",
            diagnostic=f"FortiOS {firmware} branch {branch} is newer than the lifecycle table",
            capability_refs=("system_info",),
            observed=observed,
        )
    row = table.get(branch) or {}
    eoes = str(row.get("eoes") or "")
    eos = str(row.get("eos") or "")
    observed["eoes"] = eoes or None
    observed["eos"] = eos or None
    supported = bool(eoes) and as_of < date.fromisoformat(eoes)
    detail = f"FortiOS {firmware} branch {branch} eoes {eoes or 'unknown'} eos {eos or 'unknown'} as of {as_of.isoformat()}"
    return CheckResult(
        check_id="",
        status="pass" if supported else "fail",
        severity="high",
        diagnostic=detail,
        capability_refs=("system_info",),
        observed=observed,
    )
