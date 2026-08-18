from __future__ import annotations

from collections.abc import Mapping

from omf.schema.capabilities import AdminSettings
from omf.schema.evidence import CheckResult, Evidence


def idle_timeout_set(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    payload: AdminSettings = evidence["admin_settings"].payload
    timeout = payload.idle_timeout_seconds
    failed = timeout is None or timeout <= 0
    max_seconds = params.get("max_seconds")
    if not failed and max_seconds is not None:
        failed = timeout > max_seconds
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="medium",
        diagnostic=(
            f"idle timeout is {timeout!r}" if failed else f"idle timeout is {timeout}s"
        ),
        capability_refs=("admin_settings",),
        observed={"idle_timeout_seconds": timeout},
    )


def hostname_not_default(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    payload: AdminSettings = evidence["admin_settings"].payload
    defaults = {str(h).strip().lower() for h in params.get("default_hostnames", ())}
    host = payload.hostname.strip()
    failed = (not host) or host.lower() in defaults
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="low",
        diagnostic=(
            f"hostname {payload.hostname!r} is empty or a vendor default"
            if failed
            else f"hostname {payload.hostname!r} is not a vendor default"
        ),
        capability_refs=("admin_settings",),
        observed={"hostname": payload.hostname},
    )
