from __future__ import annotations

from collections.abc import Mapping

from omf.schema.capabilities import LoggingConfig
from omf.schema.evidence import CheckResult, Evidence


def local_logging_enabled(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    payload: LoggingConfig = evidence["logging"].payload
    failed = not payload.local_enabled
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="medium",
        diagnostic="local logging is disabled" if failed else "local logging is enabled",
        capability_refs=("logging",),
        observed={"local_enabled": payload.local_enabled},
    )


def remote_syslog_configured(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    payload: LoggingConfig = evidence["logging"].payload
    failed = not payload.remote_targets
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="medium",
        diagnostic=(
            "no remote syslog targets" if failed else "remote syslog targets are configured"
        ),
        capability_refs=("logging",),
        observed={"remote_targets": list(payload.remote_targets)},
    )
