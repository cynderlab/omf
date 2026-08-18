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


def syslog_encrypted(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    payload: LoggingConfig = evidence["logging"].payload
    failed = bool(payload.remote_targets) and not (payload.syslog_reliable and payload.syslog_enc_high)
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="medium",
        diagnostic=(
            "remote syslog is not reliable with high encryption"
            if failed
            else "no remote syslog or syslog encryption is configured"
        ),
        capability_refs=("logging",),
        observed={
            "remote_targets": list(payload.remote_targets),
            "syslog_reliable": payload.syslog_reliable,
            "syslog_enc_high": payload.syslog_enc_high,
        },
    )


def faz_encrypted(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    payload: LoggingConfig = evidence["logging"].payload
    failed = payload.faz_enabled is True and not (payload.faz_reliable and payload.faz_enc_high)
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="medium",
        diagnostic=(
            "FortiAnalyzer logging is not reliable with high encryption"
            if failed
            else "FortiAnalyzer disabled or encryption is configured"
        ),
        capability_refs=("logging",),
        observed={
            "faz_enabled": payload.faz_enabled,
            "faz_reliable": payload.faz_reliable,
            "faz_enc_high": payload.faz_enc_high,
        },
    )
