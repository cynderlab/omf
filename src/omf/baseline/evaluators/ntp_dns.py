from __future__ import annotations

from collections.abc import Mapping

from omf.schema.capabilities import DnsConfig, NtpConfig
from omf.schema.evidence import CheckResult, Evidence


def ntp_configured(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    payload: NtpConfig = evidence["ntp"].payload
    failed = (not payload.enabled) or (not payload.servers)
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="medium",
        diagnostic=(
            "NTP is disabled or has no servers" if failed else "NTP is enabled with servers"
        ),
        capability_refs=("ntp",),
        observed={"enabled": payload.enabled, "servers": list(payload.servers)},
    )


def dns_configured(
    evidence: Mapping[str, Evidence],
    params: dict,
    vendor: str,
) -> CheckResult:
    payload: DnsConfig = evidence["dns"].payload
    failed = not payload.servers
    return CheckResult(
        check_id="",
        status="fail" if failed else "pass",
        severity="low",
        diagnostic="DNS servers are empty" if failed else "DNS servers are configured",
        capability_refs=("dns",),
        observed={"servers": list(payload.servers)},
    )
