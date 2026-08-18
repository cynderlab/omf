"""Skeleton report body and local destokenized header (URL from RAM)."""

from __future__ import annotations

from collections import Counter
from datetime import datetime

from omf.baseline.loader import CheckDef, mitigation_for
from omf.redactor import Redactor
from omf.schema.evidence import CheckResult

_STATUS_ORDER = ("fail", "error", "skipped", "pass")
_CLOSING = (
    "This was a read-only assessment. Mitigations are examples. "
    "The auditor is responsible for any change."
)


def skeleton_body(
    findings: list[CheckResult], checks: tuple[CheckDef, ...], vendor: str
) -> str:
    by_id = {check.id: check for check in checks}
    counts = Counter(finding.status for finding in findings)
    counts_line = ", ".join(f"{counts.get(status, 0)} {status}" for status in _STATUS_ORDER)

    rows = [
        "| id | status | severity | title | diagnostic |",
        "| --- | --- | --- | --- | --- |",
    ]
    for finding in findings:
        check = by_id.get(finding.check_id)
        title = check.title if check else ""
        rows.append(
            f"| {finding.check_id} | {finding.status} | {finding.severity} "
            f"| {title} | {finding.diagnostic} |"
        )

    parts = ["Narrative skipped", counts_line, "", *rows, ""]
    for finding in findings:
        if finding.status == "pass":
            continue
        check = by_id.get(finding.check_id)
        title = check.title if check else ""
        parts.append(f"### {finding.check_id} — {title}")
        parts.append("")
        parts.append(finding.diagnostic)
        if check is not None:
            parts.append("")
            parts.append(mitigation_for(check, vendor))
        parts.append("")
    parts.append(_CLOSING)
    return "\n".join(parts) + "\n"


def wrap_report(
    body: str, *, vendor: str, url: str, started_at: datetime, version: str
) -> str:
    header = (
        "# OH MY FIREWALL audit report\n"
        "\n"
        f"- Vendor: {vendor}\n"
        f"- Target: {url}\n"
        f"- Date: {started_at.isoformat()}\n"
        f"- Tool: OMF {version}\n"
        "\n"
    )
    return header + body


def finalize_report(body: str, redactor: Redactor, **wrap_kwargs) -> str:
    return wrap_report(redactor.destokenize(body), **wrap_kwargs)
