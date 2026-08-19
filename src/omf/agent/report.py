"""Skeleton report body and local destokenized header (URL from RAM)."""

from __future__ import annotations

from collections import Counter
from datetime import datetime

from omf.baseline.loader import CheckDef, mitigation_for
from omf.redactor import Redactor
from omf.schema.evidence import CheckResult

_STATUS_ORDER = ("fail", "error", "skipped", "pass")
_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
_CLOSING = (
    "This was a read-only assessment. Mitigations are examples. "
    "The auditor is responsible for any change."
)
_COPY = {
    "ca": {
        "title": "Informe d'auditoria de tallafoc",
        "exec": "Resum executiu",
        "vulns": "Vulnerabilitats",
    },
    "es": {
        "title": "Informe de auditoría de firewall",
        "exec": "Resumen ejecutivo",
        "vulns": "Vulnerabilidades",
    },
    "en": {
        "title": "Firewall audit report",
        "exec": "Executive summary",
        "vulns": "Vulnerabilities",
    },
}


def copy_for(language: str) -> dict[str, str]:
    return _COPY.get(language, _COPY["en"])


def _fails(findings: list[CheckResult]) -> list[CheckResult]:
    fails = [finding for finding in findings if finding.status == "fail"]
    return sorted(
        fails,
        key=lambda finding: (_SEV_ORDER.get(finding.severity, 9), finding.check_id),
    )


def _format_evidence(observed: dict) -> str:
    if not observed:
        return "—"
    return ", ".join(f"{key}={value}" for key, value in observed.items())


def _fail_table(fails: list[CheckResult], by_id: dict[str, CheckDef]) -> list[str]:
    rows = [
        "| id | severity | title |",
        "| --- | --- | --- |",
    ]
    for finding in fails:
        check = by_id.get(finding.check_id)
        title = check.title if check else ""
        rows.append(f"| {finding.check_id} | {finding.severity} | {title} |")
    return rows


def skeleton_body(
    findings: list[CheckResult],
    checks: tuple[CheckDef, ...],
    vendor: str,
    *,
    language: str,
) -> str:
    copy = copy_for(language)
    by_id = {check.id: check for check in checks}
    fails = _fails(findings)
    counts = Counter(finding.status for finding in findings)
    counts_line = ", ".join(f"{counts.get(status, 0)} {status}" for status in _STATUS_ORDER)

    parts = [
        f"## {copy['exec']}",
        "",
        "Narrative skipped",
        counts_line,
        "",
        *_fail_table(fails, by_id),
        "",
        f"## {copy['vulns']}",
        "",
    ]
    for finding in fails:
        check = by_id.get(finding.check_id)
        title = check.title if check else ""
        parts.append(f"### {finding.check_id} — {title}")
        parts.append("")
        parts.append(f"**Severity:** {finding.severity}")
        parts.append(f"**Description:** {finding.diagnostic}")
        parts.append(f"**Evidence:** {_format_evidence(finding.observed)}")
        if check is not None:
            parts.append(f"**Mitigation:** {mitigation_for(check, vendor)}")
        parts.append("")
    parts.append(_CLOSING)
    return "\n".join(parts) + "\n"


def wrap_report(
    body: str,
    *,
    vendor: str,
    url: str,
    started_at: datetime,
    version: str,
    language: str,
) -> str:
    copy = copy_for(language)
    header = (
        f"# {copy['title']}\n"
        "\n"
        "- Author: OH MY FIREWALL\n"
        f"- Date: {started_at.date().isoformat()}\n"
        f"- Firewall: {vendor} · {url}\n"
        f"- Tool: OMF {version}\n"
        "\n"
    )
    return header + body


def finalize_report(body: str, redactor: Redactor, **wrap_kwargs) -> str:
    return wrap_report(redactor.destokenize(body), **wrap_kwargs)
