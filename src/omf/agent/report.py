"""Skeleton report body and local destokenized header (URL from RAM)."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from omf.agent.html import render_html_report
from omf.baseline.loader import CheckDef
from omf.redactor import Redactor
from omf.schema.evidence import CheckResult, Status

_STATUS_ORDER = ("fail", "error", "skipped", "pass")
_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
_COPY = {
    "ca": {
        "title": "Informe de línia base de seguretat",
        "exec": "Resum executiu",
        "vulns": "Vulnerabilitats",
        "pass": "Correctes",
        "fail": "Fallades",
        "error": "Errors",
        "skipped": "Omeses",
        "checks": "comprovacions",
        "status": "Estat",
        "severity": "Severitat",
        "author": "Autor",
        "date": "Data",
        "target": "Objectiu",
        "tool": "Eina",
        "evidence": "Evidència",
        "mitigation": "Exemple de mitigació",
        "description": "Descripció",
        "id": "id",
        "title_col": "títol",
    },
    "es": {
        "title": "Informe de línea base de seguridad",
        "exec": "Resumen ejecutivo",
        "vulns": "Vulnerabilidades",
        "pass": "Correctos",
        "fail": "Fallos",
        "error": "Errores",
        "skipped": "Omitidos",
        "checks": "comprobaciones",
        "status": "Estado",
        "severity": "Severidad",
        "author": "Autor",
        "date": "Fecha",
        "target": "Objetivo",
        "tool": "Herramienta",
        "evidence": "Evidencia",
        "mitigation": "Ejemplo de mitigación",
        "description": "Descripción",
        "id": "id",
        "title_col": "título",
    },
    "en": {
        "title": "Security baseline report",
        "exec": "Executive summary",
        "vulns": "Vulnerabilities",
        "pass": "Pass",
        "fail": "Fail",
        "error": "Errors",
        "skipped": "Skipped",
        "checks": "checks",
        "status": "Status",
        "severity": "Severity",
        "author": "Author",
        "date": "Date",
        "target": "Target",
        "tool": "Tool",
        "evidence": "Evidence",
        "mitigation": "Example mitigation",
        "description": "Description",
        "id": "ID",
        "title_col": "Title",
    },
}


def copy_for(language: str) -> dict[str, str]:
    return _COPY.get(language, _COPY["en"])


class VulnNarrative(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    check_id: str
    title: str
    description: str


class ReportNarrative(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    executive_summary: str
    vulnerabilities: list[VulnNarrative]


def _to_result(finding: CheckResult | dict) -> CheckResult:
    if isinstance(finding, CheckResult):
        return finding
    status_raw = finding.get("status")
    status: Status = status_raw if status_raw in _STATUS_ORDER else "error"
    severity_raw = finding.get("severity")
    severity = severity_raw if severity_raw in _SEV_ORDER else "info"
    refs = finding.get("capability_refs") or ()
    return CheckResult(
        check_id=str(finding.get("check_id") or ""),
        status=status,
        severity=severity,
        diagnostic=str(finding.get("diagnostic") or ""),
        capability_refs=tuple(refs),
        observed=dict(finding.get("observed") or {}),
    )


def _fails(findings: list[CheckResult]) -> list[CheckResult]:
    fails = [finding for finding in findings if finding.status == "fail"]
    return sorted(
        fails,
        key=lambda finding: (_SEV_ORDER.get(finding.severity, 9), finding.check_id),
    )


def _evidence_cell(value: object) -> str:
    if value is None:
        return "—"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value) if value else "—"
    return str(value)


def _list_of_dicts(value: object) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(item, dict) for item in value)


def _list_of_scalars(value: object) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(not isinstance(item, (dict, list)) for item in value)
    )


def _markdown_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    head = "| " + " | ".join(headers) + " |"
    sep = "| " + " | ".join("---" for _ in headers) + " |"
    body = ["| " + " | ".join(row) + " |" for row in rows]
    return [head, sep, *body]


def _dict_rows_table(rows: list[dict]) -> list[str]:
    keys: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row:
            name = str(key)
            if name not in seen:
                seen.add(name)
                keys.append(name)
    return _markdown_table(
        keys,
        [[_evidence_cell(row.get(key)) for key in keys] for row in rows],
    )


def _format_evidence(observed: dict, copy: dict[str, str]) -> list[str]:
    label = copy["evidence"]
    if not observed:
        return [f"- **{label}:** —"]
    out = [f"- **{label}:**", ""]
    scalars: list[tuple[str, object]] = []

    def flush_scalars() -> None:
        if not scalars:
            return
        out.extend(
            _markdown_table(
                ["field", "value"],
                [[key, _evidence_cell(value)] for key, value in scalars],
            )
        )
        out.append("")
        scalars.clear()

    for key, value in observed.items():
        if _list_of_dicts(value):
            flush_scalars()
            out.extend(_dict_rows_table(value))
            out.append("")
        elif _list_of_scalars(value) and len(value) > 1:
            flush_scalars()
            out.extend(_markdown_table([key], [[_evidence_cell(item)] for item in value]))
            out.append("")
        else:
            scalars.append((key, value))
    flush_scalars()
    while out and out[-1] == "":
        out.pop()
    return out


def _format_mitigation(text: str, copy: dict[str, str]) -> list[str]:
    lines = text.strip().splitlines()
    if not lines:
        return []
    prose = lines[0].strip()
    rest = [line.rstrip() for line in lines[1:] if line.strip()]
    out = [f"- **{copy['mitigation']}:** {prose}"]
    if rest:
        out.extend(["", "```", *rest, "```"])
    return out


def _fail_table(
    fails: list[CheckResult],
    by_id: dict[str, CheckDef],
    copy: dict[str, str],
    titles: dict[str, str] | None = None,
) -> list[str]:
    rows = [
        f"| {copy['id']} | {copy['severity']} | {copy['title_col']} |",
        "| --- | --- | --- |",
    ]
    overlay = titles or {}
    for finding in fails:
        check = by_id.get(finding.check_id)
        title = overlay.get(finding.check_id) or (check.title if check else "")
        rows.append(f"| {finding.check_id} | {finding.severity} | {title} |")
    return rows


def _fail_sections(
    fails: list[CheckResult],
    by_id: dict[str, CheckDef],
    copy: dict[str, str],
    *,
    titles: dict[str, str] | None = None,
    descriptions: dict[str, str] | None = None,
) -> list[str]:
    title_overlay = titles or {}
    desc_overlay = descriptions or {}
    parts: list[str] = []
    for finding in fails:
        check = by_id.get(finding.check_id)
        title = title_overlay.get(finding.check_id) or (check.title if check else "")
        desc = desc_overlay.get(finding.check_id) or (
            check.description.strip()
            if check is not None and check.description.strip()
            else finding.diagnostic
        )
        parts.append(f"### {finding.check_id} — {title}")
        parts.append("")
        parts.append(f"- **{copy['severity']}:** {finding.severity}")
        parts.append(f"- **{copy['description']}:** {desc}")
        parts.extend(_format_evidence(finding.observed, copy))
        if check is not None:
            parts.extend(_format_mitigation(check.mitigation, copy))
        parts.append("")
    return parts


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
        "",
        counts_line,
        "",
        *_fail_table(fails, by_id, copy),
        "",
        f"## {copy['vulns']}",
        "",
        *_fail_sections(fails, by_id, copy),
    ]
    return "\n".join(parts) + "\n"


def _vuln_title(
    finding: CheckResult,
    check: CheckDef | None,
    narr: VulnNarrative | None,
) -> str:
    if narr is not None and narr.title.strip():
        return narr.title.strip()
    return check.title if check else ""


def _vuln_description(
    finding: CheckResult,
    check: CheckDef | None,
    narr: VulnNarrative | None,
) -> str:
    if narr is not None and narr.description.strip():
        return narr.description.strip()
    if check is not None and check.description.strip():
        return check.description.strip()
    return finding.diagnostic


def narrative_body(
    narrative: ReportNarrative,
    findings: Sequence[CheckResult] | Sequence[dict],
    checks: tuple[CheckDef, ...],
    vendor: str,
    *,
    language: str,
) -> str:
    copy = copy_for(language)
    by_id = {check.id: check for check in checks}
    results = [_to_result(item) for item in findings]
    fails = _fails(results)
    by_narr = {item.check_id: item for item in narrative.vulnerabilities}
    titles = {
        finding.check_id: _vuln_title(finding, by_id.get(finding.check_id), by_narr.get(finding.check_id))
        for finding in fails
    }
    descriptions = {
        finding.check_id: _vuln_description(
            finding, by_id.get(finding.check_id), by_narr.get(finding.check_id)
        )
        for finding in fails
    }
    parts = [
        f"## {copy['exec']}",
        "",
        narrative.executive_summary.strip(),
        "",
        *_fail_table(fails, by_id, copy, titles),
        "",
        f"## {copy['vulns']}",
        "",
        *_fail_sections(fails, by_id, copy, titles=titles, descriptions=descriptions),
    ]
    return "\n".join(parts) + "\n"


def finalize_report(
    body: str,
    redactor: Redactor,
    *,
    findings: Sequence[CheckResult],
    vendor: str,
    url: str,
    started_at: datetime,
    version: str,
    language: str,
) -> str:
    return render_html_report(
        redactor.destokenize(body),
        findings=findings,
        vendor=vendor,
        url=url,
        started_at=started_at,
        version=version,
        language=language,
    )
