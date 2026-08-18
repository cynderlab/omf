from __future__ import annotations

from dataclasses import dataclass

from pydantic_ai import Tool

from omf.baseline.loader import CheckDef, mitigation_for


@dataclass
class AnalysisContext:
    findings: list[dict]
    evidence: dict[str, dict]
    checks: tuple[CheckDef, ...]
    vendor: str
    language: str
    submitted: list[str]


def list_findings(ctx: AnalysisContext) -> list[dict]:
    by_id = {check.id: check for check in ctx.checks}
    listed: list[dict] = []
    for finding in ctx.findings:
        check_id = finding.get("check_id")
        title = finding.get("title")
        if not title and isinstance(check_id, str) and check_id in by_id:
            title = by_id[check_id].title
        listed.append(
            {
                "check_id": check_id,
                "status": finding.get("status"),
                "severity": finding.get("severity"),
                "title": title or "",
            }
        )
    return listed


def get_finding(ctx: AnalysisContext, check_id: str) -> dict:
    for finding in ctx.findings:
        if finding.get("check_id") == check_id:
            return finding
    return {}


def get_redacted_evidence(ctx: AnalysisContext, capability: str) -> dict:
    return ctx.evidence.get(capability, {})


def get_mitigation(ctx: AnalysisContext, check_id: str) -> str:
    for check in ctx.checks:
        if check.id == check_id:
            return mitigation_for(check, ctx.vendor)
    return ""


def submit_report(ctx: AnalysisContext, markdown: str) -> str:
    ctx.submitted.append(markdown)
    return "ok"


def make_tools(ctx: AnalysisContext) -> list:
    def list_findings_bound() -> list[dict]:
        """Return check_id, status, severity, and title for every finding."""
        return list_findings(ctx)

    def get_finding_bound(check_id: str) -> dict:
        """Return one redacted finding including diagnostic and observed."""
        return get_finding(ctx, check_id)

    def get_redacted_evidence_bound(capability: str) -> dict:
        """Return one redacted capability payload."""
        return get_redacted_evidence(ctx, capability)

    def get_mitigation_bound(check_id: str) -> str:
        """Return catalog mitigation text for the check and this vendor."""
        return get_mitigation(ctx, check_id)

    def submit_report_bound(markdown: str) -> str:
        """Submit the full markdown report body with no title header."""
        return submit_report(ctx, markdown)

    return [
        Tool(list_findings_bound, name="list_findings"),
        Tool(get_finding_bound, name="get_finding"),
        Tool(get_redacted_evidence_bound, name="get_redacted_evidence"),
        Tool(get_mitigation_bound, name="get_mitigation"),
        Tool(submit_report_bound, name="submit_report"),
    ]
