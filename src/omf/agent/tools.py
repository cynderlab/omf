"""Redacted-only tools the analysis agent may call."""

from __future__ import annotations

from collections.abc import Callable
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
    transcript: str = ""


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


def _notify_tool(
    on_tool: Callable[[dict], None] | None,
    name: str,
    **fields: object,
) -> None:
    if on_tool is None:
        return
    event: dict = {"tool": name}
    for key in ("check_id", "capability"):
        value = fields.get(key)
        if isinstance(value, str) and value:
            event[key] = value
    on_tool(event)


def make_tools(
    ctx: AnalysisContext,
    on_tool: Callable[[dict], None] | None = None,
) -> list:
    def list_findings_bound() -> list[dict]:
        """Return check_id, status, severity, and title for every finding."""
        _notify_tool(on_tool, "list_findings")
        return list_findings(ctx)

    def get_finding_bound(check_id: str) -> dict:
        """Return one redacted finding including diagnostic and observed."""
        _notify_tool(on_tool, "get_finding", check_id=check_id)
        return get_finding(ctx, check_id)

    def get_redacted_evidence_bound(capability: str) -> dict:
        """Return one redacted capability payload."""
        _notify_tool(on_tool, "get_redacted_evidence", capability=capability)
        return get_redacted_evidence(ctx, capability)

    def get_mitigation_bound(check_id: str) -> str:
        """Return catalog mitigation text for the check and this vendor."""
        _notify_tool(on_tool, "get_mitigation", check_id=check_id)
        return get_mitigation(ctx, check_id)

    def submit_report_bound(markdown: str) -> str:
        """Submit the markdown body: executive summary, fail table, vulnerabilities."""
        _notify_tool(on_tool, "submit_report")
        return submit_report(ctx, markdown)

    return [
        Tool(list_findings_bound, name="list_findings"),
        Tool(get_finding_bound, name="get_finding"),
        Tool(get_redacted_evidence_bound, name="get_redacted_evidence"),
        Tool(get_mitigation_bound, name="get_mitigation"),
        Tool(submit_report_bound, name="submit_report"),
    ]
