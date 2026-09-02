"""Redacted-only findings helpers. The analysis agent has no function tools."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from pydantic_ai import Tool

from omf.baseline.loader import CheckDef, mitigation_for

_EVIDENCE_LIST_CAP = 12
_STATUS_KEYS = ("fail", "pass", "error", "skipped")
_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


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
    by_id = {check.id: check for check in ctx.checks}
    for finding in ctx.findings:
        if finding.get("check_id") == check_id:
            capped = _cap_for_model(finding)
            if not isinstance(capped, dict):
                return {}
            check = by_id.get(check_id)
            if check is not None and check.description.strip():
                capped["description"] = check.description
            return capped
    return {}


def get_redacted_evidence(ctx: AnalysisContext, capability: str) -> dict:
    raw = ctx.evidence.get(capability, {})
    capped = _cap_for_model(raw)
    return capped if isinstance(capped, dict) else {}


def _cap_for_model(value: object) -> object:
    """Trim large lists so the model is not fed a full policy dump."""
    if isinstance(value, dict):
        out: dict = {}
        extras: dict = {}
        for key, item in value.items():
            if isinstance(item, list) and len(item) > _EVIDENCE_LIST_CAP:
                out[key] = [_cap_for_model(el) for el in item[:_EVIDENCE_LIST_CAP]]
                extras[f"{key}_total"] = len(item)
                extras[f"{key}_truncated"] = True
            else:
                out[key] = _cap_for_model(item)
        out.update(extras)
        return out
    if isinstance(value, list):
        capped = value[:_EVIDENCE_LIST_CAP] if len(value) > _EVIDENCE_LIST_CAP else value
        return [_cap_for_model(el) for el in capped]
    return value


def get_mitigation(ctx: AnalysisContext, check_id: str) -> str:
    for check in ctx.checks:
        if check.id == check_id:
            return mitigation_for(check, ctx.vendor)
    return ""


def submit_report(ctx: AnalysisContext, markdown: str) -> str:
    ctx.submitted.append(markdown)
    return "ok"


def status_counts(ctx: AnalysisContext) -> dict[str, int]:
    counts = {key: 0 for key in _STATUS_KEYS}
    for finding in ctx.findings:
        status = finding.get("status")
        if status in counts:
            counts[status] += 1
    return counts


def fail_pack(ctx: AnalysisContext) -> list[dict]:
    fails = [finding for finding in ctx.findings if finding.get("status") == "fail"]
    fails.sort(
        key=lambda finding: (
            _SEV_ORDER.get(str(finding.get("severity")), 9),
            str(finding.get("check_id")),
        )
    )
    pack: list[dict] = []
    for finding in fails:
        check_id = finding.get("check_id")
        if not isinstance(check_id, str):
            continue
        row = get_finding(ctx, check_id)
        if not row:
            continue
        row["mitigation"] = get_mitigation(ctx, check_id)
        pack.append(row)
    return pack


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
        """Return one redacted finding including diagnostic, observed, and catalog description."""
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
