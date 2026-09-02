"""Redacted-only findings helpers. The analysis agent has no function tools."""

from __future__ import annotations

from dataclasses import dataclass

from omf.baseline.loader import CheckDef

_EVIDENCE_LIST_CAP = 12
_STATUS_KEYS = ("fail", "pass", "error", "skipped")
_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass
class AnalysisContext:
    findings: list[dict]
    checks: tuple[CheckDef, ...]
    vendor: str
    language: str
    transcript: str = ""


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
            return check.mitigation
    return ""


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
