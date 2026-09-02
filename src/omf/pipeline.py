"""Probe → collect → evaluate → redact → analyze or skeleton → destokenized report."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from omf import __version__
from omf.adapters.base import VendorAdapter
from omf.agent.llm import LlmNotConfigured, run_analysis
from omf.agent.report import finalize_report, skeleton_body
from omf.agent.tools import AnalysisContext
from omf.baseline.loader import checks_for
from omf.config import LlmSettings
from omf.redactor import Redactor
from omf.runner import Runner
from omf.session import Session
from omf.log import get_logger
from omf.store import AuditStore

_log = get_logger("omf.pipeline")

_LAST_CALL_KEYS = ("method", "path", "status", "ms")


def run_audit(
    session: Session,
    store: AuditStore,
    adapter: VendorAdapter,
    llm: LlmSettings,
    on_event: Callable[[dict], None],
    *,
    skip_probe: bool = False,
    skip_llm: bool = False,
) -> Path:
    """probe, run, redact, write redacted/ + token_map, write report.html.
    Never writes session.url to meta.json.
    skip_llm=True skips the model and writes the skeleton; collect/eval/redact still run.
    On LlmNotConfigured or analysis failure after retry: skeleton_body.
    Always session.clear_secrets() in a finally block.
    Returns path to report.html.
    """
    try:
        started_at = _started_at(store)
        # Evaluation-only: catalog/skeleton are English; language is LLM narrative only.
        report_language = "en" if skip_llm else session.report_language
        store.write_meta({
            "vendor": session.vendor,
            "started_at": started_at.isoformat(),
            "report_language": report_language,
            "tool_version": __version__,
            "tls_verify": session.verify_tls,
        })
        if not skip_probe:
            _log.info("probe")
            _emit(store, on_event, {"phase": "probe"})
            adapter.probe()
            _forward_last_call(adapter, store, on_event, {"phase": "probe"})

        checks = checks_for(session.vendor)
        result = Runner(
            adapter,
            checks,
            store,
            lambda event: on_event(_enrich_last_call(adapter, event)),
        ).run()

        _log.info("redact findings=%s", len(result.findings))
        _emit(store, on_event, {"phase": "redact"})
        redactor = Redactor()
        redacted_evidence: dict[str, dict] = {}
        for capability, evidence in result.collected.items():
            redacted = redactor.redact_obj(evidence)
            if isinstance(redacted, dict):
                redacted_evidence[capability] = redacted
        redacted_findings = [redactor.redact_obj(finding) for finding in result.findings]
        redacted_evidence = {
            capability: redactor.apply_known(item)
            for capability, item in redacted_evidence.items()
        }
        redacted_findings = [redactor.apply_known(item) for item in redacted_findings]
        store.write_redacted_findings(redacted_findings)
        for capability, redacted in redacted_evidence.items():
            store.write_redacted_evidence(capability, redacted)
        store.write_token_map(redactor.token_map())

        body = _analysis_body(
            session=session,
            store=store,
            llm=llm,
            on_event=on_event,
            checks=checks,
            findings=result.findings,
            redacted_findings=redacted_findings,
            redacted_evidence=redacted_evidence,
            skip_llm=skip_llm,
            report_language=report_language,
        )
        report = finalize_report(
            body,
            redactor,
            findings=result.findings,
            vendor=session.vendor,
            url=session.url,
            started_at=started_at,
            version=__version__,
            language=report_language,
        )
        store.write_report(report)
        _log.info("report written")
        _emit(store, on_event, {"phase": "report"})
        return store.path / "report.html"
    finally:
        session.clear_secrets()
        adapter.close()


def _analysis_body(
    *,
    session: Session,
    store: AuditStore,
    llm: LlmSettings,
    on_event: Callable[[dict], None],
    checks,
    findings,
    redacted_findings,
    redacted_evidence: dict[str, dict],
    report_language: str,
    skip_llm: bool = False,
) -> str:
    model = llm.model or ""
    style = llm.api_style
    if skip_llm or not llm.is_configured():
        detail = "evaluation only" if skip_llm else "LLM not configured"
        _emit(store, on_event, {
            "phase": "llm",
            "status": "skipped",
            "detail": detail,
        })
        return skeleton_body(
            findings, checks, session.vendor, language=report_language
        )
    ctx = AnalysisContext(
        findings=[item for item in redacted_findings if isinstance(item, dict)],
        evidence=redacted_evidence,
        checks=checks,
        vendor=session.vendor,
        language=report_language,
        submitted=[],
    )
    try:
        _log.info("llm start model=%s style=%s", model, style)
        _emit(store, on_event, {
            "phase": "llm",
            "status": "start",
            "model": model,
            "style": style,
        })
        body = run_analysis(
            ctx,
            llm,
            on_event=lambda event: _emit(store, on_event, event),
        )
        store.write_report_redacted(body)
        _write_transcript(store, ctx)
        _emit(store, on_event, {"phase": "llm", "status": "done", "model": model})
        return body
    except (LlmNotConfigured, Exception) as exc:
        _log.warning("llm fallback: %s", exc)
        _write_transcript(store, ctx)
        _emit(store, on_event, {
            "phase": "llm",
            "status": "fallback",
            "model": model,
            "detail": _safe_exc_detail(exc, llm.api_key),
        })
        return skeleton_body(
            findings, checks, session.vendor, language=report_language
        )


def _write_transcript(store: AuditStore, ctx: AnalysisContext) -> None:
    if ctx.transcript:
        store.write_llm_transcript(ctx.transcript)


def _safe_exc_detail(exc: BaseException, secret: str | None) -> str:
    text = f"{type(exc).__name__}: {exc}".strip()
    if secret:
        text = text.replace(secret, "[STRIPPED]")
    return text.splitlines()[0][:240]


def _started_at(store: AuditStore) -> datetime:
    stamp = store.path.name.rsplit("-", 1)[0]
    try:
        return datetime.strptime(stamp, "%Y-%m-%dT%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _emit(store: AuditStore, on_event: Callable[[dict], None], event: dict) -> None:
    store.append_event(event)
    on_event(event)


def _enrich_last_call(adapter: VendorAdapter, event: dict) -> dict:
    last = getattr(adapter, "last_call", None)
    if not isinstance(last, dict):
        return event
    merged = dict(event)
    for key in _LAST_CALL_KEYS:
        if merged.get(key) in (None, "") and last.get(key) is not None:
            merged[key] = last[key]
    merged.setdefault("method", "GET")
    return merged


def _forward_last_call(
    adapter: VendorAdapter,
    store: AuditStore,
    on_event: Callable[[dict], None],
    event: dict,
) -> None:
    last = getattr(adapter, "last_call", None)
    if not isinstance(last, dict):
        return
    _emit(store, on_event, _enrich_last_call(adapter, event))


__all__ = [
    "run_audit",
]
