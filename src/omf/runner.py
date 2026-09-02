"""Collect each needed capability once, then evaluate the catalog. No LLM."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from omf.adapters.base import CollectError, VendorAdapter
from omf.baseline.evaluators import evaluate
from omf.baseline.loader import CheckDef
from omf.schema.evidence import CheckResult, Evidence
from omf.log import get_logger
from omf.store import AuditStore, _EVENT_FORBIDDEN

_log = get_logger("omf.runner")


@dataclass
class RunnerResult:
    findings: list[CheckResult]
    collected: dict[str, Evidence]


class Runner:
    def __init__(
        self,
        adapter: VendorAdapter,
        checks: tuple[CheckDef, ...],
        store: AuditStore,
        on_event: Callable[[dict], None] | None = None,
    ) -> None:
        self.adapter = adapter
        self.checks = checks
        self.store = store
        self.on_event = on_event

    def run(self) -> RunnerResult:
        implemented = self.adapter.implemented()
        needed = list(dict.fromkeys(need for check in self.checks for need in check.needs))
        collected: dict[str, Evidence] = {}
        failed: dict[str, CollectError] = {}

        for capability in needed:
            if capability not in implemented:
                continue
            _log.info("collect %s", capability)
            try:
                evidence, raw = self.adapter.collect(capability)
            except CollectError as exc:
                failed[capability] = exc
                _log.warning("collect %s failed: %s", capability, exc.message)
                self._emit({
                    "phase": "collect",
                    "capability": capability,
                    "path": exc.path,
                    "status": exc.status,
                    "error": exc.message,
                })
                continue
            collected[capability] = evidence
            self.store.write_raw(capability, raw)
            self.store.write_evidence(evidence)
            self._emit({"phase": "collect", "capability": capability})

        findings: list[CheckResult] = []
        for check in self.checks:
            missing_impl = [
                need for need in check.needs
                if need not in implemented and need not in collected
            ]
            if missing_impl:
                result = CheckResult(
                    check_id=check.id,
                    status="skipped",
                    severity=check.severity,
                    diagnostic="capability not implemented",
                    capability_refs=tuple(check.needs),
                    observed={},
                )
            elif any(need not in collected for need in check.needs):
                first = next(need for need in check.needs if need in failed)
                exc = failed[first]
                result = CheckResult(
                    check_id=check.id,
                    status="error",
                    severity=check.severity,
                    diagnostic=f"collect failed: {exc.message}",
                    capability_refs=tuple(check.needs),
                    observed={},
                )
            else:
                result = evaluate(check, collected, self.adapter.vendor)
            findings.append(result)
            _log.info("eval %s -> %s", check.id, result.status)
            self._emit(
                {
                    "phase": "eval",
                    "check_id": check.id,
                    "status": result.status,
                    "severity": result.severity,
                },
                extra={"diagnostic": result.diagnostic},
            )

        self.store.write_findings(findings)
        return RunnerResult(findings=findings, collected=collected)

    def _emit(self, event: dict, extra: dict | None = None) -> None:
        safe = {
            key: value
            for key, value in event.items()
            if not (isinstance(key, str) and key.lower() in _EVENT_FORBIDDEN)
        }
        self.store.append_event(safe)
        if self.on_event is not None:
            payload = dict(safe)
            if extra:
                payload.update(extra)
            self.on_event(payload)


__all__ = [
    "Runner",
    "RunnerResult",
]
