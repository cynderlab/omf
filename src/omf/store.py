from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from omf.schema.evidence import CheckResult, Evidence

_META_FORBIDDEN = frozenset({"url", "username", "password", "token", "api_key"})
_EVENT_FORBIDDEN = frozenset({"password", "token", "authorization", "api_key"})


class AuditStore:
    def __init__(self, audits_root: Path, vendor: str, started_at: datetime) -> None:
        self.path = audits_root / f"{started_at:%Y-%m-%dT%H%M%S}-{vendor}"

    def write_meta(self, data: dict) -> None:
        for key in data:
            if isinstance(key, str) and key.lower() in _META_FORBIDDEN:
                raise ValueError(f"meta must not contain secret key: {key}")
        self._write_json("meta.json", data)

    def write_raw(self, capability: str, data: object) -> None:
        self._write_json(Path("raw") / f"{capability}.json", data)

    def write_evidence(self, evidence: Evidence) -> None:
        self._write_json(
            Path("evidence") / f"{evidence.capability}.json",
            evidence.model_dump(mode="json"),
        )

    def write_findings(self, findings: list[CheckResult]) -> None:
        self._write_json(
            "findings.json",
            [f.model_dump(mode="json") for f in findings],
        )

    def write_redacted_findings(self, data: object) -> None:
        self._write_json(Path("redacted") / "findings.json", data)

    def write_redacted_evidence(self, capability: str, data: object) -> None:
        self._write_json(Path("redacted") / "evidence" / f"{capability}.json", data)

    def write_token_map(self, mapping: dict[str, str]) -> None:
        self._write_json("token_map.json", mapping)

    def append_event(self, event: dict) -> None:
        for key in event:
            if isinstance(key, str) and key.lower() in _EVENT_FORBIDDEN:
                raise ValueError(f"event must not contain secret key: {key}")
        path = self.path / "events.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, default=str) + "\n")

    def write_report(self, markdown: str) -> None:
        self._write_text("report.md", markdown)

    def write_report_redacted(self, markdown: str) -> None:
        self._write_text("report.redacted.md", markdown)

    def assert_no_secrets(self, forbidden: list[str]) -> None:
        if not self.path.is_dir():
            return
        for file_path in self.path.rglob("*"):
            if not file_path.is_file():
                continue
            text = file_path.read_text(encoding="utf-8", errors="replace")
            for needle in forbidden:
                if needle and needle in text:
                    raise AssertionError(
                        f"forbidden string {needle!r} found in {file_path.relative_to(self.path)}"
                    )

    def _write_json(self, rel: Path | str, data: object) -> None:
        path = self.path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, default=str) + "\n", encoding="utf-8")

    def _write_text(self, rel: Path | str, text: str) -> None:
        path = self.path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
