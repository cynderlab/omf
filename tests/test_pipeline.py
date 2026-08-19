from datetime import datetime, timezone
from pathlib import Path
from omf.pipeline import run_audit
from omf.session import Session
from omf.store import AuditStore
from omf.config import LlmSettings
from omf.schema.capabilities import (
    User, UserList, AdminSettings, Service, ServiceList, NtpConfig, DnsConfig,
    LoggingConfig, SnmpConfig, Policy, PolicyList, SystemInfo,
)
from omf.schema.evidence import Evidence
from omf.adapters.base import CollectError


class FullFake:
    vendor = "mikrotik"

    def probe(self): return None
    def close(self): return None
    def implemented(self):
        return frozenset({
            "users", "admin_settings", "services", "ntp", "dns",
            "logging", "snmp", "firewall_filter", "system_info",
        })

    def collect(self, capability: str):
        now = datetime.now(timezone.utc)
        payloads = {
            "users": UserList(users=(User(name="admin", enabled=True, groups=("full",)),)),
            "admin_settings": AdminSettings(hostname="MikroTik", idle_timeout_seconds=None),
            "services": ServiceList(services=(Service(name="telnet", enabled=True, port=23, listen="all"),)),
            "ntp": NtpConfig(enabled=False, servers=()),
            "dns": DnsConfig(servers=("1.1.1.1",)),
            "logging": LoggingConfig(local_enabled=True, remote_targets=()),
            "snmp": SnmpConfig(enabled=False, communities=()),
            "firewall_filter": PolicyList(policies=(
                Policy(id="1", enabled=True, action="accept", src=("any",), dst=("any",), service=("any",)),
            )),
            "system_info": SystemInfo(firmware="7.16.1", model="RB"),
        }
        payload = payloads[capability]
        return Evidence(capability=capability, vendor="mikrotik", collected_at=now, payload=payload), {"cap": capability}


def test_pipeline_skeleton_report_and_no_secrets_on_disk(tmp_path: Path):
    session = Session("mikrotik", "https://192.0.2.8", "admin", "s3cret", "tokentok", True, "ca")
    store = AuditStore(tmp_path, "mikrotik", datetime.now(timezone.utc))
    llm = LlmSettings(None, None, None, "openai")
    events = []
    report = run_audit(session, store, FullFake(), llm, events.append)
    text = report.read_text()
    assert "Narrative skipped" in text
    assert "Informe d'auditoria de tallafoc" in text
    assert "Author: OH MY FIREWALL" in text
    assert "## Vulnerabilitats" in text
    assert "https://192.0.2.8" in text
    assert "FW-ADM-001" in text
    disk = "\n".join(p.read_text() for p in store.path.rglob("*") if p.is_file() and p.name != "report.md")
    assert "s3cret" not in disk
    assert "tokentok" not in disk
    meta = (store.path / "meta.json").read_text()
    assert "192.0.2.8" not in meta
    assert session.password == ""
    assert any(e.get("phase") == "collect" for e in events)
    findings = (store.path / "findings.json").read_text()
    assert '"fail"' in findings
    assert (store.path / "redacted" / "findings.json").is_file()
    assert (store.path / "token_map.json").is_file()
    assert not (store.path / "redacted" / "transcript.md").is_file()


def test_pipeline_writes_llm_transcript(tmp_path: Path, monkeypatch):
    def fake_run(ctx, settings, on_event=None):
        ctx.transcript = (
            "--- LLM transcript (what the model saw; already redacted) ---\n"
            "Write the firewall audit report using only the tools.\n"
        )
        ctx.submitted.append("## Resum executiu\n")
        return ctx.submitted[-1]

    monkeypatch.setattr("omf.pipeline.run_analysis", fake_run)
    session = Session("mikrotik", "https://192.0.2.8", "admin", "s3cret", "tokentok", True, "ca")
    store = AuditStore(tmp_path, "mikrotik", datetime.now(timezone.utc))
    llm = LlmSettings("http://llm.example", "sk-live-secret-key", "model", "openai")
    run_audit(session, store, FullFake(), llm, lambda event: None)
    path = store.path / "redacted" / "transcript.md"
    text = path.read_text()
    assert "Write the firewall audit report using only the tools." in text
    assert "https://192.0.2.8" not in text
    assert "s3cret" not in text
    assert "tokentok" not in text
    assert "sk-live-secret-key" not in text


def test_pipeline_keeps_transcript_on_llm_fallback(tmp_path: Path, monkeypatch):
    def fake_run(ctx, settings, on_event=None):
        ctx.transcript = "--- LLM transcript ---\nUserPromptPart ask\n"
        raise RuntimeError("model down")

    monkeypatch.setattr("omf.pipeline.run_analysis", fake_run)
    session = Session("mikrotik", "https://192.0.2.8", "admin", "s3cret", "", True, "ca")
    store = AuditStore(tmp_path, "mikrotik", datetime.now(timezone.utc))
    llm = LlmSettings("http://llm.example", "sk-test", "model", "openai")
    report = run_audit(session, store, FullFake(), llm, lambda event: None)
    assert "Narrative skipped" in report.read_text()
    assert "UserPromptPart ask" in (store.path / "redacted" / "transcript.md").read_text()


def test_safe_exc_detail_strips_api_key():
    from omf.pipeline import _safe_exc_detail

    exc = RuntimeError("provider rejected key sk-secret-value")
    detail = _safe_exc_detail(exc, "sk-secret-value")
    assert "sk-secret-value" not in detail
    assert "RuntimeError" in detail
    assert "[STRIPPED]" in detail
