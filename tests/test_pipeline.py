from datetime import datetime, timezone
from pathlib import Path
import json
import logging
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


class IdentityFake(FullFake):
    def collect(self, capability: str):
        evidence, raw = super().collect(capability)
        now = evidence.collected_at
        if capability == "users":
            payload = UserList(users=(
                User(name="admin", enabled=True, groups=("full",)),
                User(name="reader", enabled=True, groups=("read",)),
            ))
            return Evidence(capability=capability, vendor="mikrotik", collected_at=now, payload=payload), raw
        if capability == "admin_settings":
            payload = AdminSettings(hostname="home-fw", idle_timeout_seconds=None)
            return Evidence(capability=capability, vendor="mikrotik", collected_at=now, payload=payload), raw
        return evidence, raw


def test_pipeline_skeleton_report_and_no_secrets_on_disk(tmp_path: Path):
    session = Session("mikrotik", "https://192.0.2.8", "admin", "s3cret", "tokentok", True, "ca")
    store = AuditStore(tmp_path, "mikrotik", datetime.now(timezone.utc))
    llm = LlmSettings(None, None, None, "openai")
    events = []
    report = run_audit(session, store, FullFake(), llm, events.append)
    assert report == store.path / "report.html"
    text = report.read_text()
    assert text.strip().startswith("<!DOCTYPE html>")
    assert "Narrative skipped" in text
    assert "Informe d" in text
    assert "Autor" in text
    assert "OH MY FORTRESS" not in text
    assert "This was a read-only assessment" in text
    assert text.index("Autor") < text.index("This was a read-only assessment")
    assert "Vulnerabilitats" in text
    assert "<h2>" in text
    assert "## Vulnerabilitats" not in text
    assert "https://192.0.2.8" in text
    assert text.count("https://192.0.2.8") == 1
    assert "FW-ADM-001" in text
    assert "class=\"kpis\"" in text
    assert not (store.path / "report.md").exists()
    disk = "\n".join(
        p.read_text()
        for p in store.path.rglob("*")
        if p.is_file() and p.name != "report.html"
    )
    assert "s3cret" not in disk
    assert "tokentok" not in disk
    assert "192.0.2.8" not in disk
    meta = (store.path / "meta.json").read_text()
    assert "192.0.2.8" not in meta
    assert session.password == ""
    assert any(e.get("phase") == "collect" for e in events)
    findings = (store.path / "findings.json").read_text()
    assert '"fail"' in findings
    assert (store.path / "redacted" / "findings.json").is_file()
    assert (store.path / "token_map.json").is_file()
    assert not (store.path / "redacted" / "transcript.md").is_file()
    store.assert_no_secrets(["s3cret", "tokentok"])


def test_pipeline_redacted_findings_hide_hostname_and_username(tmp_path: Path):
    session = Session("mikrotik", "https://192.0.2.8", "admin", "s3cret", "", True, "en")
    store = AuditStore(tmp_path, "mikrotik", datetime.now(timezone.utc))
    run_audit(session, store, IdentityFake(), LlmSettings(None, None, None, "openai"), lambda event: None)
    red = (store.path / "redacted" / "findings.json").read_text()
    assert "home-fw" not in red
    assert "reader" not in red
    assert "[HOST_" in red
    assert "[USER_" in red
    clear = (store.path / "findings.json").read_text()
    assert "home-fw" in clear
    assert "reader" in clear
    events_text = (store.path / "events.jsonl").read_text()
    assert "home-fw" not in events_text
    assert "reader" not in events_text
    for line in events_text.splitlines():
        row = json.loads(line)
        if row.get("phase") == "eval":
            assert "diagnostic" not in row


def test_pipeline_writes_llm_transcript(tmp_path: Path, monkeypatch):
    def fake_run(ctx, settings, on_event=None):
        ctx.transcript = (
            "--- LLM transcript (what the model saw; already redacted) ---\n"
            "Write the configuration audit report using only the tools.\n"
        )
        return "## Resum executiu\n"

    monkeypatch.setattr("omf.pipeline.run_analysis", fake_run)
    session = Session("mikrotik", "https://192.0.2.8", "admin", "s3cret", "tokentok", True, "ca")
    store = AuditStore(tmp_path, "mikrotik", datetime.now(timezone.utc))
    llm = LlmSettings("http://llm.example", "sk-live-secret-key", "model", "openai")
    run_audit(session, store, FullFake(), llm, lambda event: None)
    path = store.path / "redacted" / "transcript.md"
    text = path.read_text()
    assert "Write the configuration audit report using only the tools." in text
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


def test_skip_llm_with_configured_model_does_not_call_analysis(tmp_path: Path, monkeypatch):
    def boom(ctx, settings, on_event=None):
        raise AssertionError("run_analysis must not be called when skip_llm=True")

    monkeypatch.setattr("omf.pipeline.run_analysis", boom)
    session = Session("mikrotik", "https://192.0.2.8", "admin", "s3cret", "tokentok", True, "ca")
    store = AuditStore(tmp_path, "mikrotik", datetime.now(timezone.utc))
    llm = LlmSettings("http://llm.example", "sk-live", "model", "openai")
    events = []
    report = run_audit(session, store, FullFake(), llm, events.append, skip_llm=True)
    text = report.read_text()
    assert "Narrative skipped" in text
    assert '"fail"' in (store.path / "findings.json").read_text()
    assert (store.path / "redacted" / "findings.json").is_file()
    assert not (store.path / "redacted" / "transcript.md").is_file()
    assert any(e.get("phase") == "collect" for e in events)
    assert any(e.get("phase") == "eval" for e in events)
    skip = [e for e in events if e.get("phase") == "llm" and e.get("status") == "skipped"]
    assert skip and skip[0].get("detail") == "evaluation only"
    assert "Security baseline report" in text
    assert "Executive summary" in text
    assert "Vulnerabilities" in text
    assert "Vulnerabilitats" not in text
    assert "Resum executiu" not in text
    assert "Informe d" not in text
    assert '"report_language": "en"' in (store.path / "meta.json").read_text()
    assert session.password == ""


def test_skip_llm_without_llm_env_still_collects_and_evaluates(tmp_path: Path, monkeypatch):
    def boom(ctx, settings, on_event=None):
        raise AssertionError("run_analysis must not be called when skip_llm=True")

    monkeypatch.setattr("omf.pipeline.run_analysis", boom)
    session = Session("mikrotik", "https://192.0.2.8", "admin", "s3cret", "", True, "en")
    store = AuditStore(tmp_path, "mikrotik", datetime.now(timezone.utc))
    llm = LlmSettings(None, None, None, "openai")
    events = []
    report = run_audit(session, store, FullFake(), llm, events.append, skip_llm=True)
    assert report == store.path / "report.html"
    text = report.read_text()
    assert "Narrative skipped" in text
    assert "Security baseline report" in text
    assert any(e.get("phase") == "collect" for e in events)
    assert any(e.get("phase") == "eval" for e in events)
    assert '"fail"' in (store.path / "findings.json").read_text()
    skip = [e for e in events if e.get("phase") == "llm" and e.get("status") == "skipped"]
    assert skip and skip[0].get("detail") == "evaluation only"


def test_safe_exc_detail_strips_api_key():
    from omf.pipeline import _safe_exc_detail

    exc = RuntimeError("provider rejected key sk-secret-value")
    detail = _safe_exc_detail(exc, "sk-secret-value")
    assert "sk-secret-value" not in detail
    assert "RuntimeError" in detail
    assert "[STRIPPED]" in detail


def test_llm_fallback_log_strips_api_key(tmp_path: Path, monkeypatch, caplog):
    def fake_run(ctx, settings, on_event=None):
        raise RuntimeError(f"Incorrect API key provided: {settings.api_key}")

    monkeypatch.setattr("omf.pipeline.run_analysis", fake_run)
    session = Session("mikrotik", "https://192.0.2.8", "admin", "s3cret", "", True, "en")
    store = AuditStore(tmp_path, "mikrotik", datetime.now(timezone.utc))
    llm = LlmSettings("http://llm.example", "sk-secret-test", "model", "openai")
    caplog.set_level(logging.WARNING, logger="omf.pipeline")
    run_audit(session, store, FullFake(), llm, lambda event: None)
    assert "sk-secret-test" not in caplog.text
