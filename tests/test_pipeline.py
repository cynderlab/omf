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
