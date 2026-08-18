from datetime import datetime, timezone
from pathlib import Path
import json
import pytest
from omf.store import AuditStore
from omf.schema.capabilities import UserList
from omf.schema.evidence import Evidence, CheckResult


def test_layout_and_meta_rejects_url(tmp_path: Path):
    started = datetime(2026, 8, 18, 14, 2, 11, tzinfo=timezone.utc)
    store = AuditStore(tmp_path, "mikrotik", started)
    assert store.path.name == "2026-08-18T140211-mikrotik"
    store.write_meta({"vendor": "mikrotik", "tls_verify": True, "tool_version": "0.1.0"})
    meta = json.loads((store.path / "meta.json").read_text())
    assert "url" not in meta
    with pytest.raises(ValueError):
        store.write_meta({"vendor": "mikrotik", "url": "https://192.0.2.1"})


def test_writes_raw_evidence_findings(tmp_path: Path):
    store = AuditStore(tmp_path, "fortinet", datetime.now(timezone.utc))
    store.write_raw("users", [{"name": "admin"}])
    ev = Evidence(
        capability="users",
        vendor="fortinet",
        collected_at=datetime.now(timezone.utc),
        payload=UserList(users=()),
    )
    store.write_evidence(ev)
    store.write_findings([
        CheckResult(check_id="FW-ADM-001", status="pass", severity="high",
                    diagnostic="ok", capability_refs=("users",), observed={}),
    ])
    store.append_event({"phase": "collect", "path": "/rest/user", "status": 200})
    store.write_report("# hi\n")
    assert (store.path / "raw" / "users.json").is_file()
    assert (store.path / "evidence" / "users.json").is_file()
    assert (store.path / "findings.json").is_file()
    assert (store.path / "events.jsonl").is_file()
    assert (store.path / "report.md").read_text() == "# hi\n"
    with pytest.raises(ValueError):
        store.append_event({"password": "x"})
