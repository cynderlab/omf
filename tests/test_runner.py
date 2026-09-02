from datetime import datetime, timezone
from pathlib import Path
import json
from omf.adapters.base import CollectError
from omf.runner import Runner
from omf.store import AuditStore
from omf.schema.capabilities import UserList, User, NtpConfig
from omf.schema.evidence import Evidence
from omf.baseline.loader import checks_for


class FakeAdapter:
    vendor = "mikrotik"

    def __init__(self, implemented=None, fail=frozenset()):
        self._impl = (
            frozenset({
                "users", "admin_settings", "services", "ntp", "dns",
                "logging", "snmp", "firewall_filter", "system_info",
            })
            if implemented is None
            else frozenset(implemented)
        )
        self.fail = set(fail)
        self.calls: list[str] = []

    def probe(self) -> None:
        return None

    def implemented(self) -> frozenset[str]:
        return self._impl

    def collect(self, capability: str):
        self.calls.append(capability)
        if capability in self.fail:
            raise CollectError(capability, f"/{capability}", 500, "boom")
        now = datetime.now(timezone.utc)
        if capability == "users":
            payload = UserList(users=(User(name="alice", enabled=True, groups=()),))
        elif capability == "ntp":
            payload = NtpConfig(enabled=True, servers=("1.2.3.4",))
        else:
            raise CollectError(capability, f"/{capability}", None, "fixture missing")
        return Evidence(capability=capability, vendor="mikrotik", collected_at=now, payload=payload), {"raw": True}

    def close(self) -> None:
        return None


def test_collects_each_needed_capability_once(tmp_path: Path):
    from omf.baseline.loader import CheckDef
    checks = (
        CheckDef("A", "a", "high", ("users",), "no_generic_accounts", {}, "x"),
        CheckDef("B", "b", "high", ("users",), "no_generic_accounts", {}, "x"),
    )
    store = AuditStore(tmp_path, "mikrotik", datetime.now(timezone.utc))
    adapter = FakeAdapter()
    Runner(adapter, checks, store).run()
    assert adapter.calls == ["users"]


def test_unimplemented_capability_skips_check(tmp_path: Path):
    from omf.baseline.loader import CheckDef
    checks = (CheckDef("A", "a", "high", ("dns",), "dns_configured", {}, "x"),)
    store = AuditStore(tmp_path, "mikrotik", datetime.now(timezone.utc))
    adapter = FakeAdapter(implemented=frozenset())
    result = Runner(adapter, checks, store).run()
    assert result.findings[0].status == "skipped"
    assert adapter.calls == []


def test_collect_failure_errors_dependents(tmp_path: Path):
    from omf.baseline.loader import CheckDef
    checks = (CheckDef("A", "a", "medium", ("ntp",), "ntp_configured", {}, "x"),)
    store = AuditStore(tmp_path, "mikrotik", datetime.now(timezone.utc))
    adapter = FakeAdapter(fail=frozenset({"ntp"}))
    result = Runner(adapter, checks, store).run()
    assert result.findings[0].status == "error"
    assert (store.path / "findings.json").is_file()


def test_eval_events_omit_diagnostic(tmp_path: Path):
    from omf.baseline.loader import CheckDef
    checks = (
        CheckDef("A", "a", "high", ("users",), "no_generic_accounts", {}, "x"),
    )
    store = AuditStore(tmp_path, "mikrotik", datetime.now(timezone.utc))
    captured: list[dict] = []
    Runner(FakeAdapter(), checks, store, captured.append).run()
    eval_events = [event for event in captured if event.get("phase") == "eval"]
    assert eval_events
    for event in eval_events:
        assert event.get("check_id") == "A"
        assert event.get("status") in {"pass", "fail", "error", "skipped"}
        assert "diagnostic" in event
    for line in (store.path / "events.jsonl").read_text().splitlines():
        row = json.loads(line)
        if row.get("phase") == "eval":
            assert "diagnostic" not in row
            assert set(row) >= {"phase", "check_id", "status", "severity"}
