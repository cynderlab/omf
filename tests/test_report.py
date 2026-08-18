from datetime import datetime, timezone
from omf.agent.report import skeleton_body, wrap_report, finalize_report
from omf.schema.evidence import CheckResult
from omf.baseline.loader import load_catalog
from omf.redactor import Redactor


def test_skeleton_contains_all_findings_and_banner():
    checks = load_catalog()
    findings = [
        CheckResult(check_id="FW-ADM-001", status="fail", severity="high",
                    diagnostic="enabled user matches vendor default name 'admin'",
                    capability_refs=("users",), observed={}),
        CheckResult(check_id="FW-SYS-001", status="pass", severity="info",
                    diagnostic="firmware 7.16", capability_refs=("system_info",), observed={}),
    ]
    body = skeleton_body(findings, checks, "mikrotik")
    assert body.startswith("Narrative skipped")
    assert "FW-ADM-001" in body
    assert "FW-SYS-001" in body
    assert "Rename the default admin" in body
    assert "### FW-SYS-001" not in body
    assert "read-only" in body.lower()


def test_wrap_inserts_url_only_in_header():
    md = wrap_report("BODY", vendor="mikrotik", url="https://192.0.2.1",
                     started_at=datetime(2026, 8, 18, tzinfo=timezone.utc), version="0.1.0")
    assert md.split("BODY")[0].count("https://192.0.2.1") == 1
    assert "BODY" in md


def test_finalize_destokenizes():
    r = Redactor()
    red = r.redact_text("host 10.9.8.7")
    out = finalize_report(red, r, vendor="fortinet", url="https://fw",
                          started_at=datetime.now(timezone.utc), version="0.1.0")
    assert "10.9.8.7" in out
    assert "[IP_" not in out
