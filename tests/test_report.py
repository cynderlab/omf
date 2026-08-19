from datetime import datetime, timezone

from omf.agent.llm import _SYSTEM_PROMPT
from omf.agent.report import skeleton_body, wrap_report, finalize_report
from omf.schema.evidence import CheckResult
from omf.baseline.loader import load_catalog
from omf.redactor import Redactor


def _findings():
    return [
        CheckResult(
            check_id="FW-ADM-001",
            status="fail",
            severity="high",
            diagnostic="enabled user matches vendor default name 'admin'",
            capability_refs=("users",),
            observed={"names": ["admin"]},
        ),
        CheckResult(
            check_id="FW-SYS-001",
            status="pass",
            severity="info",
            diagnostic="firmware 7.16",
            capability_refs=("system_info",),
            observed={"firmware": "7.16"},
        ),
        CheckResult(
            check_id="FW-NTP-001",
            status="error",
            severity="medium",
            diagnostic="ntp collect failed",
            capability_refs=("ntp",),
            observed={},
        ),
    ]


def test_wrap_inserts_localized_header_with_author_date_firewall():
    md = wrap_report(
        "BODY",
        vendor="mikrotik",
        url="https://192.0.2.1",
        started_at=datetime(2026, 8, 18, tzinfo=timezone.utc),
        version="0.1.0",
        language="ca",
    )
    header, _, _ = md.partition("BODY")
    assert header.startswith("# Informe d'auditoria de tallafoc\n")
    assert "- Author: OH MY FIREWALL\n" in header
    assert "- Date: 2026-08-18\n" in header
    assert "- Firewall: mikrotik · https://192.0.2.1\n" in header
    assert "- Tool: OMF 0.1.0\n" in header
    assert header.count("https://192.0.2.1") == 1


def test_wrap_english_title():
    md = wrap_report(
        "BODY",
        vendor="fortinet",
        url="https://fw",
        started_at=datetime(2026, 8, 19, tzinfo=timezone.utc),
        version="1.2.3",
        language="en",
    )
    assert md.startswith("# Firewall audit report\n")
    assert "- Firewall: fortinet · https://fw\n" in md


def test_skeleton_is_exec_summary_and_fail_only_vulnerabilities():
    checks = load_catalog()
    body = skeleton_body(_findings(), checks, "mikrotik", language="ca")
    exec_part, _, vuln_part = body.partition("## Vulnerabilitats")
    assert "## Resum executiu" in exec_part
    assert "Narrative skipped" in exec_part
    assert "| id | severity | title |" in exec_part
    assert "| FW-ADM-001 | high |" in exec_part
    assert "FW-SYS-001" not in exec_part
    assert "FW-NTP-001" not in exec_part
    assert "### FW-ADM-001" in vuln_part
    assert "**Severity:** high" in vuln_part
    assert "**Description:** enabled user matches vendor default name 'admin'" in vuln_part
    assert "**Evidence:** names=['admin']" in vuln_part
    assert "**Mitigation:**" in vuln_part
    assert "Rename the default admin" in vuln_part
    assert "### FW-SYS-001" not in vuln_part
    assert "### FW-NTP-001" not in vuln_part
    assert "read-only" in body.lower()


def test_skeleton_english_headings():
    body = skeleton_body(_findings(), load_catalog(), "mikrotik", language="en")
    assert "## Executive summary" in body
    assert "## Vulnerabilities" in body


def test_finalize_destokenizes():
    r = Redactor()
    red = r.redact_text("host 10.9.8.7")
    out = finalize_report(
        red,
        r,
        vendor="fortinet",
        url="https://fw",
        started_at=datetime.now(timezone.utc),
        version="0.1.0",
        language="en",
    )
    assert "10.9.8.7" in out
    assert "[IP_" not in out


def test_system_prompt_requires_report_shape():
    prompt = _SYSTEM_PROMPT.format(language="ca", exec="Resum executiu", vulns="Vulnerabilitats")
    assert "no title header" in prompt.lower() or "Do not write a title" in prompt
    assert "## {exec}" not in prompt
    assert "## Resum executiu" in prompt
    assert "## Vulnerabilitats" in prompt
    assert "**Severity:**" in prompt
    assert "**Description:**" in prompt
    assert "**Evidence:**" in prompt
    assert "**Mitigation:**" in prompt
    assert "fail findings only" in prompt
