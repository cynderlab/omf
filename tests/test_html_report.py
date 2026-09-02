from omf.agent.html import (
    ReportStats,
    summarize,
    posture_strip,
    severity_chips,
    status_donut_svg,
    severity_bars_svg,
)
from omf.schema.evidence import CheckResult


def _finding(check_id, status, severity="info"):
    return CheckResult(
        check_id=check_id,
        status=status,
        severity=severity,
        diagnostic="d",
        capability_refs=("users",),
        observed={},
    )


def test_summarize_counts_status_and_fail_severity():
    stats = summarize([
        _finding("A", "fail", "high"),
        _finding("B", "fail", "high"),
        _finding("C", "fail", "medium"),
        _finding("D", "pass", "info"),
        _finding("E", "error", "low"),
        _finding("F", "skipped", "info"),
        _finding("FW-LIC-012", "fail", "low"),
    ])
    assert stats.total == 7
    assert stats.by_status == {"pass": 1, "fail": 4, "error": 1, "skipped": 1}
    assert stats.fail_by_severity == {"high": 2, "medium": 1, "low": 1, "info": 0}


def test_summarize_empty():
    stats = summarize([])
    assert stats.total == 0
    assert stats.by_status == {"pass": 0, "fail": 0, "error": 0, "skipped": 0}
    assert stats.fail_by_severity == {"high": 0, "medium": 0, "low": 0, "info": 0}


def test_posture_strip_has_no_script_and_encodes_counts():
    stats = ReportStats(
        total=2,
        by_status={"pass": 1, "fail": 1, "error": 0, "skipped": 0},
        fail_by_severity={"high": 1, "medium": 0, "low": 0, "info": 0},
    )
    copy = {"status": "Status", "pass": "Pass", "fail": "Fail", "error": "Error", "skipped": "Skipped"}
    html = posture_strip(stats, copy)
    assert 'class="posture"' in html
    assert "<script" not in html.lower()
    assert "<svg" not in html.lower()
    assert "posture-fail" in html and "posture-pass" in html
    assert "50.000%" in html


def test_severity_chips_include_zero_buckets():
    stats = ReportStats(
        total=1,
        by_status={"pass": 0, "fail": 1, "error": 0, "skipped": 0},
        fail_by_severity={"high": 1, "medium": 0, "low": 0, "info": 0},
    )
    html = severity_chips(stats, {"severity": "Severity"})
    assert 'class="sev-chips"' in html
    assert "<script" not in html.lower()
    assert "high" in html and "medium" in html and "low" in html and "info" in html
    assert "chip-high" in html


def test_donut_svg_has_no_script_and_encodes_counts():
    stats = ReportStats(
        total=2,
        by_status={"pass": 1, "fail": 1, "error": 0, "skipped": 0},
        fail_by_severity={"high": 1, "medium": 0, "low": 0, "info": 0},
    )
    copy = {"status": "Status", "pass": "Pass", "fail": "Fail", "error": "Error", "skipped": "Skipped"}
    svg = status_donut_svg(stats, copy)
    assert "<svg" in svg
    assert "<script" not in svg.lower()
    assert "Pass" in svg and "Fail" in svg
    assert "1" in svg


def test_severity_bars_include_zero_buckets():
    stats = ReportStats(
        total=1,
        by_status={"pass": 0, "fail": 1, "error": 0, "skipped": 0},
        fail_by_severity={"high": 1, "medium": 0, "low": 0, "info": 0},
    )
    svg = severity_bars_svg(stats, {"severity": "Severity"})
    assert "<svg" in svg
    assert "<script" not in svg.lower()
    assert "high" in svg and "medium" in svg and "low" in svg and "info" in svg


from omf.agent.html import markdown_to_html


def test_markdown_headings_table_list_and_bold():
    md = (
        "## Executive summary\n\n"
        "Scope paragraph.\n\n"
        "| id | severity | title |\n"
        "| --- | --- | --- |\n"
        "| FW-ADM-001 | high | Default admin |\n\n"
        "### FW-ADM-001 — Default admin\n\n"
        "- **Severity:** high\n"
        "- **Description:** bad\n"
    )
    html = markdown_to_html(md)
    assert "<h2>Executive summary</h2>" in html
    assert '<h3 id="FW-ADM-001">FW-ADM-001 — Default admin</h3>' in html
    assert '<div class="table-wrap"><table>' in html
    assert "<th>id</th>" in html
    assert '<td>FW-ADM-001 <a href="#FW-ADM-001" class="jump">#</a></td>' in html
    assert "<strong>Severity:</strong> high" in html
    assert "<p>Scope paragraph.</p>" in html


def test_markdown_policy_id_cells_are_not_jump_links():
    html = markdown_to_html(
        "| id | src | dst | service | action |\n"
        "| --- | --- | --- | --- | --- |\n"
        "| 90 | any | any | any | accept |\n"
        "| *8 | lan | wan | tcp/443 | drop |\n"
        "### FW-POL-001 — Unrestricted accept\n"
    )
    assert '<h3 id="FW-POL-001">' in html
    assert "<td>90</td>" in html
    assert "<td>*8</td>" in html
    assert 'href="#90"' not in html
    assert 'href="#*8"' not in html
    assert "class=\"jump\"" not in html


def test_markdown_check_id_without_heading_has_no_jump():
    html = markdown_to_html(
        "| id | severity | title |\n"
        "| --- | --- | --- |\n"
        "| FW-ADM-001 | high | Default admin |\n"
    )
    assert "<td>FW-ADM-001</td>" in html
    assert "class=\"jump\"" not in html
    assert 'id="FW-ADM-001"' not in html


def test_markdown_severity_cells_use_palette_classes():
    html = markdown_to_html(
        "| id | severity | title |\n"
        "| --- | --- | --- |\n"
        "| FW-H | high | High check |\n"
        "| FW-M | medium | Medium check |\n"
        "| FW-L | low | Low check |\n"
        "| FW-I | info | Info check |\n"
        "| FW-X | other | Other check |\n"
    )
    assert '<td class="sev-high">high</td>' in html
    assert '<td class="sev-medium">medium</td>' in html
    assert '<td class="sev-low">low</td>' in html
    assert '<td class="sev-info">info</td>' in html
    assert "<td>other</td>" in html
    assert "<th>severity</th>" in html
    assert 'class="sev-' not in html.split("<th>severity</th>")[0]


def test_markdown_escapes_tags_from_model_text():
    html = markdown_to_html(
        "## Executive summary\n\n"
        "<script>alert(1)</script>\n"
        "<img src=x onerror=alert(1)>\n"
    )
    assert "<script" not in html.lower()
    assert "<img" not in html.lower()
    assert "&lt;script&gt;" in html
    assert "&lt;img" in html


def test_markdown_fenced_code_preserves_newlines_and_indent():
    html = markdown_to_html(
        "Intro.\n\n"
        "```\n"
        "config system global\n"
        "    set admin-https-ssl-versions tlsv1-3\n"
        "end\n"
        "```\n"
    )
    assert "<p>Intro.</p>" in html
    assert "<pre><code>" in html
    assert "```" not in html
    assert "config system global\n    set admin-https-ssl-versions tlsv1-3\nend" in html


def test_markdown_fence_drops_language_tag():
    html = markdown_to_html("```cli\n/ip ssh/set strong-crypto=yes\n```\n")
    assert "```" not in html
    assert "/ip ssh/set strong-crypto=yes" in html
    assert html.count("cli") == 0


def test_markdown_inline_code():
    html = markdown_to_html("Rename `admin` under /user.\n")
    assert "<code>admin</code>" in html
    assert "`admin`" not in html


def test_markdown_unmatched_backtick_stays_literal():
    html = markdown_to_html("Use `admin only.\n")
    assert "<code>" not in html
    assert "`admin only." in html


def test_markdown_fence_escapes_script():
    html = markdown_to_html("```\n<script>alert(1)</script>\n```\n")
    assert "<script" not in html.lower()
    assert "&lt;script&gt;" in html
    assert "<pre><code>" in html


from datetime import datetime, timezone

from omf.agent.html import operator_username, render_html_report
from omf.agent.report import finalize_report
from omf.redactor import Redactor

_DISCLAIMER = (
    "This was a read-only assessment. Mitigations are examples. "
    "The auditor is responsible for any change."
)


def _wrap(body="## Executive summary\n\nLLM says zero problems.\n", **kwargs):
    findings = kwargs.pop(
        "findings",
        [
            _finding("FW-ADM-001", "fail", "high"),
            _finding("FW-SYS-001", "pass", "info"),
            _finding("FW-NTP-001", "error", "medium"),
        ],
    )
    return render_html_report(
        body,
        vendor=kwargs.pop("vendor", "mikrotik"),
        url=kwargs.pop("url", "https://192.0.2.1"),
        started_at=kwargs.pop("started_at", datetime(2026, 8, 18, tzinfo=timezone.utc)),
        version=kwargs.pop("version", "0.1.0"),
        language=kwargs.pop("language", "en"),
        findings=findings,
        **kwargs,
    )


def test_wrap_html_inserts_dashboard_after_exec_heading(monkeypatch):
    monkeypatch.setattr("omf.agent.html.operator_username", lambda: "alice")
    html = _wrap()
    assert html.strip().startswith("<!DOCTYPE html>")
    assert 'lang="en"' in html
    assert "<h1>Security baseline report</h1>" in html
    assert 'class="appbar"' in html
    assert 'class="mark"' not in html
    assert "Author" in html and "alice" in html
    assert "OH MY FORTRESS" not in html
    assert "OMF" in html
    assert "2026-08-18" in html
    assert "mikrotik" in html and "https://192.0.2.1" in html
    assert html.count("https://192.0.2.1") == 1
    assert "<script" not in html.lower()
    assert "cdn" not in html.lower()
    assert 'src="' not in html
    i_h2 = html.index("Executive summary")
    i_kpi = html.index('class="kpis"')
    i_para = html.index("LLM says zero problems.")
    assert i_h2 < i_kpi < i_para
    assert "Pass" in html and ">1<" in html or "1" in html
    assert "Fail" in html
    assert 'class="posture"' in html
    assert 'class="charts"' in html
    assert 'class="chart-status"' in html
    assert "<svg" in html
    assert 'class="sev-chips"' in html
    assert ".chart-status svg" in html
    assert "min-height: 22rem" not in html
    assert "min-height: 16rem" not in html
    # counts from findings, not from the lying paragraph
    assert "zero problems" in html


def test_wrap_html_uses_system_sans_and_no_cdn(monkeypatch):
    monkeypatch.setattr("omf.agent.html.operator_username", lambda: "alice")
    html = _wrap()
    assert "Google Sans" in html
    assert "Roboto" in html
    assert "Roboto Mono" in html
    assert "cdn" not in html.lower()
    assert "fonts.googleapis" not in html.lower()
    assert 'src="' not in html


def test_wrap_html_puts_disclaimer_before_author(monkeypatch):
    monkeypatch.setattr("omf.agent.html.operator_username", lambda: "alice")
    html = _wrap()
    i_h1 = html.index("<h1>")
    i_disc = html.index(_DISCLAIMER)
    i_author = html.index("alice")
    i_h2 = html.index("<h2>")
    i_identity = html.index('class="identity"')
    i_notice = html.index('class="notice"')
    assert i_h1 < i_identity < i_author < i_notice < i_disc < i_h2
    assert 'class="meta-v"' in html
    assert ".meta li" in html
    assert "⚠" in html
    assert "</div>" in html[i_identity:i_notice]


def test_wrap_html_escapes_operator_username(monkeypatch):
    monkeypatch.setattr("omf.agent.html.operator_username", lambda: "a<b")
    html = _wrap()
    assert "a&lt;b" in html
    assert "a<b" not in html


def test_operator_username_uses_getuser(monkeypatch):
    monkeypatch.setattr("omf.agent.html.getpass.getuser", lambda: "bob")
    assert operator_username() == "bob"


def test_operator_username_falls_back_to_env(monkeypatch):
    def boom():
        raise OSError("no pwd")

    monkeypatch.setattr("omf.agent.html.getpass.getuser", boom)
    monkeypatch.setenv("USER", "fromenv")
    assert operator_username() == "fromenv"


def test_operator_username_unknown_when_empty(monkeypatch):
    monkeypatch.setattr("omf.agent.html.getpass.getuser", lambda: "  ")
    monkeypatch.delenv("USER", raising=False)
    monkeypatch.delenv("LOGNAME", raising=False)
    monkeypatch.delenv("USERNAME", raising=False)
    assert operator_username() == "unknown"


def test_html_report_css_colors_severity_cells(monkeypatch):
    monkeypatch.setattr("omf.agent.html.operator_username", lambda: "alice")
    html = _wrap(
        "## Executive summary\n\n"
        "| id | severity | title |\n"
        "| --- | --- | --- |\n"
        "| FW-ADM-001 | high | Default admin |\n",
        findings=[_finding("FW-ADM-001", "fail", "high")],
    )
    assert '<td class="sev-high">high</td>' in html
    assert "#d93025" in html
    assert "#e37400" in html
    assert "#f9ab00" in html
    assert "#1a73e8" in html
    assert "#b42318" not in html


def test_wrap_html_table_headers_and_overflow_css(monkeypatch):
    monkeypatch.setattr("omf.agent.html.operator_username", lambda: "alice")
    html = _wrap(
        "## Executive summary\n\n"
        "| id | src | dst | service | action | extra |\n"
        "| --- | --- | --- | --- | --- | --- |\n"
        "| 1 | any | any | any | accept | long |\n"
    )
    body = html.split("<main", 1)[1]
    assert 'class="table-wrap"' in body
    assert "<th>id</th>" in body
    assert ".table-wrap" in html
    assert "overflow-x: auto" in html
    assert "article.finding" in html
    assert "a.jump" in html
    assert "scroll-margin-top" in html


def test_wrap_html_catalan_kpi_labels():
    html = render_html_report(
        "## Resum executiu\n\n",
        vendor="fortinet",
        url="https://fw",
        started_at=datetime(2026, 8, 19, tzinfo=timezone.utc),
        version="1.2.3",
        language="ca",
        findings=[_finding("FW-ADM-001", "fail", "high")],
    )
    assert 'lang="ca"' in html
    assert "<h1>Informe de línia base de seguretat</h1>" in html
    assert "Fallades" in html
    assert "Correctes" in html
    assert "comprovacions" in html


def test_wrap_html_renders_fenced_code_and_includes_pre_css():
    html = render_html_report(
        "## Executive summary\n\n```\nset foo\n```\n",
        vendor="mikrotik",
        url="https://192.0.2.1",
        started_at=datetime(2026, 8, 18, tzinfo=timezone.utc),
        version="0.1.0",
        language="en",
        findings=[],
    )
    assert "pre {" in html
    assert "<pre>" in html
    assert "set foo" in html
    assert "```" not in html.split("<main", 1)[1]


def test_wrap_html_findings_become_articles(monkeypatch):
    monkeypatch.setattr("omf.agent.html.operator_username", lambda: "alice")
    html = _wrap(
        "## Executive summary\n\n"
        "Scope.\n\n"
        "### FW-ADM-001 — Default admin\n\n"
        "- **Severity:** high\n"
        "- **Description:** bad\n",
        findings=[_finding("FW-ADM-001", "fail", "high")],
    )
    assert '<article class="finding sev-high"' in html
    assert 'id="FW-ADM-001"' in html
    assert "chip-high" in html
    assert html.count('id="FW-ADM-001"') == 1
    assert "<script" not in html.lower()
    assert "<li><strong>Severity:</strong> high</li>" not in html
    assert "td.sev-high { color" in html
    assert "article.finding.sev-high { color" not in html
