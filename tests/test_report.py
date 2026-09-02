from datetime import datetime, timezone

from omf.agent.llm import _prompt_for
from omf.agent.report import (
    ReportNarrative,
    VulnNarrative,
    finalize_report,
    narrative_body,
    skeleton_body,
    wrap_report,
)
from omf.schema.evidence import CheckResult
from omf.baseline.loader import CheckDef, load_catalog
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


def test_wrap_inserts_localized_header_with_author_date_target():
    html = wrap_report(
        "BODY",
        vendor="mikrotik",
        url="https://192.0.2.1",
        started_at=datetime(2026, 8, 18, tzinfo=timezone.utc),
        version="0.1.0",
        language="ca",
        findings=[],
    )
    assert html.strip().startswith("<!DOCTYPE html>")
    assert "Informe d" in html  # title; apostrophe may be escaped
    assert "Autor" in html
    assert "OH MY FORTRESS" not in html
    assert "This was a read-only assessment" in html
    assert html.index("Autor") < html.index("This was a read-only assessment")
    assert "2026-08-18" in html
    assert "mikrotik" in html and "https://192.0.2.1" in html
    assert "OMF 0.1.0" in html
    assert html.count("https://192.0.2.1") == 1
    assert "BODY" in html


def test_wrap_english_title():
    html = wrap_report(
        "BODY",
        vendor="fortinet",
        url="https://fw",
        started_at=datetime(2026, 8, 19, tzinfo=timezone.utc),
        version="1.2.3",
        language="en",
        findings=[],
    )
    assert "<h1>Security baseline report</h1>" in html
    assert "fortinet" in html and "https://fw" in html
    assert html.count("https://fw") == 1


def _low_license_fail():
    return CheckResult(
        check_id="FW-LIC-012",
        status="fail",
        severity="low",
        diagnostic="forticloud is expired (expires 2024-07-07)",
        capability_refs=("licenses",),
        observed={"key": "forticloud", "status": "expired", "expires": "2024-07-07"},
    )


def test_skeleton_includes_low_license_fail():
    findings = _findings() + [_low_license_fail()]
    body = skeleton_body(findings, load_catalog("fortinet"), "fortinet", language="en")
    exec_part, _, vuln_part = body.partition("## Vulnerabilities")
    assert "| FW-LIC-012 | low |" in exec_part
    assert "### FW-LIC-012" in vuln_part
    assert "- **Severity:** low" in vuln_part


def test_narrative_body_includes_low_license_fail():
    narrative = ReportNarrative(
        executive_summary="Scope includes a low FortiGate Cloud fail.",
        vulnerabilities=[
            VulnNarrative(
                check_id="FW-LIC-012",
                title="FortiGate Cloud",
                description="The FortiGate Cloud entitlement is expired.",
            )
        ],
    )
    body = narrative_body(
        narrative,
        [_low_license_fail()],
        load_catalog("fortinet"),
        "fortinet",
        language="en",
    )
    assert "| FW-LIC-012 | low |" in body
    assert "### FW-LIC-012" in body
    assert "- **Severity:** low" in body


def test_skeleton_is_exec_summary_and_fail_only_vulnerabilities():
    checks = load_catalog("mikrotik")
    body = skeleton_body(_findings(), checks, "mikrotik", language="ca")
    exec_part, _, vuln_part = body.partition("## Vulnerabilitats")
    assert "## Resum executiu" in exec_part
    assert "Narrative skipped" in exec_part
    assert "| id | Severitat | títol |" in exec_part
    assert "| FW-ADM-001 | high |" in exec_part
    assert "FW-SYS-001" not in exec_part
    assert "FW-NTP-001" not in exec_part
    assert "### FW-ADM-001" in vuln_part
    assert "- **Severitat:** high" in vuln_part
    desc_line = next(line for line in vuln_part.splitlines() if line.startswith("- **Descripció:**"))
    assert desc_line != "- **Descripció:** enabled user matches vendor default name 'admin'"
    assert "admin" in desc_line.lower()
    assert "| field | value |" in vuln_part
    assert "| names | admin |" in vuln_part
    assert "names=['admin']" not in vuln_part
    assert "- **Exemple de mitigació:**" in vuln_part
    assert "/user" in vuln_part
    assert "### FW-SYS-001" not in vuln_part
    assert "### FW-NTP-001" not in vuln_part
    assert "read-only" not in body.lower()
    assert "Mitigations are examples" not in body


def test_skeleton_english_headings():
    body = skeleton_body(_findings(), load_catalog(), "mikrotik", language="en")
    assert "## Executive summary" in body
    assert "## Vulnerabilities" in body


def test_skeleton_prefers_catalog_description():
    finding = CheckResult(
        check_id="FW-ADM-007",
        status="fail",
        severity="high",
        diagnostic="tlsv1-2 allowed",
        capability_refs=("admin_settings",),
        observed={"versions": ["tlsv1-2", "tlsv1-3"]},
    )
    body = skeleton_body([finding], load_catalog("fortinet"), "fortinet", language="en")
    assert "- **Description:** tlsv1-2 allowed" not in body
    desc_line = next(line for line in body.splitlines() if line.startswith("- **Description:**"))
    assert "TLS" in desc_line or "tls" in desc_line.lower()
    assert "tlsv1-2 allowed" not in desc_line


def test_skeleton_falls_back_to_diagnostic_without_catalog_description():
    checks = (
        CheckDef(
            "FW-ADM-001",
            "Default admin username",
            "medium",
            ("users",),
            "no_generic_accounts",
            {},
            "rename admin",
            description="",
        ),
    )
    body = skeleton_body(_findings(), checks, "mikrotik", language="en")
    assert "- **Description:** enabled user matches vendor default name 'admin'" in body


def test_skeleton_prefers_mikrotik_catalog_description():
    finding = CheckResult(
        check_id="FW-SVC-005",
        status="fail",
        severity="medium",
        diagnostic="ssh_strong_crypto is False",
        capability_refs=("admin_settings",),
        observed={"ssh_strong_crypto": False},
    )
    body = skeleton_body([finding], load_catalog("mikrotik"), "mikrotik", language="en")
    assert "- **Description:** ssh_strong_crypto is False" not in body
    desc_line = next(line for line in body.splitlines() if line.startswith("- **Description:**"))
    assert "ssh" in desc_line.lower() or "crypto" in desc_line.lower()
    assert "ssh_strong_crypto is False" not in desc_line


def test_skeleton_fences_catalog_cli():
    finding = CheckResult(
        check_id="FW-ADM-007",
        status="fail",
        severity="high",
        diagnostic="tlsv1-2 allowed",
        capability_refs=("admin_settings",),
        observed={"versions": ["tlsv1-2", "tlsv1-3"]},
    )
    body = skeleton_body([finding], load_catalog("fortinet"), "fortinet", language="en")
    mit_line = next(line for line in body.splitlines() if line.startswith("- **Example mitigation:**"))
    assert "config " not in mit_line
    assert "```" in body
    fence = body.split("```", 2)[1]
    assert "config system global" in fence
    assert "set admin-https-ssl-versions tlsv1-3" in fence
    assert "| tlsv1-2, tlsv1-3 |" not in body
    assert "| versions |" in body
    assert "| tlsv1-2 |" in body
    assert "| tlsv1-3 |" in body


def test_skeleton_evidence_table_for_policy_rows():
    finding = CheckResult(
        check_id="FW-POL-001",
        status="fail",
        severity="high",
        diagnostic="unrestricted accept",
        capability_refs=("firewall_filter",),
        observed={
            "policies": [
                {
                    "id": "90",
                    "src": ["any"],
                    "dst": ["any"],
                    "service": ["any"],
                    "action": "accept",
                }
            ]
        },
    )
    body = skeleton_body([finding], load_catalog("fortinet"), "fortinet", language="en")
    assert "| id | src | dst | service | action |" in body
    assert "| 90 | any | any | any | accept |" in body


def test_skeleton_evidence_mixed_policy_rows_and_scalar():
    finding = CheckResult(
        check_id="FW-POL-005",
        status="fail",
        severity="medium",
        diagnostic="unlogged",
        capability_refs=("firewall_filter", "logging"),
        observed={
            "policies": [
                {
                    "id": "90",
                    "src": ["any"],
                    "dst": ["any"],
                    "service": ["ALL"],
                    "action": "accept",
                    "log": False,
                }
            ],
            "implicit_policy_logged": True,
        },
    )
    body = skeleton_body([finding], load_catalog("fortinet"), "fortinet", language="en")
    assert "| 90 | any | any | ALL | accept | False |" in body
    assert "| implicit_policy_logged | True |" in body


def test_finalize_destokenizes():
    r = Redactor()
    red = r.redact_text("host 10.9.8.7")
    out = finalize_report(
        red,
        r,
        findings=[],
        vendor="fortinet",
        url="https://fw",
        started_at=datetime.now(timezone.utc),
        version="0.1.0",
        language="en",
    )
    assert "10.9.8.7" in out
    assert "[IP_" not in out
    assert out.strip().startswith("<!DOCTYPE html>")


def test_narrative_body_uses_model_prose_and_local_evidence():
    narrative = ReportNarrative(
        executive_summary="Scope: 1 fail.",
        vulnerabilities=[
            VulnNarrative(
                check_id="FW-ADM-001",
                title="Compte admin per defecte",
                description="L'usuari admin de fàbrica segueix habilitat.",
            )
        ],
    )
    body = narrative_body(narrative, _findings(), load_catalog("mikrotik"), "mikrotik", language="ca")
    assert "## Resum executiu" in body
    assert "Scope: 1 fail." in body
    assert "Compte admin per defecte" in body
    assert "L'usuari admin de fàbrica segueix habilitat." in body
    assert "| names | admin |" in body
    assert "- **Exemple de mitigació:**" in body
    assert "/user" in body
    assert "### FW-SYS-001" not in body


def test_narrative_body_fills_omitted_fail_and_drops_unknown():
    narrative = ReportNarrative(
        executive_summary="x",
        vulnerabilities=[
            VulnNarrative(check_id="FW-DOES-NOT-EXIST", title="nope", description="nope"),
        ],
    )
    body = narrative_body(narrative, _findings(), load_catalog(), "mikrotik", language="en")
    assert "FW-ADM-001" in body
    assert "FW-DOES-NOT-EXIST" not in body
    assert "nope" not in body


def test_system_prompt_requires_packed_narrative():
    prompt = _prompt_for("ca")
    assert "no title header" in prompt.lower() or "Do not write a title" in prompt
    assert "fail findings only" in prompt.lower() or "Every fail in the pack" in prompt
    assert "catalog description" in prompt.lower()
    assert "submit_report" not in prompt
    assert "list_findings" not in prompt
    assert "get_mitigation" not in prompt
    assert "packed" in prompt.lower()


def test_system_prompt_forbids_calques_in_ca_es():
    prompt = _prompt_for("es")
    assert "backdoor" in prompt
    assert "porta del darrere" in prompt
    assert "puerta de atrás" in prompt
    assert "troballes" in prompt
    assert "hallazgos" in prompt
    assert "vulnerabilitats" in prompt
    assert "vulnerabilidades" in prompt
    assert "tallafoc" in prompt
    assert "cortafuegos" in prompt
    assert "If a calque and the English term both exist, keep the English term." in prompt
