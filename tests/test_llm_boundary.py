import json
from omf.agent.tools import (
    AnalysisContext,
    fail_pack,
    get_finding,
    get_mitigation,
    get_redacted_evidence,
    list_findings,
    make_tools,
    status_counts,
    submit_report,
)
from omf.baseline.loader import CheckDef, load_catalog
from omf.redactor import Redactor


def _ctx():
    r = Redactor()
    findings = [r.redact_obj({
        "check_id": "FW-ADM-001",
        "status": "fail",
        "severity": "high",
        "title": "No generic default admin username",
        "diagnostic": "enabled user matches vendor default name 'admin'",
        "observed": {"names": ["admin"]},
    })]
    evidence = {"users": r.redact_obj({"users": [{"name": "admin", "enabled": True}]})}
    return AnalysisContext(findings, evidence, load_catalog(), "mikrotik", "ca", []), r


def test_get_finding_caps_long_observed_lists():
    policies = [
        {"id": str(i), "src": ["any"], "dst": ["any"], "service": ["any"], "action": "accept"}
        for i in range(40)
    ]
    ctx = AnalysisContext(
        [
            {
                "check_id": "FW-POL-001",
                "status": "fail",
                "severity": "high",
                "diagnostic": "unrestricted accept",
                "observed": {"policies": policies},
            }
        ],
        {},
        load_catalog("fortinet"),
        "fortinet",
        "en",
        [],
    )
    finding = get_finding(ctx, "FW-POL-001")
    listed = finding["observed"]["policies"]
    assert len(listed) == 12
    assert finding["observed"]["policies_total"] == 40
    assert finding["observed"]["policies_truncated"] is True
    blob = json.dumps(finding)
    assert '"id": "30"' not in blob


def test_get_redacted_evidence_caps_long_lists():
    policies = [
        {"id": str(i), "enabled": True, "action": "accept", "src": ["any"], "dst": ["any"]}
        for i in range(52)
    ]
    ctx = AnalysisContext(
        [],
        {"firewall_filter": {"capability": "firewall_filter", "payload": {"policies": policies}}},
        load_catalog(),
        "fortinet",
        "ca",
        [],
    )
    ev = get_redacted_evidence(ctx, "firewall_filter")
    listed = ev["payload"]["policies"]
    assert len(listed) == 12
    assert ev["payload"]["policies_total"] == 52
    assert ev["payload"]["policies_truncated"] is True
    assert listed[0]["id"] == "0"
    assert listed[-1]["id"] == "11"
    blob = json.dumps(ev)
    assert '"id": "40"' not in blob
    assert len(blob) < 8000


def test_model_for_sets_http_timeout():
    from omf.agent.llm import _LLM_TIMEOUT, _model_for
    from omf.config import LlmSettings

    model = _model_for(LlmSettings("http://example.invalid", "sk-test", "m", "openai"))
    timeout = model._provider._client.timeout
    assert timeout.connect == _LLM_TIMEOUT.connect
    assert timeout.read == _LLM_TIMEOUT.read


def test_get_redacted_evidence_keeps_short_lists():
    users = [{"name": "admin", "enabled": True}]
    ctx = AnalysisContext(
        [],
        {"users": {"capability": "users", "payload": {"users": users}}},
        load_catalog(),
        "mikrotik",
        "ca",
        [],
    )
    ev = get_redacted_evidence(ctx, "users")
    assert ev["payload"]["users"] == users
    assert "users_truncated" not in ev["payload"]
    assert "users_total" not in ev["payload"]


def test_tools_return_redacted_only():
    ctx, r = _ctx()
    listed = list_findings(ctx)
    assert listed[0]["check_id"] == "FW-ADM-001"
    finding = get_finding(ctx, "FW-ADM-001")
    ev = get_redacted_evidence(ctx, "users")
    blob = json.dumps({"listed": listed, "finding": finding, "ev": ev, "mit": get_mitigation(ctx, "FW-ADM-001")})
    assert "token_map" not in blob
    assert "password" not in blob
    assert "192." not in blob
    dumped = json.dumps(r.token_map())
    assert dumped not in blob


def test_get_finding_includes_catalog_description():
    check = CheckDef(
        "FW-ADM-001",
        "Default admin username",
        "medium",
        ("users",),
        "no_generic_accounts",
        {},
        "delete admin",
        description="The factory FortiOS administrator is named admin.",
    )
    ctx = AnalysisContext(
        [
            {
                "check_id": "FW-ADM-001",
                "status": "fail",
                "diagnostic": "enabled user matches vendor default name 'admin'",
                "observed": {"names": ["admin"]},
            }
        ],
        {},
        (check,),
        "fortinet",
        "en",
        [],
    )
    finding = get_finding(ctx, "FW-ADM-001")
    assert finding["description"] == "The factory FortiOS administrator is named admin."
    assert finding["diagnostic"] == "enabled user matches vendor default name 'admin'"
    assert finding["observed"] == {"names": ["admin"]}


def test_fail_pack_is_fails_only_and_capped():
    policies = [
        {"id": str(i), "src": ["any"], "dst": ["any"], "service": ["any"], "action": "accept"}
        for i in range(40)
    ]
    ctx = AnalysisContext(
        [
            {
                "check_id": "FW-POL-001",
                "status": "fail",
                "severity": "high",
                "diagnostic": "unrestricted accept",
                "observed": {"policies": policies},
            },
            {
                "check_id": "FW-SYS-001",
                "status": "pass",
                "severity": "low",
                "diagnostic": "ok",
                "observed": {},
            },
            {
                "check_id": "FW-LIC-012",
                "status": "fail",
                "severity": "low",
                "diagnostic": "forticloud is expired",
                "observed": {"key": "forticloud", "status": "expired"},
            },
        ],
        {},
        load_catalog("fortinet"),
        "fortinet",
        "en",
        [],
    )
    pack = fail_pack(ctx)
    assert [row["check_id"] for row in pack] == ["FW-POL-001", "FW-LIC-012"]
    assert pack[1]["severity"] == "low"
    assert len(pack[0]["observed"]["policies"]) == 12
    assert pack[0]["observed"]["policies_total"] == 40
    assert "mitigation" in pack[0] and pack[0]["mitigation"]
    assert "description" in pack[0] and pack[0]["description"]
    assert status_counts(ctx) == {"fail": 2, "pass": 1, "error": 0, "skipped": 0}


def test_submit_appends():
    ctx, _ = _ctx()
    submit_report(ctx, "# body")
    assert ctx.submitted == ["# body"]


def test_make_tools_emits_safe_tool_events():
    ctx, _ = _ctx()
    seen: list[dict] = []
    tools = {tool.name: tool for tool in make_tools(ctx, on_tool=seen.append)}
    tools["list_findings"].function()
    tools["get_finding"].function(check_id="FW-ADM-001")
    tools["get_redacted_evidence"].function(capability="users")
    tools["get_mitigation"].function(check_id="FW-ADM-001")
    tools["submit_report"].function(markdown="# secret-body-must-not-leak")
    names = [event["tool"] for event in seen]
    assert names == [
        "list_findings",
        "get_finding",
        "get_redacted_evidence",
        "get_mitigation",
        "submit_report",
    ]
    assert seen[1]["check_id"] == "FW-ADM-001"
    assert seen[2]["capability"] == "users"
    blob = json.dumps(seen)
    assert "secret-body-must-not-leak" not in blob
    assert "markdown" not in blob


def _narrative_response(
    *,
    check_id: str = "FW-ADM-001",
    title: str = "Default admin",
    description: str = "admin remains",
    summary: str = "one paragraph",
):
    from pydantic_ai.messages import ModelResponse, ToolCallPart

    return ModelResponse(parts=[
        ToolCallPart("final_result", {
            "executive_summary": summary,
            "vulnerabilities": [
                {"check_id": check_id, "title": title, "description": description},
            ],
        })
    ])


def test_build_agent_has_no_session_attr():
    from omf.agent.llm import build_agent
    from omf.config import LlmSettings
    ctx, _ = _ctx()
    settings = LlmSettings("http://example", "sk-test", "model", "openai")
    agent = build_agent(ctx, settings)
    assert not hasattr(agent, "session")
    assert not hasattr(agent, "token_map")
    tool_names = list(getattr(agent._function_toolset, "tools", {}) or ())
    assert "list_findings" not in tool_names
    assert "get_finding" not in tool_names
    assert "get_redacted_evidence" not in tool_names
    assert "get_mitigation" not in tool_names
    assert "submit_report" not in tool_names


def test_run_analysis_retries_once(monkeypatch):
    from omf.agent.llm import build_agent, run_analysis
    from omf.agent.report import ReportNarrative, VulnNarrative
    from omf.config import LlmSettings

    ctx, _ = _ctx()
    settings = LlmSettings("http://example", "sk-test", "model", "openai")
    calls = {"n": 0}
    real_build = build_agent
    narrative = ReportNarrative(
        executive_summary="retry ok",
        vulnerabilities=[
            VulnNarrative(check_id="FW-ADM-001", title="t", description="d"),
        ],
    )

    def wrapped(ctx_arg, settings_arg):
        agent = real_build(ctx_arg, settings_arg)

        def fake_run_sync(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("transient")
            return type("Result", (), {"output": narrative})()

        monkeypatch.setattr(agent, "run_sync", fake_run_sync)
        return agent

    monkeypatch.setattr("omf.agent.llm.build_agent", wrapped)
    out = run_analysis(ctx, settings)
    assert calls["n"] == 2
    assert "retry ok" in out
    assert "### FW-ADM-001" in out


def test_run_analysis_refuses_leaking_payload(monkeypatch):
    import pytest
    from omf.agent.llm import LlmPayloadLeak, run_analysis
    from omf.config import LlmSettings

    calls = {"n": 0}

    def capture_model(messages, info):
        calls["n"] += 1
        raise AssertionError("model must not be called")

    monkeypatch.setattr("omf.agent.llm._model_for", lambda settings: type("M", (), {})())
    ctx = AnalysisContext(
        [{
            "check_id": "FW-ADM-001",
            "status": "fail",
            "severity": "high",
            "diagnostic": "peer 10.0.0.5",
            "observed": {},
        }],
        {},
        load_catalog(),
        "mikrotik",
        "ca",
        [],
    )
    with pytest.raises(LlmPayloadLeak, match="10.0.0.5"):
        run_analysis(ctx, LlmSettings("http://llm.example", "sk-test", "model", "openai"))
    assert calls["n"] == 0


def test_run_analysis_allows_catalog_policy_tokens(monkeypatch):
    from pydantic_ai.models.function import FunctionModel

    from omf.agent.llm import run_analysis
    from omf.config import LlmSettings

    captured: list[object] = []

    def capture_model(messages, info):
        captured.append(messages)
        return _narrative_response(
            check_id="FW-SVC-002",
            title="Listen scope",
            description="management is unrestricted",
        )

    monkeypatch.setattr("omf.agent.llm._model_for", lambda settings: FunctionModel(capture_model))
    ctx = AnalysisContext(
        [
            {
                "check_id": "FW-SVC-002",
                "status": "fail",
                "severity": "high",
                "diagnostic": "management services listen on all/unknown ['ssh']",
                "observed": {"services": [{"name": "ssh", "listen": "all"}]},
            },
            {
                "check_id": "FW-LOG-002",
                "status": "fail",
                "severity": "medium",
                "diagnostic": "no remote syslog targets",
                "observed": {"remote_targets": []},
            },
        ],
        {},
        load_catalog("mikrotik"),
        "mikrotik",
        "ca",
        [],
    )
    out = run_analysis(ctx, LlmSettings("http://llm.example", "sk-test", "model", "openai"))
    assert "### FW-SVC-002" in out
    assert "### FW-LOG-002" in out
    blob = json.dumps(captured, default=str)
    assert "0.0.0.0/0" in blob
    assert "::/0" in blob
    assert "10.0.0.5" not in blob


def test_run_analysis_allows_fortinet_catalog_anycast(monkeypatch):
    from pydantic_ai.models.function import FunctionModel

    from omf.agent.llm import run_analysis
    from omf.config import LlmSettings

    captured: list[object] = []

    def capture_model(messages, info):
        captured.append(messages)
        return _narrative_response(
            check_id="FW-DNS-001",
            title="DNS",
            description="factory resolvers",
        )

    monkeypatch.setattr("omf.agent.llm._model_for", lambda settings: FunctionModel(capture_model))
    ctx = AnalysisContext(
        [
            {
                "check_id": "FW-DNS-001",
                "status": "fail",
                "severity": "low",
                "diagnostic": "DNS servers are empty",
                "observed": {"servers": []},
            }
        ],
        {},
        load_catalog("fortinet"),
        "fortinet",
        "en",
        [],
    )
    out = run_analysis(ctx, LlmSettings("http://llm.example", "sk-test", "model", "openai"))
    assert "### FW-DNS-001" in out
    blob = json.dumps(captured, default=str)
    assert "96.45.45.45" in blob
    assert "96.45.46.46" in blob


def test_run_analysis_raises_when_not_configured():
    import pytest
    from omf.agent.llm import LlmNotConfigured, run_analysis
    from omf.config import LlmSettings

    ctx, _ = _ctx()
    with pytest.raises(LlmNotConfigured):
        run_analysis(ctx, LlmSettings(None, None, None, "openai"))


def test_run_analysis_request_body_excludes_secrets(monkeypatch):
    from pydantic_ai.models.function import FunctionModel

    from omf.agent.llm import build_agent, run_analysis
    from omf.config import LlmSettings

    firewall_url = "https://192.0.2.8"
    password = "s3cret-password"
    api_key = "sk-live-secret-key"
    redactor = Redactor()
    findings = [redactor.redact_obj({
        "check_id": "FW-ADM-001",
        "status": "fail",
        "severity": "high",
        "title": "No generic default admin username",
        "diagnostic": f"enabled user matches vendor default name 'admin' at {firewall_url}",
        "observed": {"names": ["admin"], "url": firewall_url, "password": password, "api_key": api_key},
    })]
    evidence = {"users": redactor.redact_obj({
        "users": [{"name": "admin", "enabled": True, "password": password}],
    })}
    ctx = AnalysisContext(findings, evidence, load_catalog(), "mikrotik", "ca", [])
    token_map = redactor.token_map()
    captured: list[object] = []
    built: dict = {}

    def capture_model(messages, info):
        captured.append({"messages": messages, "info": info})
        return _narrative_response()

    real_build = build_agent

    def wrapped(ctx_arg, settings):
        assert ctx_arg is ctx
        agent = real_build(ctx_arg, settings)
        built["agent"] = agent
        return agent

    monkeypatch.setattr("omf.agent.llm._model_for", lambda settings: FunctionModel(capture_model))
    monkeypatch.setattr("omf.agent.llm.build_agent", wrapped)
    out = run_analysis(ctx, LlmSettings("http://llm.example", api_key, "model", "openai"))
    assert "one paragraph" in out
    assert "### FW-ADM-001" in out
    assert len(captured) == 1
    assert built["agent"] is not None
    assert not hasattr(built["agent"], "session")
    assert not hasattr(built["agent"], "token_map")
    assert not hasattr(ctx, "session")
    assert not hasattr(ctx, "token_map")
    assert not hasattr(ctx, "url")
    blob = json.dumps(captured, default=str)
    assert "FW-ADM-001" in blob
    assert "list_findings" not in blob
    assert "submit_report" not in blob
    assert firewall_url not in blob
    assert password not in blob
    assert api_key not in blob
    assert "token_map" not in blob
    assert "raw/" not in blob
    assert json.dumps(token_map) not in blob


def test_run_analysis_payload_uses_tokens_for_hostname_and_user(monkeypatch):
    from pydantic_ai.models.function import FunctionModel

    from omf.agent.llm import run_analysis
    from omf.config import LlmSettings

    redactor = Redactor()
    redactor.redact_obj({"users": [{"name": "reader"}], "hostname": "home-fw"})
    findings = [redactor.apply_known(redactor.redact_obj({
        "check_id": "FW-ADM-002",
        "status": "fail",
        "severity": "medium",
        "diagnostic": "users missing inactivity logout/lock ['admin', 'reader']",
        "observed": {"names": ["admin", "reader"], "hostname": "home-fw"},
    }))]
    evidence = {
        "users": redactor.apply_known(redactor.redact_obj({
            "users": [{"name": "admin"}, {"name": "reader"}],
        })),
        "admin_settings": redactor.apply_known(redactor.redact_obj({
            "hostname": "home-fw",
        })),
    }
    ctx = AnalysisContext(findings, evidence, load_catalog(), "mikrotik", "ca", [])
    captured: list[object] = []

    def capture_model(messages, info):
        captured.append({"messages": messages, "info": info})
        return _narrative_response(check_id="FW-ADM-002", title="Idle timeout", description="idle")

    monkeypatch.setattr("omf.agent.llm._model_for", lambda settings: FunctionModel(capture_model))
    out = run_analysis(ctx, LlmSettings("http://llm.example", "sk-test", "model", "openai"))
    assert "### FW-ADM-002" in out
    assert len(captured) == 1
    blob = json.dumps(captured, default=str)
    assert "home-fw" not in blob
    assert "reader" not in blob
    assert "[HOST_" in blob
    assert "[USER_" in blob
    assert "list_findings" not in blob


def test_run_analysis_one_request_no_tool_events(monkeypatch):
    from pydantic_ai.models.function import FunctionModel

    from omf.agent.llm import run_analysis
    from omf.config import LlmSettings

    ctx, _ = _ctx()
    events: list[dict] = []
    captured: list[object] = []

    def capture_model(messages, info):
        captured.append(messages)
        return _narrative_response()

    monkeypatch.setattr("omf.agent.llm._model_for", lambda settings: FunctionModel(capture_model))
    out = run_analysis(
        ctx,
        LlmSettings("http://llm.example", "sk-test", "model", "openai"),
        on_event=events.append,
    )
    assert "one paragraph" in out
    assert "### FW-ADM-001" in out
    assert len(captured) == 1
    assert not any(event.get("status") == "tool" for event in events)
    assert all(event.get("phase") == "llm" for event in events)
