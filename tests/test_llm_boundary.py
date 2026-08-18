import json
from omf.agent.tools import AnalysisContext, list_findings, get_finding, get_redacted_evidence, get_mitigation, submit_report
from omf.baseline.loader import load_catalog
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


def test_submit_appends():
    ctx, _ = _ctx()
    submit_report(ctx, "# body")
    assert ctx.submitted == ["# body"]


def test_build_agent_has_no_session_attr():
    from omf.agent.llm import build_agent
    from omf.config import LlmSettings
    ctx, _ = _ctx()
    settings = LlmSettings("http://example", "sk-test", "model", "openai")
    agent = build_agent(ctx, settings)
    assert not hasattr(agent, "session")
    assert not hasattr(agent, "token_map")
    tools_src = " ".join(getattr(t, "__name__", str(t)) for t in (
        list_findings, get_finding, get_redacted_evidence, get_mitigation, submit_report,
    ))
    assert "token_map" not in tools_src


def test_run_analysis_retries_once(monkeypatch):
    from omf.agent.llm import build_agent, run_analysis
    from omf.config import LlmSettings

    ctx, _ = _ctx()
    settings = LlmSettings("http://example", "sk-test", "model", "openai")
    calls = {"n": 0}
    real_build = build_agent

    def wrapped(ctx, settings):
        agent = real_build(ctx, settings)

        async def fake_run(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("transient")
            submit_report(ctx, "# body")
            return type("Result", (), {"output": "# body"})()

        monkeypatch.setattr(agent, "run", fake_run)
        return agent

    monkeypatch.setattr("omf.agent.llm.build_agent", wrapped)
    out = run_analysis(ctx, settings)
    assert calls["n"] == 2
    assert out == "# body"


def test_run_analysis_raises_when_not_configured():
    import pytest
    from omf.agent.llm import LlmNotConfigured, run_analysis
    from omf.config import LlmSettings

    ctx, _ = _ctx()
    with pytest.raises(LlmNotConfigured):
        run_analysis(ctx, LlmSettings(None, None, None, "openai"))
