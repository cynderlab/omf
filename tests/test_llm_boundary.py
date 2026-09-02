import inspect
import json

from omf.agent.tools import (
    AnalysisContext,
    fail_pack,
    status_counts,
)
from omf.baseline.loader import CheckDef, load_catalog
from omf.config import LlmSettings
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
    return AnalysisContext(findings, load_catalog(), "mikrotik", "ca"), r


def _settings(*, key="sk-test", style="openai", url="http://llm.example.invalid"):
    return LlmSettings(url, key, "model", style)


def _narrative_json(
    *,
    check_id: str = "FW-ADM-001",
    title: str = "Default admin",
    description: str = "admin remains",
    summary: str = "one paragraph",
) -> str:
    return json.dumps({
        "executive_summary": summary,
        "vulnerabilities": [
            {"check_id": check_id, "title": title, "description": description},
        ],
    })


def _patch_complete(monkeypatch, fake):
    from omf.agent import llm as llm_mod

    assert callable(llm_mod._complete)
    monkeypatch.setattr(llm_mod, "_complete", fake)


def test_fail_pack_caps_long_observed_lists():
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
        load_catalog("fortinet"),
        "fortinet",
        "en",
    )
    finding = fail_pack(ctx)[0]
    listed = finding["observed"]["policies"]
    assert len(listed) == 12
    assert finding["observed"]["policies_total"] == 40
    assert finding["observed"]["policies_truncated"] is True
    blob = json.dumps(finding)
    assert '"id": "30"' not in blob
    assert "mitigation" not in finding


def test_fail_pack_returns_redacted_only():
    ctx, r = _ctx()
    pack = fail_pack(ctx)
    blob = json.dumps(pack)
    assert "token_map" not in blob
    assert "password" not in blob
    assert "192." not in blob
    dumped = json.dumps(r.token_map())
    assert dumped not in blob
    assert "mitigation" not in pack[0]


def test_fail_pack_includes_catalog_description():
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
        (check,),
        "fortinet",
        "en",
    )
    finding = fail_pack(ctx)[0]
    assert finding["description"] == "The factory FortiOS administrator is named admin."
    assert finding["diagnostic"] == "enabled user matches vendor default name 'admin'"
    assert finding["observed"] == {"names": ["admin"]}
    assert "mitigation" not in finding


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
        load_catalog("fortinet"),
        "fortinet",
        "en",
    )
    pack = fail_pack(ctx)
    assert [row["check_id"] for row in pack] == ["FW-POL-001", "FW-LIC-012"]
    assert pack[1]["severity"] == "low"
    assert len(pack[0]["observed"]["policies"]) == 12
    assert pack[0]["observed"]["policies_total"] == 40
    assert "mitigation" not in pack[0]
    assert "description" in pack[0] and pack[0]["description"]
    assert status_counts(ctx) == {"fail": 2, "pass": 1, "error": 0, "skipped": 0}


def test_no_function_tool_helpers():
    import omf.agent.tools as tools

    assert not hasattr(tools, "make_tools")
    assert not hasattr(tools, "list_findings")
    assert not hasattr(tools, "get_redacted_evidence")
    assert not hasattr(tools, "submit_report")
    assert not hasattr(tools, "get_finding")
    assert not hasattr(tools, "get_mitigation")


def test_run_analysis_has_no_session_or_token_map_params():
    from omf.agent.llm import run_analysis
    import omf.agent.llm as llm_mod

    names = inspect.signature(run_analysis).parameters
    assert "session" not in names
    assert "token_map" not in names
    assert not hasattr(llm_mod, "build_agent")


def test_run_analysis_calls_complete_once(monkeypatch):
    from omf.agent.llm import run_analysis

    ctx, _ = _ctx()
    captured: list[dict] = []

    def fake(settings, system, user):
        captured.append({"settings": settings, "system": system, "user": user})
        return _narrative_json()

    _patch_complete(monkeypatch, fake)
    out = run_analysis(ctx, _settings())
    assert len(captured) == 1
    assert captured[0]["settings"].model == "model"
    assert "Write the audit narrative" in captured[0]["user"]
    assert "FW-ADM-001" in captured[0]["user"]
    assert "language code: ca" in captured[0]["system"]
    assert "one paragraph" in out
    assert "### FW-ADM-001" in out


def test_run_analysis_retries_once(monkeypatch):
    from omf.agent.llm import run_analysis

    ctx, _ = _ctx()
    calls = {"n": 0}

    def fake(settings, system, user):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient")
        return _narrative_json(summary="retry ok")

    _patch_complete(monkeypatch, fake)
    out = run_analysis(ctx, _settings())
    assert calls["n"] == 2
    assert "retry ok" in out
    assert "### FW-ADM-001" in out


def test_run_analysis_raises_after_retry(monkeypatch):
    import pytest
    from omf.agent.llm import run_analysis

    ctx, _ = _ctx()
    calls = {"n": 0}

    def fake(settings, system, user):
        calls["n"] += 1
        raise RuntimeError("down")

    _patch_complete(monkeypatch, fake)
    with pytest.raises(RuntimeError, match="down"):
        run_analysis(ctx, _settings())
    assert calls["n"] == 2


def test_run_analysis_refuses_leaking_payload(monkeypatch):
    import pytest
    from omf.agent.llm import LlmPayloadLeak, run_analysis

    calls = {"n": 0}

    def fake(settings, system, user):
        calls["n"] += 1
        raise AssertionError("model must not be called")

    _patch_complete(monkeypatch, fake)
    ctx = AnalysisContext(
        [{
            "check_id": "FW-ADM-001",
            "status": "fail",
            "severity": "high",
            "diagnostic": "peer 10.0.0.5",
            "observed": {},
        }],
        load_catalog(),
        "mikrotik",
        "ca",
    )
    with pytest.raises(LlmPayloadLeak, match="10.0.0.5"):
        run_analysis(ctx, _settings())
    assert calls["n"] == 0


def test_run_analysis_allows_catalog_policy_tokens(monkeypatch):
    from omf.agent.llm import run_analysis

    captured: list[dict] = []

    def fake(settings, system, user):
        captured.append({"system": system, "user": user})
        return _narrative_json(
            check_id="FW-SVC-002",
            title="Listen scope",
            description="management is unrestricted",
        )

    _patch_complete(monkeypatch, fake)
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
        load_catalog("mikrotik"),
        "mikrotik",
        "ca",
    )
    out = run_analysis(ctx, _settings())
    assert "### FW-SVC-002" in out
    assert "### FW-LOG-002" in out
    blob = json.dumps(captured)
    assert "0.0.0.0/0" in blob
    assert "::/0" in blob
    assert "10.0.0.5" not in blob


def test_run_analysis_allows_fortinet_catalog_anycast(monkeypatch):
    from omf.agent.llm import run_analysis

    captured: list[dict] = []

    def fake(settings, system, user):
        captured.append({"user": user})
        return _narrative_json(check_id="FW-DNS-001", title="DNS", description="factory resolvers")

    _patch_complete(monkeypatch, fake)
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
        load_catalog("fortinet"),
        "fortinet",
        "en",
    )
    out = run_analysis(ctx, _settings())
    assert "### FW-DNS-001" in out
    blob = json.dumps(captured)
    assert "96.45.45.45" in blob
    assert "96.45.46.46" in blob


def test_run_analysis_raises_when_not_configured():
    import pytest
    from omf.agent.llm import LlmNotConfigured, run_analysis

    ctx, _ = _ctx()
    with pytest.raises(LlmNotConfigured):
        run_analysis(ctx, LlmSettings(None, None, None, "openai"))


def test_run_analysis_request_body_excludes_secrets(monkeypatch):
    from omf.agent.llm import run_analysis

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
    ctx = AnalysisContext(findings, load_catalog(), "mikrotik", "ca")
    token_map = redactor.token_map()
    captured: list[dict] = []

    def fake(settings, system, user):
        captured.append({"system": system, "user": user})
        return _narrative_json()

    _patch_complete(monkeypatch, fake)
    out = run_analysis(ctx, _settings(key=api_key))
    assert "one paragraph" in out
    assert "### FW-ADM-001" in out
    assert len(captured) == 1
    assert not hasattr(ctx, "session")
    assert not hasattr(ctx, "token_map")
    assert not hasattr(ctx, "url")
    blob = json.dumps(captured)
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
    from omf.agent.llm import run_analysis

    redactor = Redactor()
    redactor.redact_obj({"users": [{"name": "reader"}], "hostname": "home-fw"})
    findings = [redactor.apply_known(redactor.redact_obj({
        "check_id": "FW-ADM-002",
        "status": "fail",
        "severity": "medium",
        "diagnostic": "users missing inactivity logout/lock ['admin', 'reader']",
        "observed": {"names": ["admin", "reader"], "hostname": "home-fw"},
    }))]
    ctx = AnalysisContext(findings, load_catalog(), "mikrotik", "ca")
    captured: list[dict] = []

    def fake(settings, system, user):
        captured.append({"system": system, "user": user})
        return _narrative_json(check_id="FW-ADM-002", title="Idle timeout", description="idle")

    _patch_complete(monkeypatch, fake)
    out = run_analysis(ctx, _settings())
    assert "### FW-ADM-002" in out
    assert len(captured) == 1
    blob = json.dumps(captured)
    assert "home-fw" not in blob
    assert "reader" not in blob
    assert "[HOST_" in blob
    assert "[USER_" in blob
    assert "list_findings" not in blob


def test_run_analysis_one_request_no_tool_events(monkeypatch):
    from omf.agent.llm import run_analysis

    ctx, _ = _ctx()
    events: list[dict] = []
    captured: list[object] = []

    def fake(settings, system, user):
        captured.append(user)
        return _narrative_json()

    _patch_complete(monkeypatch, fake)
    out = run_analysis(ctx, _settings(), on_event=events.append)
    assert "one paragraph" in out
    assert "### FW-ADM-001" in out
    assert len(captured) == 1
    assert not any(event.get("status") in {"tool", "span"} for event in events)
    assert all(event.get("phase") == "llm" for event in events)


def test_run_analysis_transcript_strips_api_key(monkeypatch):
    from omf.agent.llm import run_analysis

    ctx, _ = _ctx()
    api_key = "sk-live-secret-key"

    def fake(settings, system, user):
        return _narrative_json(summary=f"used {api_key}")

    _patch_complete(monkeypatch, fake)
    run_analysis(ctx, _settings(key=api_key))
    assert api_key not in ctx.transcript
    assert "[STRIPPED]" in ctx.transcript
    assert "Write the audit narrative" in ctx.transcript
    assert "Every fail in the pack" in ctx.transcript
    assert "Authorization" not in ctx.transcript


class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


class _FakeClient:
    def __init__(self, *args, **kwargs) -> None:
        self.args = args
        self.kwargs = kwargs
        self.posts: list[dict] = []
        self.response_payload: dict = {}

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        return None

    def post(self, url, *, headers=None, json=None):
        self.posts.append({"url": url, "headers": headers, "json": json})
        return _FakeResponse(self.response_payload)


def _install_client(monkeypatch, payload: dict) -> _FakeClient:
    client = _FakeClient()
    client.response_payload = payload

    def factory(*args, **kwargs):
        client.args = args
        client.kwargs = kwargs
        return client

    monkeypatch.setattr("omf.agent.llm.httpx.Client", factory)
    return client


def test_complete_openai_appends_chat_completions(monkeypatch):
    from omf.agent.llm import _LLM_TIMEOUT, _complete

    body = _narrative_json()
    client = _install_client(monkeypatch, {
        "choices": [{"message": {"content": body}}],
    })
    out = _complete(_settings(url="http://llm.example.invalid/v1"), "sys", "user")
    assert out == body
    assert client.posts[0]["url"] == "http://llm.example.invalid/v1/chat/completions"
    assert client.posts[0]["headers"]["Authorization"] == "Bearer sk-test"
    assert client.posts[0]["json"]["response_format"] == {"type": "json_object"}
    assert client.posts[0]["json"]["messages"][0] == {"role": "system", "content": "sys"}
    assert client.kwargs["timeout"] is _LLM_TIMEOUT
    assert client.kwargs["trust_env"] is False


def test_complete_openai_does_not_double_append(monkeypatch):
    from omf.agent.llm import _complete

    body = _narrative_json()
    client = _install_client(monkeypatch, {
        "choices": [{"message": {"content": body}}],
    })
    _complete(
        _settings(url="http://llm.example.invalid/chat/completions"),
        "sys",
        "user",
    )
    assert client.posts[0]["url"] == "http://llm.example.invalid/chat/completions"


def test_complete_anthropic_appends_v1_messages(monkeypatch):
    from omf.agent.llm import _complete

    body = _narrative_json()
    client = _install_client(monkeypatch, {
        "content": [{"text": body}],
    })
    out = _complete(
        _settings(style="anthropic", url="http://llm.example.invalid"),
        "sys",
        "user",
    )
    assert out == body
    assert client.posts[0]["url"] == "http://llm.example.invalid/v1/messages"
    headers = client.posts[0]["headers"]
    assert headers["x-api-key"] == "sk-test"
    assert headers["anthropic-version"] == "2023-06-01"
    assert "Authorization" not in headers
    payload = client.posts[0]["json"]
    assert payload["max_tokens"] == 8192
    assert payload["system"] == "sys"
    assert payload["messages"] == [{"role": "user", "content": "user"}]


def test_complete_anthropic_does_not_double_append(monkeypatch):
    from omf.agent.llm import _complete

    body = _narrative_json()
    client = _install_client(monkeypatch, {
        "content": [{"text": body}],
    })
    _complete(
        _settings(style="anthropic", url="http://llm.example.invalid/v1/messages/"),
        "sys",
        "user",
    )
    assert client.posts[0]["url"] == "http://llm.example.invalid/v1/messages"
