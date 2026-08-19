from types import SimpleNamespace

from omf.agent.trace import LlmSpanProcessor, format_transcript, span_to_event


def test_span_to_event_end_has_name_and_ms():
    span = SimpleNamespace(
        name="execute_tool list_findings",
        start_time=1_000_000_000,
        end_time=1_012_000_000,
        attributes={"gen_ai.tool.name": "list_findings"},
    )
    event = span_to_event(span, ended=True)
    assert event["phase"] == "llm"
    assert event["status"] == "span"
    assert "execute_tool list_findings" in event["name"]
    assert event["ms"] == 12
    assert "list_findings" in event["name"]
    blob = str(event)
    assert "authorization" not in blob.lower()
    assert "api_key" not in blob.lower()


def test_span_processor_emits_start_then_end():
    seen: list[dict] = []
    processor = LlmSpanProcessor(seen.append)
    span = SimpleNamespace(
        name="chat demo-model",
        start_time=0,
        end_time=2_000_000_000,
        attributes={"gen_ai.request.model": "accounts/fireworks/models/demo-model"},
    )
    processor.on_start(span)
    processor.on_end(span)
    assert [event["state"] for event in seen] == ["start", "end"]
    assert seen[0].get("ms") is None
    assert seen[1]["ms"] == 2000
    assert "demo-model" in seen[1]["name"]
    assert "accounts/fireworks" not in seen[1]["name"]


def test_format_transcript_shows_ask_and_strips_secret():
    from pydantic_ai.messages import (
        ModelRequest,
        ModelResponse,
        SystemPromptPart,
        ToolCallPart,
        ToolReturnPart,
        UserPromptPart,
    )

    secret = "sk-live-secret-key"
    messages = [
        ModelRequest(parts=[
            SystemPromptPart(content=f"Write the report. key={secret}"),
            UserPromptPart(content="Write the firewall audit report using only the tools."),
        ]),
        ModelResponse(parts=[ToolCallPart("list_findings", {})]),
        ModelRequest(parts=[
            ToolReturnPart(
                "list_findings",
                [{"check_id": "FW-ADM-001", "status": "fail"}],
                tool_call_id="call-1",
            ),
        ]),
    ]
    text = format_transcript(messages, secret=secret)
    assert "Write the firewall audit report using only the tools." in text
    assert "list_findings" in text
    assert "FW-ADM-001" in text
    assert secret not in text
    assert "[STRIPPED]" in text
    assert "Authorization" not in text


def test_run_analysis_debug_dumps_what_we_ask(monkeypatch, capsys):
    from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart

    from omf.agent.llm import build_agent, run_analysis
    from omf.agent.tools import AnalysisContext
    from omf.baseline.loader import load_catalog
    from omf.config import LlmSettings
    from omf.log import configure

    def capture_model(messages, info):
        if not any(isinstance(message, ModelResponse) for message in messages):
            return ModelResponse(parts=[
                ToolCallPart("list_findings", {}),
                ToolCallPart("submit_report", {"markdown": "# body"}),
            ])
        return ModelResponse(parts=[TextPart("ok")])

    real_build = build_agent

    def wrapped(ctx_arg, settings, on_tool=None):
        return real_build(ctx_arg, settings, on_tool=on_tool)

    from pydantic_ai.models.function import FunctionModel
    monkeypatch.setattr("omf.agent.llm._model_for", lambda settings: FunctionModel(capture_model))
    monkeypatch.setattr("omf.agent.llm.build_agent", wrapped)

    ctx = AnalysisContext([], {}, load_catalog(), "mikrotik", "ca", [])
    configure(debug=True)
    try:
        run_analysis(
            ctx,
            LlmSettings("http://llm.example", "sk-live-secret-key", "model", "openai"),
            on_event=lambda event: None,
        )
    finally:
        configure()
    err = capsys.readouterr().err
    assert "LLM transcript" in err
    assert "Write the firewall audit report using only the tools." in err
    assert "list_findings" in err
    assert "sk-live-secret-key" not in err
    assert "Write the firewall audit report using only the tools." in ctx.transcript
    assert "fail findings only" in ctx.transcript
    assert "sk-live-secret-key" not in ctx.transcript
