from rich.console import Console

from omf.tui import _LiveState


def _text(state: _LiveState) -> str:
    console = Console(record=True, width=80, force_terminal=True)
    console.print(state)
    return console.export_text()


def test_llm_start_shows_narrative_panel():
    state = _LiveState({"FW-ADM-001": "No generic admin"})
    state.handle({
        "phase": "llm",
        "status": "start",
        "model": "accounts/fireworks/models/deepseek-v4-flash-0731",
    })
    assert state.phase == "llm"
    rendered = _text(state)
    assert "Writing narrative" in rendered
    assert "LLM UPLINK" not in rendered
    assert "SYN-ACK" not in rendered
    assert "thinking" in rendered
    assert "deepseek-v4-flash-0731" in rendered
    assert "accounts/fireworks/models/" not in rendered
    assert "no secrets on the wire" in rendered
    assert "0s" in rendered


def test_llm_tool_event_updates_narrative():
    state = _LiveState({"FW-ADM-001": "No generic admin"})
    state.handle({"phase": "llm", "status": "start", "model": "demo-model"})
    state.handle({
        "phase": "llm",
        "status": "tool",
        "tool": "get_finding",
        "check_id": "FW-ADM-001",
    })
    rendered = _text(state)
    assert "Writing narrative" in rendered
    assert "opening FW-ADM-001" in rendered
    assert "last: get_finding" in rendered


def test_llm_tool_labels():
    state = _LiveState({"FW-ADM-001": "x"})
    state.handle({"phase": "llm", "status": "start", "model": "m"})
    cases = (
        ({"tool": "list_findings"}, "reading findings"),
        ({"tool": "get_redacted_evidence", "capability": "users"}, "reading evidence: users"),
        ({"tool": "get_mitigation", "check_id": "FW-ADM-001"}, "looking up mitigation"),
        ({"tool": "submit_report"}, "submitting report"),
    )
    for extra, label in cases:
        state.handle({"phase": "llm", "status": "tool", **extra})
        assert label in _text(state)


def test_narrative_spinner_moves_with_clock():
    clock = [10.0]
    state = _LiveState({"FW-ADM-001": "x"}, now=lambda: clock[0])
    state.handle({"phase": "llm", "status": "start", "model": "m"})
    first = _text(state)
    clock[0] = 10.5
    second = _text(state)
    assert first != second
    assert "0s" in first
    assert "0s" in second


def test_llm_skipped_no_narrative_panel():
    state = _LiveState({"FW-ADM-001": "x"})
    state.handle({"phase": "llm", "status": "skipped", "detail": "LLM not configured"})
    rendered = _text(state)
    assert "Writing narrative" not in rendered
    assert "skeleton" in state.activity


def test_llm_fallback_keeps_error_detail():
    state = _LiveState({"FW-ADM-001": "x"})
    state.handle({
        "phase": "llm",
        "status": "fallback",
        "model": "demo-model",
        "detail": "ModelHTTPError: status_code: 404",
    })
    assert state.llm_status == "fallback"
    assert "ModelHTTPError" in state.llm_detail
    assert "Writing narrative" not in _text(state)
