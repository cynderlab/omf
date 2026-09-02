from rich.console import Console
from rich.live import Live

from omf.tui import _LiveState


def _text(state: _LiveState) -> str:
    console = Console(record=True, width=80, force_terminal=True)
    console.print(state)
    return console.export_text()


def _many_titles(n: int = 41) -> dict[str, str]:
    return {f"FW-{i:03d}": f"Fortinet check {i:03d}" for i in range(n)}


def _eval_all(state: _LiveState, titles: dict[str, str]) -> None:
    for check_id in titles:
        state.handle({
            "phase": "eval",
            "check_id": check_id,
            "status": "pass",
            "severity": "low",
            "diagnostic": "ok",
        })


def _live_text(state: _LiveState, *, height: int = 20) -> str:
    console = Console(record=True, width=80, height=height, force_terminal=True)
    with Live(state, console=console, auto_refresh=False, vertical_overflow="ellipsis"):
        pass
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
    assert "evaluation only" not in state.activity


def test_llm_skipped_evaluation_only_copy():
    state = _LiveState({"FW-ADM-001": "x"})
    state.handle({"phase": "llm", "status": "skipped", "detail": "evaluation only"})
    rendered = _text(state)
    assert "Writing narrative" not in rendered
    assert "evaluation only" in state.activity
    assert "no LLM configured" not in state.activity


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


def test_llm_panel_survives_short_terminal_with_many_checks():
    titles = _many_titles()
    state = _LiveState(titles)
    _eval_all(state, titles)
    state.handle({"phase": "llm", "status": "start", "model": "demo-model"})
    rendered = _live_text(state, height=20)
    assert "Writing narrative" in rendered
    assert "thinking" in rendered
    assert "demo-model" in rendered
    assert "no secrets on the wire" in rendered
    assert "Fortinet check" not in rendered
    assert "PASS 41" in rendered


def test_eval_keeps_check_table_with_many_checks():
    titles = _many_titles()
    state = _LiveState(titles)
    state.handle({
        "phase": "eval",
        "check_id": "FW-000",
        "status": "fail",
        "severity": "high",
        "diagnostic": "x",
    })
    rendered = _text(state)
    assert "Fortinet check 000" in rendered
    assert "Fortinet check 040" in rendered
    assert "Writing narrative" not in rendered
    assert "FAIL" in rendered


def test_post_eval_phases_drop_table_so_banner_fits():
    titles = _many_titles()
    state = _LiveState(titles)
    _eval_all(state, titles)
    state.handle({"phase": "redact"})
    redacted = _text(state)
    assert "Fortinet check" not in redacted
    assert "PASS 41" in redacted
    assert "Redacting" in redacted
    state.handle({"phase": "report"})
    assert "Fortinet check" not in _text(state)
