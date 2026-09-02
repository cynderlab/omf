from pathlib import Path

from rich.console import Console

from omf.config import UserPrefs
from omf.tui import (
    _LiveState,
    _print_results,
    _prompt_report_mode,
    _prompt_session,
    _severity_cell,
)


def test_prompt_session_does_not_ask_tls_and_defaults_off(monkeypatch):
    confirms: list[str] = []

    def fake_select(label, options, default=None, **kwargs):
        if "Vendor" in label:
            return "mikrotik"
        if "language" in label.lower():
            return "ca"
        if "Report" in label:
            return "llm"
        raise AssertionError(f"unexpected select: {label}")

    monkeypatch.setattr("omf.tui.select_value", fake_select)
    monkeypatch.setattr(
        "omf.tui._ask_reachable_url",
        lambda console, default, label="Device URL": "https://192.0.2.1",
    )
    monkeypatch.setattr(
        "omf.tui._prompt_credentials",
        lambda *args, **kwargs: {"username": "admin", "password": "x", "token": ""},
    )
    monkeypatch.setattr(
        "omf.tui.confirm",
        lambda prompt, default=False: confirms.append(prompt) or False,
    )

    prefs = UserPrefs(True, 1, "ca", "mikrotik", "https://192.0.2.1", "admin")
    session, skip_llm = _prompt_session(
        Console(quiet=True), prefs, llm_configured=True
    )
    assert session.verify_tls is False
    assert skip_llm is False
    assert confirms == []


def test_prompt_report_mode_defaults_to_eval_when_llm_missing():
    assert _prompt_report_mode(llm_configured=False, ask=lambda: "eval") is True


def test_prompt_report_mode_defaults_argument_when_llm_configured(monkeypatch):
    seen = {}

    def fake_select(message, options, default=None, *, ask=None):
        seen["default"] = default
        return "llm"

    monkeypatch.setattr("omf.tui.select_value", fake_select)
    assert _prompt_report_mode(llm_configured=True) is False
    assert seen["default"] == "llm"


def test_prompt_report_mode_defaults_eval_when_unconfigured(monkeypatch):
    seen = {}

    def fake_select(message, options, default=None, *, ask=None):
        seen["default"] = default
        seen["message"] = message
        return "eval"

    monkeypatch.setattr("omf.tui.select_value", fake_select)
    assert _prompt_report_mode(llm_configured=False) is True
    assert seen["default"] == "eval"
    assert seen["message"] == "Report"


def test_prompt_report_mode_prefers_saved_choice(monkeypatch):
    seen = {}

    def fake_select(message, options, default=None, *, ask=None):
        seen["default"] = default
        return "eval"

    monkeypatch.setattr("omf.tui.select_value", fake_select)
    assert _prompt_report_mode(llm_configured=True, last_report_mode="eval") is True
    assert seen["default"] == "eval"


def test_prompt_session_returns_skip_llm(monkeypatch):
    def fake_select(label, options, default=None, **kwargs):
        if "Vendor" in label:
            return "mikrotik"
        if "language" in label.lower():
            raise AssertionError("evaluation only must not ask report language")
        if "Report" in label:
            return "eval"
        raise AssertionError(f"unexpected select: {label}")

    monkeypatch.setattr("omf.tui.select_value", fake_select)
    monkeypatch.setattr(
        "omf.tui._ask_reachable_url",
        lambda console, default, label="Device URL": "https://192.0.2.1",
    )
    monkeypatch.setattr(
        "omf.tui._prompt_credentials",
        lambda *args, **kwargs: {"username": "admin", "password": "x", "token": ""},
    )
    prefs = UserPrefs(True, 1, "es", "mikrotik", "https://192.0.2.1", "admin")
    session, skip_llm = _prompt_session(
        Console(quiet=True), prefs, llm_configured=False
    )
    assert session.vendor == "mikrotik"
    assert skip_llm is True
    assert session.report_language == "en"


def test_prompt_session_asks_language_only_for_llm_narrative(monkeypatch):
    seen: list[str] = []

    def fake_select(label, options, default=None, **kwargs):
        seen.append(label)
        if label == "Vendor":
            return "mikrotik"
        if label == "Report":
            return "llm"
        if label == "Report language":
            return "en"
        raise AssertionError(f"unexpected select: {label}")

    monkeypatch.setattr("omf.tui.select_value", fake_select)
    monkeypatch.setattr(
        "omf.tui._ask_reachable_url",
        lambda console, default, label="Device URL": "https://192.0.2.1",
    )
    monkeypatch.setattr(
        "omf.tui._prompt_credentials",
        lambda *args, **kwargs: {"username": "admin", "password": "x", "token": ""},
    )
    prefs = UserPrefs(True, 1, "ca", "mikrotik", "https://192.0.2.1", "admin")
    session, skip_llm = _prompt_session(
        Console(quiet=True), prefs, llm_configured=True
    )
    assert skip_llm is False
    assert session.report_language == "en"
    assert seen == ["Vendor", "Report", "Report language"]


def test_print_results_evaluation_only_narrative_line(tmp_path: Path):
    state = _LiveState({"FW-ADM-001": "No generic admin"})
    state.handle({
        "phase": "eval",
        "check_id": "FW-ADM-001",
        "status": "fail",
        "severity": "high",
        "diagnostic": "default admin present",
    })
    state.handle({"phase": "llm", "status": "skipped", "detail": "evaluation only"})
    console = Console(record=True, width=80, force_terminal=True)
    _print_results(console, state, tmp_path / "report.html")
    text = console.export_text()
    assert "FAIL 1" in text
    assert "Findings" in text
    assert "Narrative: evaluation only" in text
    assert "report.html" in text


def _fail(state: _LiveState, check_id: str, severity: str) -> None:
    state.handle({
        "phase": "eval",
        "check_id": check_id,
        "status": "fail",
        "severity": severity,
        "diagnostic": f"{severity} why",
    })


def test_print_results_orders_findings_highest_severity_first(tmp_path: Path):
    state = _LiveState({
        "FW-LOW": "Low check",
        "FW-INFO": "Info check",
        "FW-HIGH": "High check",
        "FW-MED": "Medium check",
    })
    _fail(state, "FW-LOW", "low")
    _fail(state, "FW-INFO", "info")
    _fail(state, "FW-HIGH", "high")
    _fail(state, "FW-MED", "medium")
    console = Console(record=True, width=80, force_terminal=True)
    _print_results(console, state, tmp_path / "report.html")
    text = console.export_text()
    assert text.index("High check") < text.index("Medium check")
    assert text.index("Medium check") < text.index("Low check")
    assert text.index("Low check") < text.index("Info check")


def test_print_results_same_severity_orders_by_check_id(tmp_path: Path):
    state = _LiveState({
        "FW-B": "Check B",
        "FW-A": "Check A",
    })
    _fail(state, "FW-B", "high")
    _fail(state, "FW-A", "high")
    console = Console(record=True, width=80, force_terminal=True)
    _print_results(console, state, tmp_path / "report.html")
    text = console.export_text()
    assert text.index("Check A") < text.index("Check B")


def test_severity_cell_styles_match_palette():
    high = _severity_cell("high")
    assert high.plain == "high"
    assert str(high.style) == "bold red"
    medium = _severity_cell("medium")
    assert medium.plain == "medium"
    assert str(medium.style) == "bold dark_orange"
    low = _severity_cell("low")
    assert low.plain == "low"
    assert str(low.style) == "yellow"
    info = _severity_cell("info")
    assert info.plain == "info"
    assert str(info.style) == "dim"
    missing = _severity_cell("")
    assert missing.plain == "—"
    assert str(missing.style) == "dim"
