from rich.console import Console

from omf.config import UserPrefs
from omf.tui import _prompt_session


def test_prompt_session_does_not_ask_tls_and_defaults_off(monkeypatch):
    confirms: list[str] = []

    def fake_select(label, options, default=None):
        if "Vendor" in label:
            return "mikrotik"
        if "language" in label.lower():
            return "ca"
        raise AssertionError(f"unexpected select: {label}")

    monkeypatch.setattr("omf.tui.select_value", fake_select)
    monkeypatch.setattr(
        "omf.tui._ask_reachable_url",
        lambda console, default: "https://192.0.2.1",
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
    session = _prompt_session(Console(quiet=True), prefs)
    assert session.verify_tls is False
    assert confirms == []
