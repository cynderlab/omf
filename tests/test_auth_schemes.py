import pytest

from omf.adapters.auth import auth_schemes, scheme_by_id


def test_mikrotik_is_basic_only_no_token():
    schemes = auth_schemes("mikrotik")
    assert len(schemes) == 1
    assert schemes[0].id == "basic"
    assert schemes[0].fields == ("username", "password")
    assert "token" not in schemes[0].fields


def test_fortinet_offers_token_or_session():
    ids = {scheme.id: scheme.fields for scheme in auth_schemes("fortinet")}
    assert ids["token"] == ("token",)
    assert ids["session"] == ("username", "password")


def test_unknown_vendor():
    with pytest.raises(ValueError, match="unknown vendor"):
        auth_schemes("paloalto")


def test_scheme_by_id():
    assert scheme_by_id("mikrotik", "basic").id == "basic"
    with pytest.raises(ValueError, match="unknown auth scheme"):
        scheme_by_id("mikrotik", "token")


def test_mikrotik_prompt_skips_token(monkeypatch):
    asked: list[str] = []

    def fake_ask(label, **kwargs):
        asked.append(label)
        return "x"

    monkeypatch.setattr("omf.tui.Prompt.ask", fake_ask)
    from omf.tui import _prompt_credentials

    creds = _prompt_credentials(scheme_by_id("mikrotik", "basic"))
    assert asked == ["Username", "Password"]
    assert creds["token"] == ""


def test_fortinet_token_prompt_skips_password(monkeypatch):
    asked: list[str] = []

    def fake_ask(label, **kwargs):
        asked.append(label)
        return "tok"

    monkeypatch.setattr("omf.tui.Prompt.ask", fake_ask)
    from omf.tui import _prompt_credentials

    creds = _prompt_credentials(scheme_by_id("fortinet", "token"))
    assert asked == ["API token"]
    assert creds["username"] == ""
    assert creds["password"] == ""
    assert creds["token"] == "tok"
