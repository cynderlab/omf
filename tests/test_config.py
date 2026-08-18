# tests/test_config.py
from pathlib import Path
from omf.config import (
    load_llm_settings,
    load_user_prefs,
    save_user_prefs,
    needs_disclaimer,
    UserPrefs,
)
from omf import DISCLAIMER_VERSION


def test_llm_prefers_cwd_env(tmp_path: Path):
    cwd = tmp_path / "proj"
    cfg = tmp_path / "cfg"
    cwd.mkdir(); cfg.mkdir()
    (cwd / ".env").write_text("OMF_LLM_MODEL=cwd-model\nOMF_LLM_API_KEY=k\nOMF_LLM_BASE_URL=http://x\n")
    (cfg / ".env").write_text("OMF_LLM_MODEL=home-model\n")
    s = load_llm_settings(cwd, cfg)
    assert s.model == "cwd-model"
    assert s.is_configured() is True
    assert s.api_style == "openai"


def test_llm_falls_back_to_config_dir(tmp_path: Path):
    cwd = tmp_path / "proj"
    cfg = tmp_path / "cfg"
    cwd.mkdir(); cfg.mkdir()
    (cfg / ".env").write_text(
        "OMF_LLM_MODEL=home\nOMF_LLM_API_KEY=k\nOMF_LLM_BASE_URL=http://x\nOMF_LLM_API_STYLE=anthropic\n"
    )
    s = load_llm_settings(cwd, cfg)
    assert s.model == "home"
    assert s.api_style == "anthropic"


def test_missing_llm_is_not_configured(tmp_path: Path):
    cwd = tmp_path / "p"; cfg = tmp_path / "c"
    cwd.mkdir(); cfg.mkdir()
    s = load_llm_settings(cwd, cfg)
    assert s.is_configured() is False


def test_broken_yaml_returns_defaults_and_rewrites(tmp_path: Path):
    cfg = tmp_path / "c"
    cfg.mkdir()
    (cfg / "config.yaml").write_text(": : not yaml [")
    prefs, warning = load_user_prefs(cfg)
    assert warning is not None
    assert prefs.disclaimer_accepted is False
    assert prefs.default_report_language == "ca"
    text = (cfg / "config.yaml").read_text()
    assert "disclaimer_accepted" in text


def test_roundtrip_prefs(tmp_path: Path):
    cfg = tmp_path / "c"
    cfg.mkdir()
    save_user_prefs(
        cfg,
        UserPrefs(
            True,
            DISCLAIMER_VERSION,
            "en",
            "fortinet",
            last_url="https://192.0.2.1",
            last_username="reader",
        ),
    )
    prefs, warning = load_user_prefs(cfg)
    assert warning is None
    assert prefs.last_vendor == "fortinet"
    assert prefs.last_url == "https://192.0.2.1"
    assert prefs.last_username == "reader"
    assert prefs.default_report_language == "en"
    assert needs_disclaimer(prefs) is False


def test_needs_disclaimer_when_version_stale():
    prefs = UserPrefs(True, DISCLAIMER_VERSION - 1 if DISCLAIMER_VERSION else 0, "ca", None)
    assert needs_disclaimer(prefs) is True


def test_remember_does_not_blank_saved_username(tmp_path, monkeypatch):
    from omf.session import Session
    from omf.tui import _remember_target

    monkeypatch.setattr("omf.tui._CONFIG_DIR", tmp_path)
    prefs = UserPrefs(True, 1, "ca", "mikrotik", last_url="http://192.168.1.1", last_username="reader")
    session = Session("mikrotik", "http://192.168.1.1", "", "", "", False, "ca")
    _remember_target(prefs, session)
    assert prefs.last_username == "reader"


def test_prefs_never_write_secrets(tmp_path: Path):
    cfg = tmp_path / "c"
    cfg.mkdir()
    save_user_prefs(
        cfg,
        UserPrefs(True, 1, "ca", "mikrotik", last_url="https://192.0.2.1", last_username="reader"),
    )
    text = (cfg / "config.yaml").read_text()
    assert "password" not in text
    assert "token" not in text
    assert "reader" in text
    assert "https://192.0.2.1" in text
