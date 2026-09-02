# tests/test_cli.py
from omf.cli import main


def test_help_exits_zero(capsys):
    assert main(["help"]) == 0
    out = capsys.readouterr().out
    assert "OH MY FORTRESS" in out
    assert "install" in out and "doctor" in out


def test_help_flags(capsys):
    assert main(["-h"]) == 0
    assert main(["--help"]) == 0


def test_unknown_exits_one(capsys):
    assert main(["audit"]) == 1
    assert "install" in capsys.readouterr().out


def test_default_calls_tui(monkeypatch):
    called = {"n": 0}

    def fake() -> int:
        called["n"] += 1
        return 0

    monkeypatch.setattr("omf.cli.run_tui", fake)
    assert main([]) == 0
    assert called["n"] == 1


def test_install_invokes_uv(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    seen = {}

    def fake_run(cmd, check):
        seen["cmd"] = cmd
        class R:
            returncode = 0
        return R()

    monkeypatch.setattr("omf.cli.subprocess.run", fake_run)
    assert main(["install"]) == 0
    assert seen["cmd"] == ["uv", "sync", "--all-extras", "--all-groups"]


def test_install_creates_env_from_example(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env.example").write_text("OMF_LLM_MODEL=\n", encoding="utf-8")

    def fake_run(cmd, check):
        class R:
            returncode = 0
        return R()

    monkeypatch.setattr("omf.cli.subprocess.run", fake_run)
    assert main(["install"]) == 0
    assert (tmp_path / ".env").read_text(encoding="utf-8") == "OMF_LLM_MODEL=\n"
    assert "created .env" in capsys.readouterr().out


def test_install_keeps_existing_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env.example").write_text("NEW=\n", encoding="utf-8")
    (tmp_path / ".env").write_text("OLD=\n", encoding="utf-8")

    def fake_run(cmd, check):
        class R:
            returncode = 0
        return R()

    monkeypatch.setattr("omf.cli.subprocess.run", fake_run)
    assert main(["install"]) == 0
    assert (tmp_path / ".env").read_text(encoding="utf-8") == "OLD=\n"


def test_doctor_dispatches(monkeypatch):
    monkeypatch.setattr("omf.cli.run_doctor", lambda: 7)
    assert main(["doctor"]) == 7


def test_debug_flag_starts_tui(monkeypatch):
    seen = {}
    monkeypatch.setattr("omf.cli.configure", lambda **kwargs: seen.update(kwargs))
    monkeypatch.setattr("omf.cli.run_tui", lambda: 0)
    assert main(["--debug"]) == 0
    assert seen == {"debug": True}


def test_v_flag_is_debug(monkeypatch):
    seen = {}
    monkeypatch.setattr("omf.cli.configure", lambda **kwargs: seen.update(kwargs))
    monkeypatch.setattr("omf.cli.run_doctor", lambda: 0)
    assert main(["-v", "doctor"]) == 0
    assert seen == {"debug": True}


def test_verbose_alias_is_debug(monkeypatch):
    seen = {}
    monkeypatch.setattr("omf.cli.configure", lambda **kwargs: seen.update(kwargs))
    monkeypatch.setattr("omf.cli.run_doctor", lambda: 0)
    assert main(["doctor", "--verbose"]) == 0
    assert seen == {"debug": True}
