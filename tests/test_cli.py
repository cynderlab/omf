# tests/test_cli.py
from omf.cli import main


def test_help_exits_zero(capsys):
    assert main(["help"]) == 0
    out = capsys.readouterr().out
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


def test_install_invokes_uv(monkeypatch):
    seen = {}

    def fake_run(cmd, check):
        seen["cmd"] = cmd
        class R:
            returncode = 0
        return R()

    monkeypatch.setattr("omf.cli.subprocess.run", fake_run)
    assert main(["install"]) == 0
    assert seen["cmd"] == ["uv", "sync", "--all-extras", "--all-groups"]


def test_doctor_dispatches(monkeypatch):
    monkeypatch.setattr("omf.cli.run_doctor", lambda: 7)
    assert main(["doctor"]) == 7
