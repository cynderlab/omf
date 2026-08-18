# tests/test_launcher.py
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def test_launcher_help_exits_zero_without_venv():
    result = subprocess.run(
        ["bash", str(ROOT / "omf"), "help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    out = result.stdout
    assert "./omf" in out
    assert "install" in out
    assert "doctor" in out
    assert "help" in out


def test_launcher_unknown_arg_exits_one_and_prints_help():
    result = subprocess.run(
        ["bash", str(ROOT / "omf"), "audit"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "install" in result.stdout


def test_launcher_help_flags():
    for flag in ("-h", "--help"):
        result = subprocess.run(
            ["bash", str(ROOT / "omf"), flag],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, flag
