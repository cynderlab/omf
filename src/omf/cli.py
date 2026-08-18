# src/omf/cli.py
from __future__ import annotations

import subprocess
import sys

HELP = """OH MY FIREWALL

Usage:
  omf              Start the audit TUI
  omf install      Sync all project dependencies with uv
  omf doctor       Check what is missing (no firewall connection)
  omf help         Show this help
"""


def run_tui() -> int:
    from omf.tui import run
    return run()


def run_doctor() -> int:
    from omf.doctor import run
    return run()


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        return run_tui()
    cmd = args[0]
    if cmd in {"help", "-h", "--help"}:
        print(HELP, end="")
        return 0
    if cmd == "install":
        completed = subprocess.run(
            ["uv", "sync", "--all-extras", "--all-groups"],
            check=False,
        )
        return int(completed.returncode)
    if cmd == "doctor":
        return run_doctor()
    print(HELP, end="")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
