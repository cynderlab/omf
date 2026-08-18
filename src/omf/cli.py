"""CLI dispatch: default TUI, install, doctor, help. Flags: -v/--debug."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from omf.log import configure

HELP = """OH MY FIREWALL

Usage:
  omf              Start the audit TUI
  omf install      Sync dependencies and create .env from .env.example if missing
  omf doctor       Check what is missing (no firewall connection)
  omf help         Show this help

Flags:
  -v, --debug      DEBUG logs on stderr (HTTP URLs, phases; no secrets)
"""


def ensure_dotenv(root: Path) -> str:
    dest = root / ".env"
    example = root / ".env.example"
    if dest.exists():
        return "kept existing .env"
    if not example.is_file():
        return "no .env.example found"
    dest.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
    return "created .env from .env.example"


def run_tui() -> int:
    from omf.tui import run
    return run()


def run_doctor() -> int:
    from omf.doctor import run
    return run()


def _parse(argv: list[str]) -> tuple[str | None, bool]:
    debug = False
    command: str | None = None
    for arg in argv:
        if arg in {"-v", "--verbose", "--debug"}:
            debug = True
            continue
        if arg in {"help", "-h", "--help"}:
            return "help", debug
        if command is None:
            command = arg
            continue
        return "help", debug
    return command, debug


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    command, debug = _parse(args)
    configure(debug=debug)
    if command is None:
        return run_tui()
    if command == "help":
        print(HELP, end="")
        return 0
    if command == "install":
        completed = subprocess.run(
            ["uv", "sync", "--all-extras", "--all-groups"],
            check=False,
        )
        print(ensure_dotenv(Path.cwd()))
        return int(completed.returncode)
    if command == "doctor":
        return run_doctor()
    print(HELP, end="")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
