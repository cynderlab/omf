# src/omf/doctor.py
from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Callable, Mapping


def run_doctor_checks(
    *,
    env: Mapping[str, str],
    which_uv: Callable[[], str | None],
    python_version: tuple[int, int],
    try_import: Callable[[], bool],
    env_file_exists: bool,
) -> tuple[int, list[str]]:
    lines: list[str] = []
    required_failed = False

    def req(name: str, ok: bool, detail: str = "") -> None:
        nonlocal required_failed
        if ok:
            lines.append(f"OK       {name}" + (f"  {detail}" if detail else ""))
        else:
            required_failed = True
            lines.append(f"MISSING  {name}" + (f"  {detail}" if detail else ""))

    def warn(name: str, ok: bool, detail: str = "") -> None:
        if ok:
            lines.append(f"OK       {name}" + (f"  {detail}" if detail else ""))
        else:
            lines.append(f"WARN     {name}" + (f"  {detail}" if detail else ""))

    uv = which_uv()
    req("uv", uv is not None, uv or "")
    req("python", python_version >= (3, 12), f"{python_version[0]}.{python_version[1]}")
    req("deps", try_import(), "import omf")
    warn("env-file", env_file_exists)
    warn("OMF_LLM_BASE_URL", bool(env.get("OMF_LLM_BASE_URL", "").strip()))
    key = env.get("OMF_LLM_API_KEY", "").strip()
    warn("OMF_LLM_API_KEY", bool(key), "set" if key else "missing")
    warn("OMF_LLM_MODEL", bool(env.get("OMF_LLM_MODEL", "").strip()))
    style = env.get("OMF_LLM_API_STYLE", "").strip()
    warn(
        "OMF_LLM_API_STYLE",
        style == "" or style in {"openai", "anthropic"},
        style or "default=openai",
    )
    return (1 if required_failed else 0, lines)


def run() -> int:
    from pathlib import Path

    cwd = Path.cwd()
    home = Path.home() / ".config" / "omf"
    env_file_exists = (cwd / ".env").is_file() or (home / ".env").is_file()
    try:
        import omf  # noqa: F401

        imported = True
    except ImportError:
        imported = False
    code, lines = run_doctor_checks(
        env=os.environ,
        which_uv=lambda: shutil.which("uv"),
        python_version=sys.version_info[:2],
        try_import=lambda: imported,
        env_file_exists=env_file_exists,
    )
    for line in lines:
        print(line)
    return code
