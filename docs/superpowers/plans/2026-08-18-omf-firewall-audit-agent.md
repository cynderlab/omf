# OMF Firewall Audit Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `./omf` so an auditor can install, doctor, and run a read-only MikroTik/Fortinet audit that writes `./audits/.../report.md` without ever sending URL, credentials, raw evidence, or `token_map` to an LLM.

**Architecture:** A POSIX launcher plus a Python package. A deterministic runner collects vendor capabilities through adapters, evaluates a YAML catalog with pure functions, redacts identifiers, then either a Pydantic AI agent (redacted tools only) or a skeleton writer produces Markdown. Firewall secrets stay in RAM.

**Tech Stack:** Python 3.12+, uv, pydantic v2, pydantic-ai, httpx, rich, pyyaml, python-dotenv, pytest.

**Spec:** `docs/superpowers/specs/2026-08-18-omf-firewall-audit-agent-design.md`

## Global Constraints

- Python 3.12+. Tooling is uv only. Entry point `./omf` / `omf`: default TUI; `install`; `doctor`; `help`.
- TUI language: English. Report language: `ca` | `es` | `en`.
- Username, password, API token: process memory only. Target URL on disk only in `report.md` header.
- LLM sees only redacted findings/evidence + catalog text. Never `raw/`, never `token_map.json`, never `.env`.
- Adapters are read-only (GET, plus FortiOS session login if no token). Evaluators import neither HTTP nor secrets.
- TLS verify on by default. No SSH, no PDF, no Textual, no Haystack, no LangGraph.
- Fourteen checks, nine capabilities, vendors `mikrotik` and `fortinet` only.
- CI has no live firewall.

## File map

| Path | Responsibility |
|---|---|
| `omf` | POSIX launcher: `help` / `install` / `doctor` / default TUI |
| `pyproject.toml` | package, console script `omf`, deps, pytest |
| `.env.example` | LLM var names, empty values |
| `.gitignore` | add `/audits/` |
| `src/omf/__init__.py` | `__version__`, `DISCLAIMER_VERSION`, `DISCLAIMER_TEXT` |
| `src/omf/__main__.py` | `python -m omf` |
| `src/omf/cli.py` | argv dispatch |
| `src/omf/doctor.py` | doctor checks |
| `src/omf/config.py` | `.env` + `config.yaml` |
| `src/omf/session.py` | RAM session + `clear_secrets` |
| `src/omf/wizard.py` | pure validators |
| `src/omf/tui.py` | Rich prompts + Live |
| `src/omf/schema/evidence.py` | `Evidence`, `CheckResult` |
| `src/omf/schema/capabilities.py` | nine frozen payloads |
| `src/omf/baseline/catalog.yaml` | 14 checks |
| `src/omf/baseline/profiles/*.yaml` | vendor lists |
| `src/omf/baseline/loader.py` | load + resolve params |
| `src/omf/baseline/evaluators/` | pure evaluators + registry |
| `src/omf/redactor.py` | tokenize / strip / destokenize |
| `src/omf/store.py` | `./audits/...` layout |
| `src/omf/runner.py` | plan, collect once, evaluate |
| `src/omf/adapters/base.py` | protocol + errors |
| `src/omf/adapters/normalize.py` | `any` token helper |
| `src/omf/adapters/mikrotik.py` | REST + normalize |
| `src/omf/adapters/fortinet.py` | REST + synthesize services |
| `src/omf/agent/report.py` | skeleton + local header |
| `src/omf/agent/tools.py` | Pydantic AI tools |
| `src/omf/agent/llm.py` | agent construction |
| `tests/` | unit tests + vendor JSON fixtures |

---

### Task 1: uv package and POSIX launcher

**Files:**
- Create: `pyproject.toml`
- Create: `src/omf/__init__.py`
- Create: `src/omf/__main__.py`
- Create: `src/omf/cli.py`
- Create: `omf`
- Create: `.env.example`
- Modify: `.gitignore` (append `/audits/`)
- Test: `tests/test_launcher.py`

**Interfaces:**
- Consumes: nothing
- Produces: `omf.__version__ == "0.1.0"`; `omf.cli.main(argv: list[str] | None = None) -> int`; console script `omf`; launcher `./omf`

- [ ] **Step 1: Write the failing launcher test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_launcher.py -v`  
Expected: FAIL — `omf` does not exist (or is not executable).

- [ ] **Step 3: Write pyproject, package stub, and launcher**

`pyproject.toml`:

```toml
[project]
name = "omf"
version = "0.1.0"
description = "OH MY FIREWALL — read-only multi-vendor firewall audit agent"
requires-python = ">=3.12"
dependencies = [
  "pydantic>=2.10",
  "pydantic-ai>=0.4",
  "httpx>=0.28",
  "rich>=13.9",
  "pyyaml>=6.0",
  "python-dotenv>=1.0",
]

[project.scripts]
omf = "omf.cli:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/omf"]

[dependency-groups]
dev = ["pytest>=8.3"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
markers = ["integration: optional live firewall tests (not CI)"]
```

`src/omf/__init__.py`:

```python
__version__ = "0.1.0"
DISCLAIMER_VERSION = 1
DISCLAIMER_TEXT = (
    "OMF is a read-only firewall audit tool. It will authenticate to the device "
    "you specify and collect configuration evidence. It will not change the device. "
    "Suggested mitigations in the report are examples only. You, the auditor, are "
    "responsible for any change applied to the system. Review the session folder "
    "before sharing it; `raw/` contains unredacted vendor data. Proceed?"
)
```

`src/omf/cli.py` (stub — Task 2 fills dispatch):

```python
def main(argv: list[str] | None = None) -> int:
    raise SystemExit("not implemented")


if __name__ == "__main__":
    raise SystemExit(main())
```

`src/omf/__main__.py`:

```python
from omf.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
```

`.env.example`:

```
OMF_LLM_BASE_URL=
OMF_LLM_API_KEY=
OMF_LLM_MODEL=
OMF_LLM_API_STYLE=openai
```

Root launcher `omf` (POSIX, `chmod +x`):

```sh
#!/usr/bin/env sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
cd "$ROOT"

HELP='OH MY FIREWALL

Usage:
  ./omf              Start the audit TUI (requires ./omf install)
  ./omf install      Sync all project dependencies with uv
  ./omf doctor       Check what is missing (no firewall connection)
  ./omf help         Show this help
'

case "${1:-}" in
  help|-h|--help)
    printf '%s' "$HELP"
    exit 0
    ;;
  install)
    if ! command -v uv >/dev/null 2>&1; then
      echo "uv is not on PATH. Install it:" >&2
      echo "  curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
      exit 1
    fi
    exec uv sync --all-extras --all-groups
    ;;
  doctor)
    if ! command -v uv >/dev/null 2>&1; then
      echo "MISSING  uv"
      echo "run: curl -LsSf https://astral.sh/uv/install.sh | sh"
      exit 1
    fi
    exec uv run python -m omf doctor
    ;;
  "")
    if ! command -v uv >/dev/null 2>&1; then
      echo "uv is not on PATH. Run ./omf doctor" >&2
      exit 1
    fi
    if ! uv run python -c "import omf" >/dev/null 2>&1; then
      echo "Dependencies are not synced. Run ./omf install" >&2
      exit 1
    fi
    exec uv run python -m omf
    ;;
  *)
    printf '%s' "$HELP"
    exit 1
    ;;
esac
```

Append to `.gitignore`:

```
/audits/
```

- [ ] **Step 4: Run launcher tests**

Run: `python3 -m pytest tests/test_launcher.py -v`  
Expected: PASS (help/unknown do not need uv sync).

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/omf/__init__.py src/omf/__main__.py src/omf/cli.py omf .env.example .gitignore tests/test_launcher.py
git commit -m "chore: scaffold uv package and POSIX launcher"
```

---

### Task 2: Python CLI dispatch (`help`, `doctor`, `install`, default)

**Files:**
- Modify: `src/omf/cli.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `omf.cli.main`
- Produces: `main(argv) -> int` with verbs `help`/`-h`/`--help`, `install`, `doctor`, default (`None`/empty → `run_tui()`). `install` runs `uv sync --all-extras --all-groups` via `subprocess`. Unknown → help + exit 1.

- [ ] **Step 1: Write the failing CLI tests**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cli.py -v`  
Expected: FAIL — `run_tui` / dispatch missing.

- [ ] **Step 3: Implement dispatch**

```python
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
    raise SystemExit("TUI not implemented")


def run_doctor() -> int:
    raise SystemExit("doctor not implemented")


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
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_cli.py tests/test_launcher.py -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/omf/cli.py tests/test_cli.py
git commit -m "feat: dispatch omf help install doctor and default TUI"
```

---

### Task 3: `doctor`

**Files:**
- Create: `src/omf/doctor.py`
- Modify: `src/omf/cli.py` (`run_doctor` calls `run`)
- Test: `tests/test_doctor.py`

**Interfaces:**
- Consumes: `omf.config.load_llm_settings` will exist in Task 4 — **do not import it yet**. Doctor reads env itself in this task via optional `env: dict[str, str]` and `import_omf: Callable[[], None]` injection so tests do not need Task 4.
- Produces: `run_doctor_checks(*, env: Mapping[str, str], which_uv: Callable[[], str | None], python_version: tuple[int, int], try_import: Callable[[], bool], env_file_exists: bool) -> tuple[int, list[str]]` and `run() -> int` for the CLI.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_doctor.py
from omf.doctor import run_doctor_checks


def test_all_required_ok_llm_missing_is_warn_exit_zero():
    code, lines = run_doctor_checks(
        env={},
        which_uv=lambda: "/usr/bin/uv",
        python_version=(3, 12),
        try_import=lambda: True,
        env_file_exists=False,
    )
    assert code == 0
    text = "\n".join(lines)
    assert "OK       uv" in text
    assert "OK       python" in text
    assert "OK       deps" in text
    assert "WARN     env-file" in text
    assert "WARN     OMF_LLM_API_KEY" in text
    assert "sk-secret" not in text


def test_missing_uv_exits_one():
    code, lines = run_doctor_checks(
        env={},
        which_uv=lambda: None,
        python_version=(3, 12),
        try_import=lambda: True,
        env_file_exists=True,
    )
    assert code == 1
    assert any(line.startswith("MISSING  uv") for line in lines)


def test_old_python_exits_one():
    code, _ = run_doctor_checks(
        env={},
        which_uv=lambda: "/uv",
        python_version=(3, 11),
        try_import=lambda: True,
        env_file_exists=True,
    )
    assert code == 1


def test_api_key_never_printed():
    code, lines = run_doctor_checks(
        env={
            "OMF_LLM_BASE_URL": "https://openrouter.ai/api/v1",
            "OMF_LLM_API_KEY": "sk-secret-value",
            "OMF_LLM_MODEL": "x",
            "OMF_LLM_API_STYLE": "openai",
        },
        which_uv=lambda: "/uv",
        python_version=(3, 13),
        try_import=lambda: True,
        env_file_exists=True,
    )
    assert code == 0
    joined = "\n".join(lines)
    assert "sk-secret-value" not in joined
    assert "OK       OMF_LLM_API_KEY" in joined


def test_bad_api_style_is_warn():
    _, lines = run_doctor_checks(
        env={"OMF_LLM_API_STYLE": "haystack"},
        which_uv=lambda: "/uv",
        python_version=(3, 12),
        try_import=lambda: True,
        env_file_exists=True,
    )
    assert any("WARN     OMF_LLM_API_STYLE" in line for line in lines)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_doctor.py -v`  
Expected: FAIL — module missing.

- [ ] **Step 3: Implement doctor**

```python
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
```

Wire `src/omf/cli.py`:

```python
def run_doctor() -> int:
    from omf.doctor import run
    return run()
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_doctor.py tests/test_cli.py -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/omf/doctor.py src/omf/cli.py tests/test_doctor.py
git commit -m "feat: add omf doctor with required vs warn checks"
```

---

### Task 4: Config (`.env` + `config.yaml`) and disclaimer prefs

**Files:**
- Create: `src/omf/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: `omf.DISCLAIMER_VERSION`
- Produces:

```python
@dataclass(frozen=True)
class LlmSettings:
    base_url: str | None
    api_key: str | None
    model: str | None
    api_style: Literal["openai", "anthropic"]
    def is_configured(self) -> bool: ...

@dataclass
class UserPrefs:
    disclaimer_accepted: bool
    disclaimer_version: int
    default_report_language: Literal["ca", "es", "en"]
    last_vendor: Literal["mikrotik", "fortinet"] | None

def load_llm_settings(cwd: Path, config_dir: Path) -> LlmSettings
def load_user_prefs(config_dir: Path) -> tuple[UserPrefs, str | None]
def save_user_prefs(config_dir: Path, prefs: UserPrefs) -> None
def needs_disclaimer(prefs: UserPrefs) -> bool
```

Search order for `.env`: `cwd/.env` then `config_dir/.env`. `config_dir` is `~/.config/omf` in production. Broken yaml → defaults + warning + rewrite.

- [ ] **Step 1: Write the failing tests**

```python
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
        UserPrefs(True, DISCLAIMER_VERSION, "en", "fortinet"),
    )
    prefs, warning = load_user_prefs(cfg)
    assert warning is None
    assert prefs.last_vendor == "fortinet"
    assert prefs.default_report_language == "en"
    assert needs_disclaimer(prefs) is False


def test_needs_disclaimer_when_version_stale():
    prefs = UserPrefs(True, DISCLAIMER_VERSION - 1 if DISCLAIMER_VERSION else 0, "ca", None)
    assert needs_disclaimer(prefs) is True


def test_prefs_never_write_secrets(tmp_path: Path):
    cfg = tmp_path / "c"
    cfg.mkdir()
    save_user_prefs(cfg, UserPrefs(True, 1, "ca", "mikrotik"))
    text = (cfg / "config.yaml").read_text()
    assert "password" not in text
    assert "http" not in text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_config.py -v`  
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `src/omf/config.py`**

Use `dotenv.dotenv_values` on the first existing `.env`. `is_configured` is true only when `base_url`, `api_key`, and `model` are all non-empty. Invalid `api_style` → `"openai"`. `load_user_prefs` catches YAML errors, writes defaults via `save_user_prefs`, returns a warning string. Allowed languages: `ca|es|en`. Allowed vendors: `mikrotik|fortinet`. `needs_disclaimer` is true when not accepted **or** `prefs.disclaimer_version != DISCLAIMER_VERSION`.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_config.py -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/omf/config.py tests/test_config.py
git commit -m "feat: load LLM .env and user config.yaml prefs"
```

---

### Task 5: Session and wizard validators

**Files:**
- Create: `src/omf/session.py`
- Create: `src/omf/wizard.py`
- Test: `tests/test_session.py`
- Test: `tests/test_wizard.py`

**Interfaces:**
- Consumes: nothing
- Produces:

```python
# wizard.py
class ValidationError(ValueError): ...
def parse_vendor(raw: str) -> Literal["mikrotik", "fortinet"]
def parse_url(raw: str) -> str          # must be http(s), no credentials in URL
def parse_language(raw: str) -> Literal["ca", "es", "en"]
def parse_yes_no(raw: str, *, default: bool) -> bool

# session.py
@dataclass
class Session:
    vendor: Literal["mikrotik", "fortinet"]
    url: str
    username: str
    password: str
    token: str
    verify_tls: bool
    report_language: Literal["ca", "es", "en"]
    def clear_secrets(self) -> None: ...   # password = token = username = ""
```

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_wizard.py
import pytest
from omf.wizard import parse_vendor, parse_url, parse_language, parse_yes_no, ValidationError


def test_vendor():
    assert parse_vendor("MikroTik") == "mikrotik"
    assert parse_vendor("FORTINET") == "fortinet"
    with pytest.raises(ValidationError):
        parse_vendor("palo")


def test_url_https_ok():
    assert parse_url("https://192.0.2.1") == "https://192.0.2.1"
    assert parse_url("https://fw.example:8443/") == "https://fw.example:8443"


def test_url_rejects_embedded_userinfo():
    with pytest.raises(ValidationError):
        parse_url("https://admin:secret@192.0.2.1")


def test_url_rejects_non_http():
    with pytest.raises(ValidationError):
        parse_url("ftp://192.0.2.1")


def test_language():
    assert parse_language("CA") == "ca"
    with pytest.raises(ValidationError):
        parse_language("fr")


def test_yes_no_default():
    assert parse_yes_no("", default=True) is True
    assert parse_yes_no("n", default=True) is False
    assert parse_yes_no("yes", default=False) is True
```

```python
# tests/test_session.py
from omf.session import Session


def test_clear_secrets_wipes_creds_keeps_url():
    s = Session(
        vendor="mikrotik",
        url="https://192.0.2.1",
        username="admin",
        password="p@ss",
        token="tok",
        verify_tls=True,
        report_language="ca",
    )
    s.clear_secrets()
    assert s.password == ""
    assert s.token == ""
    assert s.username == ""
    assert s.url == "https://192.0.2.1"
    assert s.vendor == "mikrotik"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_wizard.py tests/test_session.py -v`  
Expected: FAIL — modules missing.

- [ ] **Step 3: Implement validators and Session**

`parse_url`: `urllib.parse.urlparse`; scheme in `{http, https}`; `netloc` non-empty; `username`/`password` on the parse result must be empty; strip trailing slash. `parse_yes_no`: accept `y/yes/true/1` and `n/no/false/0` case-insensitive; empty → default.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_wizard.py tests/test_session.py -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/omf/session.py src/omf/wizard.py tests/test_session.py tests/test_wizard.py
git commit -m "feat: add session secrets holder and wizard validators"
```

---

### Task 6: Canonical frozen models

**Files:**
- Create: `src/omf/schema/__init__.py`
- Create: `src/omf/schema/evidence.py`
- Create: `src/omf/schema/capabilities.py`
- Test: `tests/test_schema.py`

**Interfaces:**
- Consumes: nothing
- Produces: frozen pydantic models exactly as spec §6:

```python
Vendor = Literal["mikrotik", "fortinet"]
CapabilityName = Literal[
    "users", "admin_settings", "services", "ntp", "dns",
    "logging", "snmp", "firewall_filter", "system_info",
]
ALL_CAPABILITIES: tuple[CapabilityName, ...]
Status = Literal["pass", "fail", "error", "skipped"]
Severity = Literal["info", "low", "medium", "high"]
Listen = Literal["all", "restricted", "unknown"]
PolicyAction = Literal["accept", "deny", "drop", "other"]

class Evidence(BaseModel, Generic[T]):
    capability: str
    vendor: Vendor
    schema_version: int = 1
    collected_at: datetime
    payload: T

class CheckResult(BaseModel):
    check_id: str
    status: Status
    severity: Severity
    diagnostic: str
    capability_refs: tuple[str, ...]
    observed: dict[str, Any]
```

Payloads: `User`/`UserList`, `AdminSettings` (`hostname: str`, `idle_timeout_seconds: int | None = None`), `Service`/`ServiceList`, `NtpConfig`, `DnsConfig`, `LoggingConfig`, `SnmpCommunity`/`SnmpConfig`, `Policy`/`PolicyList`, `SystemInfo` (`firmware: str`, `model: str | None = None`). All `model_config = ConfigDict(frozen=True)`. No extra fields (`extra="forbid"`).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_schema.py
import pytest
from pydantic import ValidationError
from omf.schema.capabilities import User, UserList
from omf.schema.evidence import Evidence, CheckResult


def test_userlist_frozen():
    users = UserList(users=(User(name="admin", enabled=True, groups=("full",)),))
    with pytest.raises(Exception):
        users.users[0].name = "x"  # type: ignore[misc]


def test_evidence_wraps_payload():
    payload = UserList(users=())
    ev = Evidence(capability="users", vendor="mikrotik", payload=payload)
    assert ev.schema_version == 1
    assert ev.payload is payload


def test_user_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        User(name="a", enabled=True, groups=(), password="nope")


def test_check_result_status_enum():
    CheckResult(
        check_id="FW-ADM-001",
        status="fail",
        severity="high",
        diagnostic="default admin present",
        capability_refs=("users",),
        observed={"names": ["admin"]},
    )
    with pytest.raises(ValidationError):
        CheckResult(
            check_id="x",
            status="warn",
            severity="high",
            diagnostic="",
            capability_refs=(),
            observed={},
        )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_schema.py -v`  
Expected: FAIL — modules missing.

- [ ] **Step 3: Implement schema modules** as specified in Interfaces. Export all public types from `omf.schema`.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_schema.py -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/omf/schema tests/test_schema.py
git commit -m "feat: add frozen capability and finding models"
```

---

### Task 7: Catalog YAML, profiles, and loader

**Files:**
- Create: `src/omf/baseline/catalog.yaml` (all 14 checks — full text below)
- Create: `src/omf/baseline/profiles/mikrotik.yaml`
- Create: `src/omf/baseline/profiles/fortinet.yaml`
- Create: `src/omf/baseline/__init__.py`
- Create: `src/omf/baseline/loader.py`
- Test: `tests/test_catalog.py`

**Interfaces:**
- Consumes: `CapabilityName`, `Severity`
- Produces:

```python
@dataclass(frozen=True)
class CheckDef:
    id: str
    title: str
    severity: Severity
    applies_to: tuple[str, ...]
    needs: tuple[str, ...]
    evaluator: str
    params: dict
    mitigation: dict[str, str]   # generic / mikrotik / fortinet

def load_catalog() -> tuple[CheckDef, ...]
def load_profile(vendor: str) -> dict
def resolve_params(check: CheckDef, vendor: str) -> dict
def checks_for(vendor: str) -> tuple[CheckDef, ...]
def mitigation_for(check: CheckDef, vendor: str) -> str
```

`resolve_params`: shallow-merge `params.default`, then `params[vendor]`, then profile keys that the evaluator documents (`forbidden_services`, `mgmt_services`, `default_hostnames`) if the check does not already set them.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_catalog.py
from omf.baseline.loader import load_catalog, checks_for, resolve_params, mitigation_for


def test_catalog_has_fourteen_unique_ids():
    checks = load_catalog()
    ids = [c.id for c in checks]
    assert len(ids) == 14
    assert len(set(ids)) == 14
    assert "FW-POL-002" in ids


def test_pol002_only_mikrotik():
    mt = {c.id for c in checks_for("mikrotik")}
    ft = {c.id for c in checks_for("fortinet")}
    assert "FW-POL-002" in mt
    assert "FW-POL-002" not in ft
    assert len(mt) == 14
    assert len(ft) == 13


def test_resolve_admin_mode_differs_by_vendor():
    check = next(c for c in load_catalog() if c.id == "FW-ADM-001")
    assert resolve_params(check, "mikrotik")["mode"] == "must_not_exist"
    assert resolve_params(check, "fortinet")["mode"] == "must_be_renamed"


def test_mitigation_falls_back_to_generic():
    check = next(c for c in load_catalog() if c.id == "FW-SYS-001")
    text = mitigation_for(check, "mikrotik")
    assert text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_catalog.py -v`  
Expected: FAIL — loader missing.

- [ ] **Step 3: Write catalog, profiles, loader**

`src/omf/baseline/profiles/mikrotik.yaml`:

```yaml
forbidden_services: [telnet, ftp, www]
mgmt_services: [www, www-ssl, api, api-ssl, ssh, winbox]
default_hostnames: ["MikroTik", ""]
```

`src/omf/baseline/profiles/fortinet.yaml`:

```yaml
forbidden_services: [telnet, ftp, http]
mgmt_services: [https, ssh, http, telnet]
default_hostnames: ["FortiGate", ""]
```

`src/omf/baseline/catalog.yaml` — write **all 14** entries. Required fields per spec §7. Use this mitigation copy (English; the LLM/skeleton will use it verbatim or adapt):

```yaml
checks:
  - id: FW-ADM-001
    title: No generic default admin username
    severity: high
    applies_to: [mikrotik, fortinet]
    needs: [users]
    evaluator: no_generic_accounts
    params:
      default:
        names: [admin, administrator, root]
      mikrotik:
        names: [admin]
        mode: must_not_exist
      fortinet:
        names: [admin]
        mode: must_be_renamed
    mitigation:
      generic: "Replace factory-default admin identities with unique named accounts."
      mikrotik: "Rename the default admin user under /user so the name is no longer admin."
      fortinet: "Rename the default admin administrator. FortiOS does not allow deleting it."
  - id: FW-ADM-002
    title: Admin idle timeout is set
    severity: medium
    applies_to: [mikrotik, fortinet]
    needs: [admin_settings]
    evaluator: idle_timeout_set
    params:
      default: {}
    mitigation:
      generic: "Configure a non-zero administrative idle timeout."
  - id: FW-ADM-003
    title: Device identity is not the factory default
    severity: low
    applies_to: [mikrotik, fortinet]
    needs: [admin_settings]
    evaluator: hostname_not_default
    params:
      default: {}
    mitigation:
      generic: "Set a unique hostname that identifies the device and site."
  - id: FW-SVC-001
    title: Insecure management services are disabled
    severity: high
    applies_to: [mikrotik, fortinet]
    needs: [services]
    evaluator: insecure_services_disabled
    params:
      default: {}
    mitigation:
      generic: "Disable telnet, ftp, and cleartext HTTP management services."
  - id: FW-SVC-002
    title: Management services are not open to all
    severity: high
    applies_to: [mikrotik, fortinet]
    needs: [services]
    evaluator: services_not_unrestricted
    params:
      default: {}
    mitigation:
      generic: "Restrict management services to trusted addresses or interfaces."
  - id: FW-NTP-001
    title: NTP is enabled with at least one server
    severity: medium
    applies_to: [mikrotik, fortinet]
    needs: [ntp]
    evaluator: ntp_configured
    params:
      default: {}
    mitigation:
      generic: "Enable NTP and point it at trusted time servers."
  - id: FW-DNS-001
    title: DNS servers are configured
    severity: low
    applies_to: [mikrotik, fortinet]
    needs: [dns]
    evaluator: dns_configured
    params:
      default: {}
    mitigation:
      generic: "Configure explicit DNS servers, preferably internal."
  - id: FW-LOG-001
    title: Local logging is enabled
    severity: medium
    applies_to: [mikrotik, fortinet]
    needs: [logging]
    evaluator: local_logging_enabled
    params:
      default: {}
    mitigation:
      generic: "Enable local logging so administrative actions are recorded on-box."
  - id: FW-LOG-002
    title: Remote syslog is configured
    severity: medium
    applies_to: [mikrotik, fortinet]
    needs: [logging]
    evaluator: remote_syslog_configured
    params:
      default: {}
    mitigation:
      generic: "Send logs to a remote syslog collector that you control."
  - id: FW-SNMP-001
    title: No default SNMP community
    severity: high
    applies_to: [mikrotik, fortinet]
    needs: [snmp]
    evaluator: no_default_snmp_community
    params:
      default:
        forbidden: [public, private]
    mitigation:
      generic: "Remove public/private communities. Prefer SNMPv3 or disable SNMP."
  - id: FW-SNMP-002
    title: SNMP is disabled or uses v3-only communities
    severity: medium
    applies_to: [mikrotik, fortinet]
    needs: [snmp]
    evaluator: snmp_not_legacy
    params:
      default: {}
    mitigation:
      generic: "Disable SNMP if unused, or configure SNMPv3 only."
  - id: FW-POL-001
    title: No unrestricted accept policy
    severity: high
    applies_to: [mikrotik, fortinet]
    needs: [firewall_filter]
    evaluator: no_any_any_accept
    params:
      default: {}
    mitigation:
      generic: "Remove or tighten any accept rule that allows any source, destination, and service."
  - id: FW-POL-002
    title: Explicit deny is present
    severity: medium
    applies_to: [mikrotik]
    needs: [firewall_filter]
    evaluator: explicit_deny_present
    params:
      default: {}
    mitigation:
      generic: "Add a final drop/deny rule so unmatched traffic is explicitly denied."
      mikrotik: "Add a last /ip/firewall/filter rule with action=drop."
  - id: FW-SYS-001
    title: Firmware version is recorded
    severity: info
    applies_to: [mikrotik, fortinet]
    needs: [system_info]
    evaluator: firmware_present
    params:
      default: {}
    mitigation:
      generic: "Record the firmware version and compare it to the vendor advisory feed offline."
```

Loader reads YAML next to the module via `Path(__file__).parent`. Package data: ensure hatchling includes `*.yaml` (add to `pyproject.toml`):

```toml
[tool.hatch.build.targets.wheel]
packages = ["src/omf"]

[tool.hatch.build]
include = ["src/omf/**/*.yaml"]
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_catalog.py -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/omf/baseline pyproject.toml tests/test_catalog.py
git commit -m "feat: add 14-check catalog, vendor profiles, and loader"
```

---

### Task 8: Evaluators (pure functions + registry)

**Files:**
- Create: `src/omf/baseline/evaluators/__init__.py` (`REGISTRY`, `get_evaluator`, `evaluate`)
- Create: `src/omf/baseline/evaluators/accounts.py` — `no_generic_accounts`
- Create: `src/omf/baseline/evaluators/admin.py` — `idle_timeout_set`, `hostname_not_default`
- Create: `src/omf/baseline/evaluators/services.py` — `insecure_services_disabled`, `services_not_unrestricted`
- Create: `src/omf/baseline/evaluators/ntp_dns.py` — `ntp_configured`, `dns_configured`
- Create: `src/omf/baseline/evaluators/logging.py` — `local_logging_enabled`, `remote_syslog_configured`
- Create: `src/omf/baseline/evaluators/snmp.py` — `no_default_snmp_community`, `snmp_not_legacy`
- Create: `src/omf/baseline/evaluators/policy.py` — `no_any_any_accept`, `explicit_deny_present`
- Create: `src/omf/baseline/evaluators/system.py` — `firmware_present`
- Test: `tests/test_evaluators.py`

**Interfaces:**
- Consumes: `Evidence`, payloads, `CheckResult`, `CheckDef`
- Produces:

```python
Evaluator = Callable[[Mapping[str, Evidence], dict, str], CheckResult]
REGISTRY: dict[str, Evaluator]
def get_evaluator(name: str) -> Evaluator
def evaluate(check: CheckDef, evidence: Mapping[str, Evidence], vendor: str) -> CheckResult
```

`evaluate` resolves params, looks up the function, and on exception returns `status="error"` with the exception message (no traceback in `diagnostic`; runner logs traceback later). If any `check.needs` key is missing from `evidence`, return `status="error"` with diagnostic `missing capability {name}` — **unless** the runner already marked skip; evaluators do not decide SKIPPED.

Rules (lock these; tests encode them):

| Function | FAIL when |
|---|---|
| `no_generic_accounts` | any **enabled** user whose `name.lower()` is in `params.names`. `must_be_renamed` and `must_not_exist` use the same FAIL condition (name still present). |
| `idle_timeout_set` | `idle_timeout_seconds` is `None` or `<= 0`. If `params.max_seconds` set, also FAIL when timeout `>` that value. |
| `hostname_not_default` | `hostname.strip()` is in `params.default_hostnames` (from profile) or empty. Compare case-insensitive. |
| `insecure_services_disabled` | any enabled service whose `name.lower()` is in `params.forbidden` or profile `forbidden_services`. |
| `services_not_unrestricted` | any enabled service in `params.mgmt` or profile `mgmt_services` with `listen` in `{all, unknown}`. |
| `ntp_configured` | not `enabled` or `servers` empty. |
| `dns_configured` | `servers` empty. |
| `local_logging_enabled` | `local_enabled` is False. |
| `remote_syslog_configured` | `remote_targets` empty. |
| `no_default_snmp_community` | SNMP enabled and any community `name.lower()` in `forbidden` (default `public`, `private`). |
| `snmp_not_legacy` | SNMP enabled and any community `version` is not `3` / `"3"` / `"v3"`. Pass if SNMP disabled. |
| `no_any_any_accept` | enabled policy with `action=="accept"` and `src`, `dst`, `service` each equal to `("any",)` or containing only `any`. |
| `explicit_deny_present` | no enabled policy with `action` in `{deny, drop}`. |
| `firmware_present` | `firmware` empty or whitespace. |

- [ ] **Step 1: Write the failing tests** (keep them in one file; each function has pass + fail):

```python
# tests/test_evaluators.py
from datetime import datetime, timezone
from omf.schema.capabilities import (
    User, UserList, AdminSettings, Service, ServiceList,
    NtpConfig, DnsConfig, LoggingConfig, SnmpCommunity, SnmpConfig,
    Policy, PolicyList, SystemInfo,
)
from omf.schema.evidence import Evidence
from omf.baseline.evaluators.accounts import no_generic_accounts
from omf.baseline.evaluators.admin import idle_timeout_set, hostname_not_default
from omf.baseline.evaluators.services import insecure_services_disabled, services_not_unrestricted
from omf.baseline.evaluators.ntp_dns import ntp_configured, dns_configured
from omf.baseline.evaluators.logging import local_logging_enabled, remote_syslog_configured
from omf.baseline.evaluators.snmp import no_default_snmp_community, snmp_not_legacy
from omf.baseline.evaluators.policy import no_any_any_accept, explicit_deny_present
from omf.baseline.evaluators.system import firmware_present
from omf.baseline.evaluators import REGISTRY, evaluate
from omf.baseline.loader import load_catalog, resolve_params


def ev(capability, payload, vendor="mikrotik"):
    return Evidence(
        capability=capability,
        vendor=vendor,
        collected_at=datetime.now(timezone.utc),
        payload=payload,
    )


def test_no_generic_accounts_fail_enabled_admin():
    evidence = {"users": ev("users", UserList(users=(
        User(name="admin", enabled=True, groups=()),
    )))}
    r = no_generic_accounts(evidence, {"names": ["admin"], "mode": "must_not_exist"}, "mikrotik")
    assert r.status == "fail"


def test_no_generic_accounts_pass_renamed():
    evidence = {"users": ev("users", UserList(users=(
        User(name="alice", enabled=True, groups=()),
    )))}
    r = no_generic_accounts(evidence, {"names": ["admin"], "mode": "must_be_renamed"}, "fortinet")
    assert r.status == "pass"


def test_no_generic_accounts_ignores_disabled_default():
    evidence = {"users": ev("users", UserList(users=(
        User(name="admin", enabled=False, groups=()),
    )))}
    r = no_generic_accounts(evidence, {"names": ["admin"], "mode": "must_not_exist"}, "mikrotik")
    assert r.status == "pass"


def test_idle_timeout_zero_fails():
    evidence = {"admin_settings": ev("admin_settings", AdminSettings(hostname="fw", idle_timeout_seconds=0))}
    assert idle_timeout_set(evidence, {}, "mikrotik").status == "fail"


def test_hostname_default_fails():
    evidence = {"admin_settings": ev("admin_settings", AdminSettings(hostname="MikroTik"))}
    r = hostname_not_default(evidence, {"default_hostnames": ["MikroTik", ""]}, "mikrotik")
    assert r.status == "fail"


def test_insecure_telnet_fails():
    evidence = {"services": ev("services", ServiceList(services=(
        Service(name="telnet", enabled=True, port=23, listen="restricted"),
    )))}
    r = insecure_services_disabled(evidence, {"forbidden": ["telnet", "ftp", "www"]}, "mikrotik")
    assert r.status == "fail"


def test_mgmt_unknown_listen_fails():
    evidence = {"services": ev("services", ServiceList(services=(
        Service(name="www-ssl", enabled=True, port=443, listen="unknown"),
    )))}
    r = services_not_unrestricted(evidence, {"mgmt": ["www-ssl", "ssh"]}, "mikrotik")
    assert r.status == "fail"


def test_ntp_and_dns():
    assert ntp_configured({"ntp": ev("ntp", NtpConfig(enabled=True, servers=("1.1.1.1",)))}, {}, "m").status == "pass"
    assert ntp_configured({"ntp": ev("ntp", NtpConfig(enabled=True, servers=()))}, {}, "m").status == "fail"
    assert dns_configured({"dns": ev("dns", DnsConfig(servers=()))}, {}, "m").status == "fail"


def test_logging():
    lg = ev("logging", LoggingConfig(local_enabled=True, remote_targets=()))
    assert local_logging_enabled({"logging": lg}, {}, "m").status == "pass"
    assert remote_syslog_configured({"logging": lg}, {}, "m").status == "fail"


def test_snmp():
    enabled_public = ev("snmp", SnmpConfig(enabled=True, communities=(
        SnmpCommunity(name="public", version="2"),
    )))
    assert no_default_snmp_community({"snmp": enabled_public}, {"forbidden": ["public", "private"]}, "m").status == "fail"
    disabled = ev("snmp", SnmpConfig(enabled=False, communities=()))
    assert snmp_not_legacy({"snmp": disabled}, {}, "m").status == "pass"


def test_policies():
    bad = ev("firewall_filter", PolicyList(policies=(
        Policy(id="1", enabled=True, action="accept", src=("any",), dst=("any",), service=("any",)),
    )))
    assert no_any_any_accept({"firewall_filter": bad}, {}, "m").status == "fail"
    deny = ev("firewall_filter", PolicyList(policies=(
        Policy(id="9", enabled=True, action="drop", src=("any",), dst=("any",), service=("any",)),
    )))
    assert explicit_deny_present({"firewall_filter": deny}, {}, "mikrotik").status == "pass"


def test_firmware():
    assert firmware_present({"system_info": ev("system_info", SystemInfo(firmware="7.16"))}, {}, "m").status == "pass"
    assert firmware_present({"system_info": ev("system_info", SystemInfo(firmware="  "))}, {}, "m").status == "fail"


def test_registry_covers_catalog():
    for check in load_catalog():
        assert check.evaluator in REGISTRY


def test_evaluate_missing_capability_is_error():
    check = next(c for c in load_catalog() if c.id == "FW-NTP-001")
    r = evaluate(check, {}, "mikrotik")
    assert r.status == "error"
    assert "ntp" in r.diagnostic
```

Each evaluator sets `check_id` to the catalog id **passed in via params `_check_id`** or a module-level constant matching the catalog. Cleaner: `evaluate()` stamps `check_id`, `severity`, and `capability_refs` on the returned model after the function returns a partial. **Lock this:** functions return `CheckResult` with the correct `check_id` hard-coded (as in the tests for FW-ADM-001). Other functions use their catalog id (`FW-ADM-002`, …). `evaluate()` may replace `check_id`/`severity`/`capability_refs` from `CheckDef` so hard-coding is only a fallback.

Preferred implementation of `evaluate`:

```python
def evaluate(check, evidence, vendor):
    try:
        for need in check.needs:
            if need not in evidence:
                return CheckResult(
                    check_id=check.id, status="error", severity=check.severity,
                    diagnostic=f"missing capability {need}",
                    capability_refs=check.needs, observed={},
                )
        raw = REGISTRY[check.evaluator](evidence, resolve_params(check, vendor), vendor)
        return raw.model_copy(update={
            "check_id": check.id,
            "severity": check.severity,
            "capability_refs": check.needs,
        })
    except Exception as exc:
        return CheckResult(
            check_id=check.id, status="error", severity=check.severity,
            diagnostic=str(exc), capability_refs=check.needs, observed={},
        )
```

Then evaluator functions can use a dummy `check_id=""`; update the ADM-001 test to assert `evaluate(...)` or accept `model_copy`. **Adjust the ADM-001 unit test** to call `evaluate` on the catalog check, or assert only `status`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_evaluators.py -v`  
Expected: FAIL — evaluators missing.

- [ ] **Step 3: Implement all evaluator modules and the registry.** Evaluators must not import `httpx`, `omf.adapters`, or `os.environ`.

```python
# src/omf/baseline/evaluators/accounts.py
from omf.schema.capabilities import UserList
from omf.schema.evidence import CheckResult


def no_generic_accounts(evidence, params, vendor) -> CheckResult:
    names = {n.lower() for n in params.get("names", ("admin", "administrator", "root"))}
    payload: UserList = evidence["users"].payload
    hits = [u.name for u in payload.users if u.enabled and u.name.lower() in names]
    return CheckResult(
        check_id="",
        status="fail" if hits else "pass",
        severity="high",
        diagnostic=(
            f"enabled user matches vendor default name {hits!r}" if hits else "no generic admin names"
        ),
        capability_refs=("users",),
        observed={"names": hits},
    )
```

Repeat that shape for every function in the rules table. Registry:

```python
# src/omf/baseline/evaluators/__init__.py
from omf.baseline.evaluators.accounts import no_generic_accounts
from omf.baseline.evaluators.admin import idle_timeout_set, hostname_not_default
from omf.baseline.evaluators.services import insecure_services_disabled, services_not_unrestricted
from omf.baseline.evaluators.ntp_dns import ntp_configured, dns_configured
from omf.baseline.evaluators.logging import local_logging_enabled, remote_syslog_configured
from omf.baseline.evaluators.snmp import no_default_snmp_community, snmp_not_legacy
from omf.baseline.evaluators.policy import no_any_any_accept, explicit_deny_present
from omf.baseline.evaluators.system import firmware_present
from omf.baseline.loader import resolve_params
from omf.schema.evidence import CheckResult

REGISTRY = {
    "no_generic_accounts": no_generic_accounts,
    "idle_timeout_set": idle_timeout_set,
    "hostname_not_default": hostname_not_default,
    "insecure_services_disabled": insecure_services_disabled,
    "services_not_unrestricted": services_not_unrestricted,
    "ntp_configured": ntp_configured,
    "dns_configured": dns_configured,
    "local_logging_enabled": local_logging_enabled,
    "remote_syslog_configured": remote_syslog_configured,
    "no_default_snmp_community": no_default_snmp_community,
    "snmp_not_legacy": snmp_not_legacy,
    "no_any_any_accept": no_any_any_accept,
    "explicit_deny_present": explicit_deny_present,
    "firmware_present": firmware_present,
}

def get_evaluator(name: str):
    return REGISTRY[name]


def evaluate(check, evidence, vendor) -> CheckResult:
    try:
        for need in check.needs:
            if need not in evidence:
                return CheckResult(
                    check_id=check.id, status="error", severity=check.severity,
                    diagnostic=f"missing capability {need}",
                    capability_refs=tuple(check.needs), observed={},
                )
        raw = REGISTRY[check.evaluator](evidence, resolve_params(check, vendor), vendor)
        return raw.model_copy(update={
            "check_id": check.id,
            "severity": check.severity,
            "capability_refs": tuple(check.needs),
        })
    except Exception as exc:
        return CheckResult(
            check_id=check.id, status="error", severity=check.severity,
            diagnostic=str(exc), capability_refs=tuple(check.needs), observed={},
        )
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_evaluators.py tests/test_catalog.py -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/omf/baseline/evaluators tests/test_evaluators.py
git commit -m "feat: add pure evaluators and registry for 14 checks"
```

---

### Task 9: Redactor

**Files:**
- Create: `src/omf/redactor.py`
- Test: `tests/test_redactor.py`

**Interfaces:**
- Consumes: nothing (operates on strings / JSON-able objects)
- Produces:

```python
ALLOWLIST = frozenset({
    "admin", "administrator", "root", "guest", "public", "private",
    "accept", "deny", "drop", "any", "mikrotik", "fortinet",
})
STRIP_KEYS = frozenset({
    "password", "passwd", "passphrase", "secret", "psk", "private_key", "api_key",
})

class Redactor:
    def redact_text(self, text: str) -> str
    def redact_obj(self, obj: Any) -> Any
    def destokenize(self, text: str) -> str
    def token_map(self) -> dict[str, str]   # token -> original
```

Same original value → same token. IPv4, IPv6, URLs (`https?://…`), hostnames with a dot, serial-like (`[A-Z0-9]{8,}` if not allowlisted — keep this conservative: only apply serial regex to values of keys named `serial` / `serial_number`). Usernames: when redacting a dict, if key is `name` or `username` and the value is a string not in ALLOWLIST, tokenize as `[USER_n]`. SNMP community names that are not public/private: `[SECRET_n]`. Strip keys: replace value with `[STRIPPED]` (do not put the secret in `token_map`).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_redactor.py
from omf.redactor import Redactor


def test_ip_and_stability():
    r = Redactor()
    out = r.redact_text("peer 10.0.0.5 and again 10.0.0.5")
    assert "10.0.0.5" not in out
    assert out.count("[IP_1]") == 2
    assert r.destokenize(out) == "peer 10.0.0.5 and again 10.0.0.5"


def test_allowlist_admin_stays():
    r = Redactor()
    assert r.redact_obj({"name": "admin"})["name"] == "admin"
    assert r.redact_obj({"name": "jcasas"})["name"] == "[USER_1]"


def test_url_and_hostname():
    r = Redactor()
    out = r.redact_text("see https://fw.client.tld/login on fw.client.tld")
    assert "client.tld" not in out
    assert "[URL_1]" in out


def test_password_stripped_not_in_map():
    r = Redactor()
    out = r.redact_obj({"password": "s3cret", "name": "alice"})
    assert out["password"] == "[STRIPPED]"
    assert "s3cret" not in r.token_map().values()
    assert out["name"] == "[USER_1]"


def test_public_community_kept_custom_secret():
    r = Redactor()
    obj = r.redact_obj({"communities": [{"name": "public"}, {"name": "s3cr3tcomm"}]})
    assert obj["communities"][0]["name"] == "public"
    assert obj["communities"][1]["name"] == "[SECRET_1]"


def test_llm_payload_builder_excludes_map_and_raw():
    r = Redactor()
    r.redact_text("10.1.2.3")
    payload = {
        "findings": r.redact_obj([{"diagnostic": "host 10.1.2.3"}]),
        "vendor": "mikrotik",
    }
    blob = str(payload)
    assert "token_map" not in blob
    assert "10.1.2.3" not in blob
    assert "raw" not in payload
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_redactor.py -v`  
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `Redactor`.** Walk strings with compiled regexes for IPv4, IPv6, and URLs first (URLs before hostnames so the host inside a URL is not double-tokenized). Recurse into dicts/lists/tuples. Pydantic models: `model_dump(mode="json")` then redact. Capability names and check IDs are not special-cased beyond allowlist words.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_redactor.py -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/omf/redactor.py tests/test_redactor.py
git commit -m "feat: add deterministic redactor and destokenizer"
```

---

### Task 10: Audit store

**Files:**
- Create: `src/omf/store.py`
- Test: `tests/test_store.py`

**Interfaces:**
- Consumes: `Evidence`, `CheckResult`
- Produces:

```python
class AuditStore:
    def __init__(self, audits_root: Path, vendor: str, started_at: datetime): ...
    path: Path   # audits_root / f"{started_at:%Y-%m-%dT%H%M%S}-{vendor}"
    def write_meta(self, data: dict) -> None
    def write_raw(self, capability: str, data: object) -> None
    def write_evidence(self, evidence: Evidence) -> None
    def write_findings(self, findings: list[CheckResult]) -> None
    def write_redacted_findings(self, data: object) -> None
    def write_redacted_evidence(self, capability: str, data: object) -> None
    def write_token_map(self, mapping: dict[str, str]) -> None
    def append_event(self, event: dict) -> None
    def write_report(self, markdown: str) -> None
    def write_report_redacted(self, markdown: str) -> None
    def assert_no_secrets(self, forbidden: list[str]) -> None  # test helper can just grep
```

`write_meta` **raises `ValueError`** if any key in `{"url", "username", "password", "token", "api_key"}` is present (any case). `append_event` writes JSONL and also raises if a string value contains a password passed in — keep it simple: refuse keys `password`, `token`, `authorization`, `api_key`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_store.py
from datetime import datetime, timezone
from pathlib import Path
import json
import pytest
from omf.store import AuditStore
from omf.schema.capabilities import UserList
from omf.schema.evidence import Evidence, CheckResult


def test_layout_and_meta_rejects_url(tmp_path: Path):
    started = datetime(2026, 8, 18, 14, 2, 11, tzinfo=timezone.utc)
    store = AuditStore(tmp_path, "mikrotik", started)
    assert store.path.name == "2026-08-18T140211-mikrotik"
    store.write_meta({"vendor": "mikrotik", "tls_verify": True, "tool_version": "0.1.0"})
    meta = json.loads((store.path / "meta.json").read_text())
    assert "url" not in meta
    with pytest.raises(ValueError):
        store.write_meta({"vendor": "mikrotik", "url": "https://192.0.2.1"})


def test_writes_raw_evidence_findings(tmp_path: Path):
    store = AuditStore(tmp_path, "fortinet", datetime.now(timezone.utc))
    store.write_raw("users", [{"name": "admin"}])
    ev = Evidence(capability="users", vendor="fortinet", payload=UserList(users=()))
    store.write_evidence(ev)
    store.write_findings([
        CheckResult(check_id="FW-ADM-001", status="pass", severity="high",
                    diagnostic="ok", capability_refs=("users",), observed={}),
    ])
    store.append_event({"phase": "collect", "path": "/rest/user", "status": 200})
    store.write_report("# hi\n")
    assert (store.path / "raw" / "users.json").is_file()
    assert (store.path / "evidence" / "users.json").is_file()
    assert (store.path / "findings.json").is_file()
    assert (store.path / "events.jsonl").is_file()
    assert (store.path / "report.md").read_text() == "# hi\n"
    with pytest.raises(ValueError):
        store.append_event({"password": "x"})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_store.py -v`  
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `AuditStore`.** Create directories on first write. Dump JSON with `default=str`. Evidence via `model_dump(mode="json")`.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_store.py -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/omf/store.py tests/test_store.py
git commit -m "feat: persist audit session layout without secrets in meta"
```

---

### Task 11: Runner + fake adapter

**Files:**
- Create: `src/omf/adapters/__init__.py`
- Create: `src/omf/adapters/base.py`
- Create: `src/omf/runner.py`
- Test: `tests/test_runner.py`

**Interfaces:**
- Consumes: `CheckDef`, `evaluate`, `AuditStore`, `Evidence`, `CheckResult`
- Produces:

```python
class CollectError(Exception):
    def __init__(self, capability: str, path: str, status: int | None, message: str): ...

class ProbeError(Exception):
    def __init__(self, path: str, status: int | None, message: str): ...

class VendorAdapter(Protocol):
    vendor: Literal["mikrotik", "fortinet"]
    def probe(self) -> None: ...
    def collect(self, capability: str) -> Evidence: ...
    def implemented(self) -> frozenset[str]: ...
    def close(self) -> None: ...

@dataclass
class RunnerResult:
    findings: list[CheckResult]
    collected: dict[str, Evidence]

class Runner:
    def __init__(
        self,
        adapter: VendorAdapter,
        checks: tuple[CheckDef, ...],
        store: AuditStore,
        on_event: Callable[[dict], None] | None = None,
    ): ...
    def run(self) -> RunnerResult: ...
```

Algorithm:

1. Filter checks already passed in (caller uses `checks_for(vendor)`).
2. `needed = unique needs in order`.
3. For each capability in `needed`: if not in `adapter.implemented()`, record skip (do not call collect). Else call `collect` once. Success → `write_raw` if the adapter attached `raw` via an optional attribute is **not** required; runner writes raw only if `collect` returns and the adapter exposes `last_raw: object | None` — **simpler lock:** `collect` returns `Evidence` only; adapters write nothing; runner does not have vendor JSON unless we add a side channel.

**Lock:** change `collect` to return `tuple[Evidence, object]` `(canonical, raw_json)`. Fake adapter returns `{}` as raw. Real adapters return the vendor payload.

4. Collect fail → `CollectError` → no evidence key; those checks become `status=error` diagnostic `collect failed: ...`. Continue.
5. For each check: if any need missing from implemented() and never collected → `skipped` (capability not implemented). If need implemented but collect failed → `error`. Else `evaluate`.
6. `write_evidence` for successes, `write_findings`, `append_event` for each collect/eval.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_runner.py
from datetime import datetime, timezone
from pathlib import Path
from omf.adapters.base import CollectError
from omf.runner import Runner
from omf.store import AuditStore
from omf.schema.capabilities import UserList, User, NtpConfig
from omf.schema.evidence import Evidence
from omf.baseline.loader import checks_for


class FakeAdapter:
    vendor = "mikrotik"

    def __init__(self, implemented=None, fail=frozenset()):
        self._impl = implemented or frozenset({
            "users", "admin_settings", "services", "ntp", "dns",
            "logging", "snmp", "firewall_filter", "system_info",
        })
        self.fail = set(fail)
        self.calls: list[str] = []

    def probe(self) -> None:
        return None

    def implemented(self) -> frozenset[str]:
        return self._impl

    def collect(self, capability: str):
        self.calls.append(capability)
        if capability in self.fail:
            raise CollectError(capability, f"/{capability}", 500, "boom")
        now = datetime.now(timezone.utc)
        if capability == "users":
            payload = UserList(users=(User(name="alice", enabled=True, groups=()),))
        elif capability == "ntp":
            payload = NtpConfig(enabled=True, servers=("1.2.3.4",))
        else:
            raise CollectError(capability, f"/{capability}", None, "fixture missing")
        return Evidence(capability=capability, vendor="mikrotik", collected_at=now, payload=payload), {"raw": True}

    def close(self) -> None:
        return None


def test_collects_each_needed_capability_once(tmp_path: Path):
    from omf.baseline.loader import CheckDef
    checks = (
        CheckDef("A", "a", "high", ("mikrotik",), ("users",), "no_generic_accounts", {}, {"generic": "x"}),
        CheckDef("B", "b", "high", ("mikrotik",), ("users",), "no_generic_accounts", {}, {"generic": "x"}),
    )
    store = AuditStore(tmp_path, "mikrotik", datetime.now(timezone.utc))
    adapter = FakeAdapter()
    Runner(adapter, checks, store).run()
    assert adapter.calls == ["users"]


def test_unimplemented_capability_skips_check(tmp_path: Path):
    from omf.baseline.loader import CheckDef
    checks = (CheckDef("A", "a", "high", ("mikrotik",), ("dns",), "dns_configured", {}, {"generic": "x"}),)
    store = AuditStore(tmp_path, "mikrotik", datetime.now(timezone.utc))
    adapter = FakeAdapter(implemented=frozenset())
    result = Runner(adapter, checks, store).run()
    assert result.findings[0].status == "skipped"
    assert adapter.calls == []


def test_collect_failure_errors_dependents(tmp_path: Path):
    from omf.baseline.loader import CheckDef
    checks = (CheckDef("A", "a", "medium", ("mikrotik",), ("ntp",), "ntp_configured", {}, {"generic": "x"}),)
    store = AuditStore(tmp_path, "mikrotik", datetime.now(timezone.utc))
    adapter = FakeAdapter(fail=frozenset({"ntp"}))
    result = Runner(adapter, checks, store).run()
    assert result.findings[0].status == "error"
    assert (store.path / "findings.json").is_file()
```

For the first test, `no_generic_accounts` will actually run — alice is not admin so PASS. That is fine.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_runner.py -v`  
Expected: FAIL — runner missing.

- [ ] **Step 3: Implement `CollectError`, `ProbeError`, `VendorAdapter` protocol, and `Runner`.** Emit `on_event({"phase": "collect"|"eval", ...})` without host or secrets.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_runner.py -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/omf/adapters/base.py src/omf/adapters/__init__.py src/omf/runner.py tests/test_runner.py
git commit -m "feat: run baseline with one collect per capability"
```

---

### Task 12: Normalize helpers + MikroTik fixtures

**Files:**
- Create: `src/omf/adapters/normalize.py`
- Create: `src/omf/adapters/mikrotik.py` (normalize functions only in this task; HTTP in Task 14)
- Create: `tests/adapters/fixtures/mikrotik/*.json` (one file per capability, samples below)
- Test: `tests/adapters/test_mikrotik_normalize.py`

**Interfaces:**
- Consumes: capability models
- Produces:

```python
def as_any_token(value: object) -> str
# empty, *, all, any, 0.0.0.0/0, ::/0 → "any"; else str(value)

def mikrotik_users(raw: object) -> UserList
def mikrotik_admin_settings(identity_raw: object, settings_raw: object) -> AdminSettings
def mikrotik_services(raw: object) -> ServiceList
def mikrotik_ntp(raw: object) -> NtpConfig
def mikrotik_dns(raw: object) -> DnsConfig
def mikrotik_logging(logging_raw: object, actions_raw: object) -> LoggingConfig
def mikrotik_snmp(snmp_raw: object, communities_raw: object) -> SnmpConfig
def mikrotik_filter(raw: object) -> PolicyList
def mikrotik_system(raw: object) -> SystemInfo
```

Mapping rules:

- users: RouterOS `/rest/user` list; `disabled=true` → `enabled=False`; `group` string → `groups=(group,)`.
- admin_settings: identity `name` → hostname; settings `minimum-timeout` or `session-timeout` if present, else `None`.
- services: `disabled`; `address` empty or `0.0.0.0/0` → `listen=all` else `restricted`; `port` int.
- ntp: `enabled=true` plus `servers` list or `server` field.
- dns: `servers` comma-separated string or list.
- logging: `local_enabled=True` if any rule action is `memory` or `disk`; remote targets = action targets that look like remote (`remote` or have `remote` address).
- snmp: `enabled`; communities `name`, `security`/`version`.
- filter: `action` (`accept`/`drop`/`reject`→`deny`/`!`→`other`); `src-address`, `dst-address`, `protocol`/`dst-port` → service; apply `as_any_token`.
- system: `version` → firmware; `board-name` → model.

- [ ] **Step 1: Write fixtures + failing tests**

`tests/adapters/fixtures/mikrotik/user.json`:

```json
[{"name": "admin", "group": "full", "disabled": "false"}]
```

`tests/adapters/fixtures/mikrotik/ip_service.json`:

```json
[
  {"name": "www", "port": "80", "disabled": "false", "address": ""},
  {"name": "www-ssl", "port": "443", "disabled": "false", "address": "10.0.0.0/24"}
]
```

`tests/adapters/fixtures/mikrotik/ntp_client.json`:

```json
{"enabled": "true", "servers": ["1.1.1.1"]}
```

`tests/adapters/fixtures/mikrotik/ip_dns.json`:

```json
{"servers": "8.8.8.8,1.1.1.1"}
```

`tests/adapters/fixtures/mikrotik/system_identity.json`:

```json
{"name": "MikroTik"}
```

`tests/adapters/fixtures/mikrotik/user_settings.json`:

```json
{"minimum-timeout": "10m"}
```

`tests/adapters/fixtures/mikrotik/system_logging.json`:

```json
[{"topics": "info", "action": "memory"}]
```

`tests/adapters/fixtures/mikrotik/system_logging_action.json`:

```json
[{"name": "memory", "target": "memory"}, {"name": "remote", "target": "remote", "remote": "10.0.0.9"}]
```

`tests/adapters/fixtures/mikrotik/snmp.json`:

```json
{"enabled": "true"}
```

`tests/adapters/fixtures/mikrotik/snmp_community.json`:

```json
[{"name": "public", "security": "none"}]
```

`tests/adapters/fixtures/mikrotik/ip_firewall_filter.json`:

```json
[
  {"chain": "forward", "action": "accept", "src-address": "0.0.0.0/0", "dst-address": "", "protocol": ""},
  {"chain": "forward", "action": "drop"}
]
```

`tests/adapters/fixtures/mikrotik/system_resource.json`:

```json
{"version": "7.16.1", "board-name": "RB5009"}
```

```python
# tests/adapters/test_mikrotik_normalize.py
import json
from pathlib import Path
from omf.adapters.mikrotik import (
    mikrotik_users, mikrotik_services, mikrotik_ntp, mikrotik_dns,
    mikrotik_admin_settings, mikrotik_logging, mikrotik_snmp,
    mikrotik_filter, mikrotik_system,
)

FIX = Path(__file__).parent / "fixtures" / "mikrotik"

def load(name: str):
    return json.loads((FIX / name).read_text())

def test_users():
    users = mikrotik_users(load("user.json"))
    assert users.users[0].name == "admin"
    assert users.users[0].enabled is True
    assert users.users[0].groups == ("full",)

def test_services_listen():
    svc = mikrotik_services(load("ip_service.json"))
    by_name = {s.name: s for s in svc.services}
    assert by_name["www"].listen == "all"
    assert by_name["www-ssl"].listen == "restricted"

def test_ntp_dns_system():
    assert mikrotik_ntp(load("ntp_client.json")).servers == ("1.1.1.1",)
    assert mikrotik_dns(load("ip_dns.json")).servers == ("8.8.8.8", "1.1.1.1")
    info = mikrotik_system(load("system_resource.json"))
    assert info.firmware.startswith("7.16")

def test_filter_any_and_drop():
    policies = mikrotik_filter(load("ip_firewall_filter.json"))
    assert policies.policies[0].src == ("any",)
    assert policies.policies[0].action == "accept"
    assert policies.policies[1].action == "drop"

def test_admin_and_logging_and_snmp():
    admin = mikrotik_admin_settings(load("system_identity.json"), load("user_settings.json"))
    assert admin.hostname == "MikroTik"
    log = mikrotik_logging(load("system_logging.json"), load("system_logging_action.json"))
    assert log.local_enabled is True
    assert log.remote_targets
    snmp = mikrotik_snmp(load("snmp.json"), load("snmp_community.json"))
    assert snmp.communities[0].name == "public"
```

Timeout parse: `"10m"` → `600` seconds. Support `Ns`, `Nm`, `Nh` or a bare integer.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/adapters/test_mikrotik_normalize.py -v`  
Expected: FAIL — functions missing.

- [ ] **Step 3: Implement `as_any_token` and all `mikrotik_*` normalizers.** Accept either a list or a single dict (RouterOS REST sometimes returns one object).

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/adapters/test_mikrotik_normalize.py -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/omf/adapters/normalize.py src/omf/adapters/mikrotik.py tests/adapters
git commit -m "feat: normalize MikroTik REST payloads into frozen models"
```

---

### Task 13: Fortinet fixtures + normalize (including services synthesis)

**Files:**
- Modify: `src/omf/adapters/fortinet.py` (create)
- Create: `tests/adapters/fixtures/fortinet/*.json`
- Test: `tests/adapters/test_fortinet_normalize.py`

**Interfaces:**
- Consumes: `as_any_token`, capability models
- Produces:

```python
def forti_unwrap(raw: object) -> object  # if dict with "results", return results
def forti_users(raw: object) -> UserList
def forti_admin_settings(global_raw: object, admin_raw: object) -> AdminSettings
def forti_services(interface_raw: object, admin_raw: object) -> ServiceList
def forti_ntp(raw: object) -> NtpConfig
def forti_dns(raw: object) -> DnsConfig
def forti_logging(syslogd_raw: object, syslogd2_raw: object | None) -> LoggingConfig
def forti_snmp(sysinfo_raw: object, community_raw: object) -> SnmpConfig
def forti_filter(raw: object) -> PolicyList
def forti_system(raw: object) -> SystemInfo
```

FortiOS CMDB usually wraps `{ "results": ... }`.

Services synthesis (spec §13): protocols `https`, `ssh`, `http`, `telnet`, `ftp`. `enabled=True` if any interface `allowaccess` contains it. `listen=restricted` if **every enabled admin** has at least one non-empty `trusthostN` that is not `0.0.0.0/0`. `listen=all` if any enabled admin has empty trusthosts or a `0.0.0.0/0` trusthost. `listen=unknown` if admin objects have **no** `trusthost*` keys at all.

Users: `name`, `accprofile` → groups; treat missing `q_origin_key` fine; disabled if `q_name` unused — use `trusthost` only for services. Admin `disable` / `enable` if present.

NTP: `ntpsync` enable + `ntpserver` list. DNS: `primary`/`secondary`. Logging: `status=enable` on syslogd → remote target = `server`. Local logging: `local_enabled=True` if we cannot prove it off (FortiOS always logs locally) — **lock:** `local_enabled=True` unless `global` says otherwise; fixtures without a disable flag → True. SNMP: `status` on sysinfo; communities names + `query-v1-status` etc. → version `1`/`2`/`3`. Policies: `srcaddr`/`dstaddr`/`service` as list of `{name}`; `action=accept|deny`; `status=enable`. `all` → `any`. System: `version` / `serial` ignored for firmware string `version`.

- [ ] **Step 1: Write fixtures and failing tests**

`tests/adapters/fixtures/fortinet/admin.json`:

```json
{"results": [{"name": "admin", "accprofile": "super_admin"}]}
```

`tests/adapters/fixtures/fortinet/interface.json`:

```json
{"results": [{"name": "wan1", "allowaccess": "ping https http ssh"}]}
```

`tests/adapters/fixtures/fortinet/global.json`:

```json
{"results": {"hostname": "FortiGate", "admintimeout": 5}}
```

`tests/adapters/fixtures/fortinet/ntp.json`:

```json
{"results": {"ntpsync": "enable", "ntpserver": [{"server": "1.1.1.1"}]}}
```

`tests/adapters/fixtures/fortinet/dns.json`:

```json
{"results": {"primary": "1.1.1.1", "secondary": "8.8.8.8"}}
```

`tests/adapters/fixtures/fortinet/syslogd.json`:

```json
{"results": {"status": "enable", "server": "10.0.0.9"}}
```

`tests/adapters/fixtures/fortinet/snmp_sysinfo.json`:

```json
{"results": {"status": "enable"}}
```

`tests/adapters/fixtures/fortinet/snmp_community.json`:

```json
{"results": [{"name": "public"}]}
```

`tests/adapters/fixtures/fortinet/policy.json`:

```json
{"results": [{"policyid": 1, "status": "enable", "action": "accept", "srcaddr": [{"name": "all"}], "dstaddr": [{"name": "all"}], "service": [{"name": "ALL"}]}]}
```

`tests/adapters/fixtures/fortinet/status.json`:

```json
{"version": "v7.4.4", "hostname": "FortiGate"}
```

```python
# tests/adapters/test_fortinet_normalize.py
import json
from pathlib import Path
from omf.adapters.fortinet import (
    forti_users, forti_admin_settings, forti_services, forti_ntp, forti_dns,
    forti_logging, forti_snmp, forti_filter, forti_system,
)

FIX = Path(__file__).parent / "fixtures" / "fortinet"

def load(name: str):
    return json.loads((FIX / name).read_text())

def test_users_default_admin():
    assert forti_users(load("admin.json")).users[0].name == "admin"

def test_services_listen_all_without_trusthost():
    svc = forti_services(load("interface.json"), load("admin.json"))
    by_name = {s.name: s for s in svc.services}
    assert by_name["https"].enabled is True
    assert by_name["https"].listen == "all"
    assert by_name["http"].enabled is True

def test_filter_all_becomes_any():
    policies = forti_filter(load("policy.json"))
    assert policies.policies[0].src == ("any",)
    assert policies.policies[0].dst == ("any",)
    assert policies.policies[0].service == ("any",)
    assert policies.policies[0].action == "accept"

def test_ntp_dns_log_snmp_system_admin():
    assert forti_ntp(load("ntp.json")).enabled is True
    assert forti_dns(load("dns.json")).servers[0] == "1.1.1.1"
    log = forti_logging(load("syslogd.json"), None)
    assert log.remote_targets
    assert forti_snmp(load("snmp_sysinfo.json"), load("snmp_community.json")).communities[0].name == "public"
    assert forti_system(load("status.json")).firmware.startswith("v7.4")
    admin = forti_admin_settings(load("global.json"), load("admin.json"))
    assert admin.hostname == "FortiGate"
    assert admin.idle_timeout_seconds == 300
```

`admintimeout: 5` is minutes → `300` seconds.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/adapters/test_fortinet_normalize.py -v`  
Expected: FAIL — module missing.

- [ ] **Step 3: Implement Fortinet normalizers** and commit the JSON fixtures as used by the tests.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/adapters/test_fortinet_normalize.py -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/omf/adapters/fortinet.py tests/adapters/fixtures/fortinet tests/adapters/test_fortinet_normalize.py
git commit -m "feat: normalize FortiOS REST payloads and synthesize services"
```

---

### Task 14: HTTP adapters (mocked httpx)

**Files:**
- Modify: `src/omf/adapters/mikrotik.py` (add `MikrotikAdapter`)
- Modify: `src/omf/adapters/fortinet.py` (add `FortinetAdapter`)
- Create: `src/omf/adapters/factory.py` — `build_adapter(session: Session) -> VendorAdapter`
- Test: `tests/adapters/test_http_adapters.py`

**Interfaces:**
- Consumes: `Session`, normalizers, `CollectError`, `ProbeError`, `VendorAdapter`
- Produces:

```python
class MikrotikAdapter:
    vendor: Literal["mikrotik"]
    def __init__(self, session: Session, client: httpx.Client): ...
    # probe GET /rest/system/identity
    # collect uses spec §13 paths; Basic auth from session.username/password
    # token ignored

class FortinetAdapter:
    vendor: Literal["fortinet"]
    def __init__(self, session: Session, client: httpx.Client): ...
    # if session.token: Authorization Bearer
    # else POST /logincheck then cookie
    # probe GET /api/v2/monitor/system/status
    # close: GET /logout if session-login was used

def build_adapter(session: Session, client: httpx.Client | None = None) -> VendorAdapter
```

Timeouts: `httpx.Timeout(30.0, connect=15.0)`. `verify=session.verify_tls`. Base URL = `session.url`. `implemented()` returns all nine capabilities.

Do **not** log the full URL. Events from adapters should expose `path` only; the TUI will print `[collect] GET /rest/user 200 84ms`. Adapter methods can return timing via a callback or set `self.last_call = {method, path, status, ms}` for the runner to pick up. **Lock:** after each HTTP call set `adapter.last_call: dict`.

- [ ] **Step 1: Write failing HTTP tests with `httpx.MockTransport`**

```python
# tests/adapters/test_http_adapters.py
import json
from pathlib import Path
import httpx
from omf.session import Session
from omf.adapters.mikrotik import MikrotikAdapter
from omf.adapters.fortinet import FortinetAdapter
from omf.adapters.base import ProbeError

MT = Path(__file__).parent / "fixtures" / "mikrotik"


def mt_session() -> Session:
    return Session("mikrotik", "https://192.0.2.1", "u", "p", "", True, "en")


def test_mikrotik_probe_ok_and_collect_users():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("authorization", "").lower().startswith("basic")
        assert request.url.host == "192.0.2.1"
        if request.url.path == "/rest/system/identity":
            return httpx.Response(200, json={"name": "fw"})
        if request.url.path == "/rest/user":
            return httpx.Response(200, json=json.loads((MT / "user.json").read_text()))
        return httpx.Response(404, json={})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://192.0.2.1")
    ad = MikrotikAdapter(mt_session(), client)
    ad.probe()
    ev, raw = ad.collect("users")
    assert ev.payload.users[0].name == "admin"
    assert isinstance(raw, list)
    client.close()


def test_mikrotik_probe_401():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": 401})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://192.0.2.1")
    ad = MikrotikAdapter(mt_session(), client)
    try:
        ad.probe()
        raise AssertionError("should have failed")
    except ProbeError as exc:
        assert exc.status == 401
        assert exc.path == "/rest/system/identity"
    client.close()


def test_fortinet_bearer_no_logincheck():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        assert request.headers.get("authorization") == "Bearer tok"
        if request.url.path == "/api/v2/monitor/system/status":
            return httpx.Response(200, json={"version": "v7.4.4"})
        return httpx.Response(404)

    session = Session("fortinet", "https://192.0.2.2", "u", "p", "tok", True, "en")
    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://192.0.2.2")
    ad = FortinetAdapter(session, client)
    ad.probe()
    assert "/logincheck" not in seen
    client.close()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/adapters/test_http_adapters.py -v`  
Expected: FAIL — adapter classes missing.

- [ ] **Step 3: Implement HTTP adapters.** GET only except FortiOS `/logincheck` (and logout). Map collect capability → path(s) from spec §13. On non-2xx raise `CollectError`/`ProbeError`. `build_adapter` constructs a default `httpx.Client` when `client is None`.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/adapters -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/omf/adapters tests/adapters/test_http_adapters.py
git commit -m "feat: add MikroTik and Fortinet REST adapters"
```

---

### Task 15: Skeleton report + local header + destokenize

**Files:**
- Create: `src/omf/agent/__init__.py`
- Create: `src/omf/agent/report.py`
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: `CheckResult`, `CheckDef`, `Redactor`, `mitigation_for`
- Produces:

```python
def skeleton_body(findings: list[CheckResult], checks: tuple[CheckDef, ...], vendor: str) -> str
def wrap_report(body: str, *, vendor: str, url: str, started_at: datetime, version: str) -> str
def finalize_report(body: str, redactor: Redactor, **wrap_kwargs) -> str
```

`skeleton_body` starts with the line `Narrative skipped`, then a counts line, a markdown table of all findings (`id|status|severity|title|diagnostic`), then one `### {id} — {title}` section per non-pass check with verbatim `mitigation_for`. Closing line: `This was a read-only assessment. Mitigations are examples. The auditor is responsible for any change.`

`wrap_report` prepends:

```markdown
# OH MY FIREWALL audit report

- Vendor: {vendor}
- Target: {url}
- Date: {started_at iso}
- Tool: OMF {version}

```

`finalize_report` = `wrap_report(redactor.destokenize(body), ...)`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_report.py
from datetime import datetime, timezone
from omf.agent.report import skeleton_body, wrap_report, finalize_report
from omf.schema.evidence import CheckResult
from omf.baseline.loader import load_catalog
from omf.redactor import Redactor


def test_skeleton_contains_all_findings_and_banner():
    checks = load_catalog()
    findings = [
        CheckResult(check_id="FW-ADM-001", status="fail", severity="high",
                    diagnostic="enabled user matches vendor default name 'admin'",
                    capability_refs=("users",), observed={}),
        CheckResult(check_id="FW-SYS-001", status="pass", severity="info",
                    diagnostic="firmware 7.16", capability_refs=("system_info",), observed={}),
    ]
    body = skeleton_body(findings, checks, "mikrotik")
    assert body.startswith("Narrative skipped")
    assert "FW-ADM-001" in body
    assert "FW-SYS-001" in body
    assert "Rename the default admin" in body
    assert "### FW-SYS-001" not in body
    assert "read-only" in body.lower()


def test_wrap_inserts_url_only_in_header():
    md = wrap_report("BODY", vendor="mikrotik", url="https://192.0.2.1",
                     started_at=datetime(2026, 8, 18, tzinfo=timezone.utc), version="0.1.0")
    assert md.split("BODY")[0].count("https://192.0.2.1") == 1
    assert "BODY" in md


def test_finalize_destokenizes():
    r = Redactor()
    red = r.redact_text("host 10.9.8.7")
    out = finalize_report(red, r, vendor="fortinet", url="https://fw",
                          started_at=datetime.now(timezone.utc), version="0.1.0")
    assert "10.9.8.7" in out
    assert "[IP_" not in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_report.py -v`  
Expected: FAIL — module missing.

- [ ] **Step 3: Implement report writers.**

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_report.py -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/omf/agent/report.py src/omf/agent/__init__.py tests/test_report.py
git commit -m "feat: write skeleton markdown report with local URL header"
```

---

### Task 16: Pydantic AI tools and LLM boundary

**Files:**
- Create: `src/omf/agent/tools.py`
- Create: `src/omf/agent/llm.py`
- Test: `tests/test_llm_boundary.py`

**Interfaces:**
- Consumes: redacted findings (dicts), redacted evidence (dicts), catalog, `AuditStore`
- Produces:

```python
@dataclass
class AnalysisContext:
    findings: list[dict]
    evidence: dict[str, dict]
    checks: tuple[CheckDef, ...]
    vendor: str
    language: str
    submitted: list[str]

def make_tools(ctx: AnalysisContext) -> list  # pydantic-ai Tool wrappers OR plain functions used by the agent

def list_findings(ctx) -> list[dict]          # id, status, severity, title
def get_finding(ctx, check_id: str) -> dict
def get_redacted_evidence(ctx, capability: str) -> dict
def get_mitigation(ctx, check_id: str) -> str
def submit_report(ctx, markdown: str) -> str

def build_agent(ctx: AnalysisContext, settings: LlmSettings)
def run_analysis(ctx, settings) -> str   # submitted markdown; one retry on failure
```

`build_agent` must not receive `Session`, `token_map`, adapter, or URL. System prompt (exact English, plus `{language}`):

```
You write a firewall audit report in language code: {language}.
Use only tool data. Adapt catalog mitigations to the redacted evidence.
Do not invent vendor CLI or API beyond that mitigation text.
State that mitigations are examples and the auditor owns any change.
Do not ask for credentials. Do not guess hidden IPs, hostnames, or URLs.
Call submit_report with the full markdown body (no title header).
```

If `settings.is_configured()` is false, `run_analysis` raises `LlmNotConfigured` and the TUI uses the skeleton (Task 17).

- [ ] **Step 1: Write the failing boundary tests**

```python
# tests/test_llm_boundary.py
import json
from omf.agent.tools import AnalysisContext, list_findings, get_finding, get_redacted_evidence, get_mitigation, submit_report
from omf.baseline.loader import load_catalog
from omf.redactor import Redactor


def _ctx():
    r = Redactor()
    findings = [r.redact_obj({
        "check_id": "FW-ADM-001",
        "status": "fail",
        "severity": "high",
        "title": "No generic default admin username",
        "diagnostic": "enabled user matches vendor default name 'admin'",
        "observed": {"names": ["admin"]},
    })]
    evidence = {"users": r.redact_obj({"users": [{"name": "admin", "enabled": True}]})}
    return AnalysisContext(findings, evidence, load_catalog(), "mikrotik", "ca", []), r


def test_tools_return_redacted_only():
    ctx, r = _ctx()
    listed = list_findings(ctx)
    assert listed[0]["check_id"] == "FW-ADM-001"
    finding = get_finding(ctx, "FW-ADM-001")
    ev = get_redacted_evidence(ctx, "users")
    blob = json.dumps({"listed": listed, "finding": finding, "ev": ev, "mit": get_mitigation(ctx, "FW-ADM-001")})
    assert "token_map" not in blob
    assert "password" not in blob
    assert "192." not in blob
    dumped = json.dumps(r.token_map())
    assert dumped not in blob


def test_submit_appends():
    ctx, _ = _ctx()
    submit_report(ctx, "# body")
    assert ctx.submitted == ["# body"]


def test_build_agent_has_no_session_attr():
    from omf.agent.llm import build_agent
    from omf.config import LlmSettings
    ctx, _ = _ctx()
    settings = LlmSettings("http://example", "sk-test", "model", "openai")
    agent = build_agent(ctx, settings)
    assert not hasattr(agent, "session")
    assert not hasattr(agent, "token_map")
    tools_src = " ".join(getattr(t, "__name__", str(t)) for t in (
        list_findings, get_finding, get_redacted_evidence, get_mitigation, submit_report,
    ))
    assert "token_map" not in tools_src
```

Also add a test that `run_analysis` retries once: monkeypatch the agent `run` to fail then succeed.

For pydantic-ai, construct with `OpenAIChatModel` / `AnthropicModel` using `base_url` from settings. If the exact class names differ in the pinned version, adapt to that version’s documented OpenAI-compatible constructor — **do not** invent a second HTTP client. Tools are the five functions closed over `ctx`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_llm_boundary.py -v`  
Expected: FAIL — tools missing.

- [ ] **Step 3: Implement tools + `build_agent` + `run_analysis` (try/except, one retry, then raise).**

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_llm_boundary.py tests/test_report.py -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/omf/agent/tools.py src/omf/agent/llm.py tests/test_llm_boundary.py
git commit -m "feat: add redacted-only analysis tools and LLM agent"
```

---

### Task 17: TUI wiring and end-to-end (fake adapter)

**Files:**
- Create: `src/omf/tui.py`
- Create: `src/omf/pipeline.py` — orchestrates probe → runner → redact → report (no Rich)
- Modify: `src/omf/cli.py` (`run_tui` imports `omf.tui.run`)
- Test: `tests/test_pipeline.py`

**Interfaces:**
- Consumes: all previous units
- Produces:

```python
# pipeline.py — unit-tested, no Rich
def run_audit(
    session: Session,
    store: AuditStore,
    adapter: VendorAdapter,
    llm: LlmSettings,
    on_event: Callable[[dict], None],
) -> Path:
    """probe, run, redact, write redacted/ + token_map, write report.md.
    Never writes session.url to meta.json.
    On LlmNotConfigured or analysis failure after retry: skeleton_body.
    Always session.clear_secrets() in a finally block.
    Returns path to report.md.
    """

# tui.py
def run() -> int:
    # load prefs; print DISCLAIMER_TEXT if needs_disclaimer; y/n; persist
    # refused → return 1
    # prompt vendor/url/user/password/token/verify_tls/language (defaults from prefs)
    # build Session, adapter, store under Path.cwd()/audits
    # Rich Live: phase, counters, table, last 20 events
    # call run_audit(...)
    # print report path
    # save last_vendor + language
```

TUI event format printed: `[collect] GET {path} {status} {ms}ms` — **path only**.

- [ ] **Step 1: Write the failing pipeline test**

```python
# tests/test_pipeline.py
from datetime import datetime, timezone
from pathlib import Path
from omf.pipeline import run_audit
from omf.session import Session
from omf.store import AuditStore
from omf.config import LlmSettings
from omf.schema.capabilities import (
    User, UserList, AdminSettings, Service, ServiceList, NtpConfig, DnsConfig,
    LoggingConfig, SnmpConfig, Policy, PolicyList, SystemInfo,
)
from omf.schema.evidence import Evidence
from omf.adapters.base import CollectError


class FullFake:
    vendor = "mikrotik"

    def probe(self): return None
    def close(self): return None
    def implemented(self):
        return frozenset({
            "users", "admin_settings", "services", "ntp", "dns",
            "logging", "snmp", "firewall_filter", "system_info",
        })

    def collect(self, capability: str):
        now = datetime.now(timezone.utc)
        payloads = {
            "users": UserList(users=(User(name="admin", enabled=True, groups=("full",)),)),
            "admin_settings": AdminSettings(hostname="MikroTik", idle_timeout_seconds=None),
            "services": ServiceList(services=(Service(name="telnet", enabled=True, port=23, listen="all"),)),
            "ntp": NtpConfig(enabled=False, servers=()),
            "dns": DnsConfig(servers=("1.1.1.1",)),
            "logging": LoggingConfig(local_enabled=True, remote_targets=()),
            "snmp": SnmpConfig(enabled=False, communities=()),
            "firewall_filter": PolicyList(policies=(
                Policy(id="1", enabled=True, action="accept", src=("any",), dst=("any",), service=("any",)),
            )),
            "system_info": SystemInfo(firmware="7.16.1", model="RB"),
        }
        payload = payloads[capability]
        return Evidence(capability=capability, vendor="mikrotik", collected_at=now, payload=payload), {"cap": capability}


def test_pipeline_skeleton_report_and_no_secrets_on_disk(tmp_path: Path):
    session = Session("mikrotik", "https://192.0.2.8", "admin", "s3cret", "tokentok", True, "ca")
    store = AuditStore(tmp_path, "mikrotik", datetime.now(timezone.utc))
    llm = LlmSettings(None, None, None, "openai")
    events = []
    report = run_audit(session, store, FullFake(), llm, events.append)
    text = report.read_text()
    assert "Narrative skipped" in text
    assert "https://192.0.2.8" in text
    assert "FW-ADM-001" in text
    disk = "\n".join(p.read_text() for p in store.path.rglob("*") if p.is_file() and p.name != "report.md")
    assert "s3cret" not in disk
    assert "tokentok" not in disk
    meta = (store.path / "meta.json").read_text()
    assert "192.0.2.8" not in meta
    assert session.password == ""
    assert any(e.get("phase") == "collect" for e in events)
    findings = (store.path / "findings.json").read_text()
    assert '"fail"' in findings
    assert (store.path / "redacted" / "findings.json").is_file()
    assert (store.path / "token_map.json").is_file()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_pipeline.py -v`  
Expected: FAIL — pipeline missing.

- [ ] **Step 3: Implement `run_audit`:** write meta `{vendor, started_at, report_language, tool_version, tls_verify}` only; redact all findings + evidence; write `redacted/` and `token_map`; if llm configured try `run_analysis` then `finalize_report`; else skeleton + `finalize_report`; `finally: session.clear_secrets(); adapter.close()`.

Implement `tui.py` with `rich.prompt.Prompt` / `Confirm` and a `Live` renderable: phase string, counters from findings-so-far, a table of check id+status, last 20 event lines. Keep TUI thin: it only collects wizard fields and calls `run_audit`. On `ProbeError`, print `probe failed: {status} {path}` and return 1 (after clear). `KeyboardInterrupt` → return 1 after clear.

Wire `run_tui` → `omf.tui.run`.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_pipeline.py tests/test_cli.py -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/omf/pipeline.py src/omf/tui.py src/omf/cli.py tests/test_pipeline.py
git commit -m "feat: wire audit pipeline and Rich TUI entry"
```

---

### Task 18: README + launcher smoke + full unit suite

**Files:**
- Modify: `README.md`
- Test: none new; run the full suite and a launcher smoke

**Interfaces:**
- Consumes: working `./omf help|install|doctor`
- Produces: README that documents only the four commands, `.env` vars, and that the tool is read-only.

- [ ] **Step 1: Write README**

```markdown
# omf

OH MY FIREWALL — read-only firewall audit agent (MikroTik RouterOS 7+ and Fortinet FortiOS).

## Setup

```bash
# requires https://docs.astral.sh/uv/
./omf install
./omf doctor
cp .env.example .env   # optional; without it you still get findings + a skeleton report
./omf
```

## Commands

| Command | Purpose |
|---|---|
| `./omf` | Audit TUI (English) |
| `./omf install` | `uv sync --all-extras --all-groups` |
| `./omf doctor` | What is missing (never talks to a firewall) |
| `./omf help` | Help |

Firewall credentials are never stored. The model never receives URLs, credentials, raw dumps, or the token map.

See `docs/superpowers/specs/2026-08-18-omf-firewall-audit-agent-design.md`.
```

- [ ] **Step 2: Run the full unit suite**

Run: `uv run pytest -m "not integration" -v`  
Expected: PASS, no live network.

- [ ] **Step 3: Smoke the launcher**

Run: `./omf help`; `./omf doctor` (warnings for LLM are OK, exit 0 if uv+deps ok); `./omf nope` (exit 1).

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: document ./omf install doctor help and default TUI"
```

---

## Self-review (spec coverage)

| Spec section | Task |
|---|---|
| §1–2 goals / non-goals | Tasks 1, 17, 18 (no SSH/PDF/Textual/Haystack) |
| §3 secrets / read-only / TLS | 5, 10, 14, 16, 17 |
| §4 architecture | 11, 16, 17 |
| §5 matching | 7, 8, 11 |
| §6 models | 6 |
| §7 14 checks + mitigations | 7, 8 |
| §8 .env / config.yaml / disclaimer | 4, 17 |
| §9 store + pipeline | 10, 15, 17 |
| §10 redaction | 9, 15 |
| §11 agent tools | 16 |
| §12 CLI / doctor / TUI | 1, 2, 3, 17, 18 |
| §13 adapters + endpoints | 12, 13, 14 |
| §14 errors | 3, 4, 11, 14, 16, 17 |
| §15 tests | every task |
| §16 layout | file map |
| §17 success criteria | Task 17 pipeline test + Task 18 suite |

No `TBD` / `TODO` / “similar to Task N” leftovers. Signatures used later (`Session.clear_secrets`, `collect → (Evidence, raw)`, `LlmSettings.is_configured`, `AuditStore.write_meta`) match earlier tasks.
