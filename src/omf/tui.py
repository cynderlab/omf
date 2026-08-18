from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console, Group
from rich.live import Live
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from omf import DISCLAIMER_TEXT, DISCLAIMER_VERSION
from omf.adapters.base import ProbeError
from omf.adapters.factory import build_adapter
from omf.baseline.loader import checks_for
from omf.config import (
    UserPrefs,
    load_llm_settings,
    load_user_prefs,
    needs_disclaimer,
    save_user_prefs,
)
from omf.pipeline import run_audit
from omf.session import Session
from omf.store import AuditStore
from omf.wizard import ValidationError, parse_language, parse_url, parse_vendor

_CONFIG_DIR = Path.home() / ".config" / "omf"


def run() -> int:
    console = Console()
    prefs, warning = load_user_prefs(_CONFIG_DIR)
    if warning:
        console.print(warning)
    if needs_disclaimer(prefs):
        console.print(DISCLAIMER_TEXT)
        try:
            accepted = Confirm.ask("Proceed", default=False)
        except (KeyboardInterrupt, EOFError):
            return 1
        if not accepted:
            return 1
        prefs.disclaimer_accepted = True
        prefs.disclaimer_version = DISCLAIMER_VERSION
        save_user_prefs(_CONFIG_DIR, prefs)

    session: Session | None = None
    adapter = None
    audit_started = False
    try:
        session = _prompt_session(prefs)
        if not session.verify_tls:
            console.print("Warning: TLS verification is disabled")
        adapter = build_adapter(session)
        store = AuditStore(Path.cwd() / "audits", session.vendor, datetime.now(timezone.utc))
        llm = load_llm_settings(Path.cwd(), _CONFIG_DIR)
        state = _LiveState()
        for check in checks_for(session.vendor):
            state.statuses[check.id] = ""
        with Live(state.render(), console=console, refresh_per_second=8) as live:
            def on_event(event: dict) -> None:
                state.handle(event)
                live.update(state.render())

            audit_started = True
            report = run_audit(session, store, adapter, llm, on_event)
        counts = Counter(state.statuses.values())
        print(
            f"PASS {counts.get('pass', 0)}  "
            f"FAIL {counts.get('fail', 0)}  "
            f"SKIP {counts.get('skipped', 0)}  "
            f"ERR {counts.get('error', 0)}"
        )
        print(report)
        prefs.last_vendor = session.vendor
        prefs.default_report_language = session.report_language
        save_user_prefs(_CONFIG_DIR, prefs)
        return 0
    except ProbeError as exc:
        print(f"probe failed: {exc.status} {exc.path}")
        return 1
    except (KeyboardInterrupt, EOFError):
        return 1
    finally:
        if not audit_started:
            if session is not None:
                session.clear_secrets()
            if adapter is not None:
                adapter.close()


def _prompt_session(prefs: UserPrefs) -> Session:
    vendor = _ask("Vendor (mikrotik/fortinet)", parse_vendor, prefs.last_vendor)
    url = _ask("Device URL", parse_url, None)
    username = Prompt.ask("Username", default="")
    password = Prompt.ask("Password", password=True, default="")
    token = Prompt.ask("API token (optional)", password=True, default="")
    verify_tls = Confirm.ask("Verify TLS certificates", default=True)
    language = _ask(
        "Report language (ca/es/en)",
        parse_language,
        prefs.default_report_language,
    )
    return Session(vendor, url, username, password, token, verify_tls, language)


def _ask(label: str, parser: Callable[[str], object], default: str | None):
    while True:
        raw = Prompt.ask(label, default=default) if default is not None else Prompt.ask(label)
        try:
            return parser(raw)
        except ValidationError as exc:
            print(exc)


class _LiveState:
    def __init__(self) -> None:
        self.phase = "starting"
        self.statuses: dict[str, str] = {}
        self.lines: list[str] = []

    def handle(self, event: dict) -> None:
        phase = event.get("phase")
        if isinstance(phase, str) and phase:
            self.phase = phase
        check_id = event.get("check_id")
        if phase == "eval" and isinstance(check_id, str):
            self.statuses[check_id] = str(event.get("status") or "")
        line = _format_event(event)
        if line:
            self.lines.append(line)
            self.lines = self.lines[-20:]

    def render(self) -> Group:
        counts = Counter(self.statuses.values())
        counters = (
            f"PASS {counts.get('pass', 0)}  "
            f"FAIL {counts.get('fail', 0)}  "
            f"SKIP {counts.get('skipped', 0)}  "
            f"ERR {counts.get('error', 0)}"
        )
        table = Table(show_header=True, header_style="bold")
        table.add_column("id")
        table.add_column("status")
        for check_id, status in self.statuses.items():
            table.add_row(check_id, status or "-")
        log = Text("\n".join(self.lines))
        return Group(Text(f"Phase: {self.phase}"), Text(counters), table, log)


def _format_event(event: dict) -> str:
    phase = str(event.get("phase") or "")
    if phase == "collect":
        method = event.get("method") or "GET"
        path = event.get("path") or event.get("capability") or ""
        status = "" if event.get("status") is None else str(event.get("status"))
        ms = event.get("ms")
        parts = [f"[{phase}]", str(method)]
        if path:
            parts.append(str(path))
        if status:
            parts.append(status)
        if ms is not None:
            parts.append(f"{ms}ms")
        return " ".join(parts)
    if phase == "eval":
        return f"[eval] {event.get('check_id', '')} {event.get('status', '')}".strip()
    if phase == "llm":
        tool = event.get("tool") or event.get("tool_name") or ""
        return f"[llm] {tool}".strip()
    if phase:
        return f"[{phase}]"
    return ""


__all__ = [
    "run",
]
