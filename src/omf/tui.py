"""English Rich + questionary TUI: banner, wizard, live audit, report path."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic

from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from omf import DISCLAIMER_TEXT, DISCLAIMER_VERSION
from omf.adapters.auth import AuthScheme, auth_schemes, scheme_by_id
from omf.adapters.base import ProbeError, VendorAdapter
from omf.adapters.factory import build_adapter
from omf.banner import print_banner
from omf.baseline.loader import checks_for, load_catalog
from omf.connect import (
    CONNECT_ACTIONS,
    URL_REACH_ACTIONS,
    check_host_reachable,
    explain_probe_error,
)
from omf.log import get_logger
from omf.menus import (
    LANGUAGE_OPTIONS,
    VENDOR_OPTIONS,
    MenuCancelled,
    confirm,
    select_value,
)
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
from omf.wizard import ValidationError, parse_url

_CONFIG_DIR = Path.home() / ".config" / "omf"
_log = get_logger("omf.tui")


def run() -> int:
    console = Console()
    print_banner(console)
    with console.status("[bold cyan]Loading baseline…", spinner="dots"):
        load_catalog()
    prefs, warning = load_user_prefs(_CONFIG_DIR)
    if warning:
        console.print(warning)
    if needs_disclaimer(prefs):
        console.print(DISCLAIMER_TEXT)
        try:
            accepted = confirm("Proceed with a read-only audit?", default=False)
        except (KeyboardInterrupt, EOFError, MenuCancelled):
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
        session = _prompt_session(console, prefs)
        _remember_target(prefs, session)
        if not session.verify_tls:
            console.print(
                "[dim]TLS certificate verification is off "
                "(self-signed management certs are accepted).[/dim]"
            )
        adapter = _connect_with_retry(console, session, prefs)
        if adapter is None:
            return 1
        _remember_target(prefs, session)
        store = AuditStore(Path.cwd() / "audits", session.vendor, datetime.now(timezone.utc))
        llm = load_llm_settings(Path.cwd(), _CONFIG_DIR)
        checks = checks_for(session.vendor)
        state = _LiveState({check.id: check.title for check in checks})
        with Live(state, console=console, refresh_per_second=8) as live:
            def on_event(event: dict) -> None:
                state.handle(event)
                live.refresh()

            audit_started = True
            report = run_audit(session, store, adapter, llm, on_event, skip_probe=True)
        _print_results(console, state, report)
        return 0
    except (KeyboardInterrupt, EOFError, MenuCancelled):
        return 1
    finally:
        if not audit_started:
            if session is not None:
                session.clear_secrets()
            if adapter is not None:
                adapter.close()


def _connect_with_retry(
    console: Console, session: Session, prefs: UserPrefs
) -> VendorAdapter | None:
    while True:
        adapter = build_adapter(session)
        _log.info("probing %s", session.vendor)
        _log.debug("probe url=%s user=%s", session.url, session.username)
        try:
            with console.status(f"[bold cyan]Connecting to {session.url}…"):
                adapter.probe()
        except ProbeError as exc:
            adapter.close()
            _log.warning("%s", explain_probe_error(exc))
            _log.debug("probe error status=%s path=%s msg=%s", exc.status, exc.path, exc.message)
            console.print("[bold red]Connection failed[/bold red]")
            console.print(explain_probe_error(exc))
            action = select_value("What next?", CONNECT_ACTIONS, "retry")
            if action == "abort":
                return None
            if action == "creds":
                creds = _prompt_credentials(
                    _resolve_auth_scheme(session.vendor),
                    default_username=session.username,
                )
                session.username = creds["username"]
                session.password = creds["password"]
                session.token = creds["token"]
            elif action == "url":
                session.url = _ask("Device URL", parse_url, session.url)
            _remember_target(prefs, session)
            continue
        _log.info("connected vendor=%s", session.vendor)
        console.print(f"[green]Connected to {session.url}[/green]")
        return adapter


def _prompt_session(console: Console, prefs: UserPrefs) -> Session:
    vendor = select_value("Vendor", VENDOR_OPTIONS, prefs.last_vendor)
    if vendor == "mikrotik":
        console.print(
            "[dim]MikroTik uses RouterOS REST "
            "(GET https://IP/rest/..., HTTP Basic on www-ssl). "
            "The binary API on tcp/8728 is not used.[/dim]"
        )
    url = _ask_reachable_url(console, prefs.last_url)
    creds = _prompt_credentials(
        _resolve_auth_scheme(vendor),
        default_username=prefs.last_username or "",
    )
    language = select_value(
        "Report language",
        LANGUAGE_OPTIONS,
        prefs.default_report_language,
    )
    verify_tls = confirm("Verify TLS certificates?", default=True)
    return Session(
        vendor,
        url,
        creds["username"],
        creds["password"],
        creds["token"],
        verify_tls,
        language,
    )


def _resolve_auth_scheme(vendor: str) -> AuthScheme:
    schemes = auth_schemes(vendor)
    if len(schemes) == 1:
        return schemes[0]
    selected = select_value(
        "Authentication",
        tuple((scheme.label, scheme.id) for scheme in schemes),
        schemes[0].id,
    )
    return scheme_by_id(vendor, selected)


def _remember_target(prefs: UserPrefs, session: Session) -> None:
    prefs.last_vendor = session.vendor
    prefs.last_url = session.url
    if session.username:
        prefs.last_username = session.username
    prefs.default_report_language = session.report_language
    save_user_prefs(_CONFIG_DIR, prefs)


def _prompt_credentials(scheme: AuthScheme, default_username: str = "") -> dict[str, str]:
    creds = {"username": "", "password": "", "token": ""}
    if "username" in scheme.fields:
        if default_username:
            creds["username"] = Prompt.ask("Username", default=default_username)
        else:
            creds["username"] = Prompt.ask("Username")
    if "password" in scheme.fields:
        creds["password"] = Prompt.ask("Password", password=True, default="")
    if "token" in scheme.fields:
        creds["token"] = Prompt.ask("API token", password=True, default="")
    return creds


def _ask_reachable_url(console: Console, default: str | None) -> str:
    while True:
        url = _ask("Device URL", parse_url, default)
        console.print(f"[dim]Using {url}[/dim]")
        with console.status(f"[bold cyan]Checking reachability of {url}…"):
            error = check_host_reachable(url)
        if error is None:
            console.print("[green]Host is reachable[/green]")
            return url
        _log.warning("%s", error)
        console.print(f"[bold red]{error}[/bold red]")
        action = select_value("What next?", URL_REACH_ACTIONS, "url")
        if action == "abort":
            raise MenuCancelled
        default = url


def _ask(label: str, parser: Callable[[str], object], default: str | None):
    while True:
        raw = Prompt.ask(label, default=default) if default is not None else Prompt.ask(label)
        try:
            return parser(raw)
        except ValidationError as exc:
            print(exc)


_STATUS_STYLE = {
    "pass": "bold green",
    "fail": "bold red",
    "error": "bold yellow",
    "skipped": "dim",
}

_PHASE_LABEL = {
    "collect": "Collecting evidence",
    "eval": "Evaluating checks",
    "redact": "Redacting",
    "llm": "Writing narrative",
    "report": "Saving report",
    "starting": "Starting",
}

_SPIN = ("●○○", "●●○", "●●●", "○●●", "○○●")
_ACTIVE_LLM = frozenset({"", "start", "retry", "tool"})


def _short_model(name: str) -> str:
    return name.rsplit("/", 1)[-1] if name else "configured-model"


def _tool_label(tool: str, check_id: str = "", capability: str = "") -> str:
    if tool == "list_findings":
        return "reading findings"
    if tool == "get_finding":
        return f"opening {check_id}" if check_id else "opening finding"
    if tool == "get_redacted_evidence":
        return f"reading evidence: {capability}" if capability else "reading evidence"
    if tool == "get_mitigation":
        return "looking up mitigation"
    if tool == "submit_report":
        return "submitting report"
    return tool or "thinking"


class _LiveState:
    def __init__(self, titles: dict[str, str], *, now: Callable[[], float] = monotonic) -> None:
        self.titles = titles
        self._now = now
        self.phase = "starting"
        self.activity = ""
        self.llm_model = ""
        self.llm_status = ""
        self.llm_detail = ""
        self.llm_tool = ""
        self.llm_tool_check = ""
        self.llm_tool_cap = ""
        self.llm_started_at: float | None = None
        self.rows: dict[str, dict[str, str]] = {
            check_id: {"status": "", "diagnostic": "", "severity": ""}
            for check_id in titles
        }

    def handle(self, event: dict) -> None:
        phase = event.get("phase")
        if isinstance(phase, str) and phase:
            self.phase = phase
        if phase == "collect":
            cap = event.get("capability") or event.get("path") or ""
            self.activity = f"GET {cap}" if cap else "collecting"
        check_id = event.get("check_id")
        if phase == "eval" and isinstance(check_id, str):
            self.rows[check_id] = {
                "status": str(event.get("status") or ""),
                "diagnostic": str(event.get("diagnostic") or ""),
                "severity": str(event.get("severity") or ""),
            }
            self.activity = f"{check_id} → {event.get('status')}"
        elif phase == "llm":
            self._handle_llm(event)
        elif phase in {"redact", "report"}:
            self.activity = _PHASE_LABEL.get(phase, phase)

    def _handle_llm(self, event: dict) -> None:
        status = str(event.get("status") or "start")
        self.llm_status = status
        if event.get("model"):
            self.llm_model = str(event["model"])
        if event.get("detail"):
            self.llm_detail = str(event["detail"])
        label = self._model_label()
        if status == "start":
            self.llm_started_at = self._now()
            self.llm_tool = ""
            self.llm_tool_check = ""
            self.llm_tool_cap = ""
            self.activity = f"generating via {label}"
        elif status == "tool":
            self.llm_tool = str(event.get("tool") or "")
            self.llm_tool_check = str(event.get("check_id") or "")
            self.llm_tool_cap = str(event.get("capability") or "")
            self.activity = _tool_label(
                self.llm_tool, self.llm_tool_check, self.llm_tool_cap
            )
        else:
            self.activity = {
                "done": f"received report from {label}",
                "skipped": "no LLM configured — skeleton report",
                "fallback": "LLM failed — skeleton report",
            }.get(status, status)

    def _model_label(self) -> str:
        return _short_model(self.llm_model) if self.llm_model else "LLM"

    def _elapsed_s(self) -> int:
        if self.llm_started_at is None:
            return 0
        return max(0, int(self._now() - self.llm_started_at))

    def _spin(self) -> str:
        started = self.llm_started_at if self.llm_started_at is not None else self._now()
        return _SPIN[int((self._now() - started) * 8) % len(_SPIN)]

    def __rich__(self) -> Group:
        return self.render()

    def render(self) -> Group:
        counts = Counter(row["status"] for row in self.rows.values() if row["status"])
        header = Text()
        if self.phase == "llm" and self.llm_status == "skipped":
            phase_label = "Narrative skipped"
        elif self.phase == "llm" and self.llm_status == "fallback":
            phase_label = "Narrative failed"
        else:
            phase_label = _PHASE_LABEL.get(self.phase, self.phase)
        header.append(phase_label, style="bold cyan")
        if self.activity:
            header.append(f"  ·  {self.activity}", style="dim")
        header.append("\n")
        header.append(f"PASS {counts.get('pass', 0)}", style="green")
        header.append("  ")
        header.append(f"FAIL {counts.get('fail', 0)}", style="red")
        header.append("  ")
        header.append(f"SKIP {counts.get('skipped', 0)}", style="dim")
        header.append("  ")
        header.append(f"ERR {counts.get('error', 0)}", style="yellow")

        table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
        table.add_column("Check", min_width=28)
        table.add_column("Sev", width=6)
        table.add_column("Result", width=8)
        for check_id, row in self.rows.items():
            status = row["status"]
            style = _STATUS_STYLE.get(status, "dim")
            title = self.titles.get(check_id, check_id)
            table.add_row(
                Text(title, overflow="ellipsis"),
                row["severity"] or "—",
                Text(status.upper() if status else "…", style=style),
            )
        parts: list = [header, table]
        if self.phase == "llm" and self.llm_status in _ACTIVE_LLM:
            label = _tool_label(self.llm_tool, self.llm_tool_check, self.llm_tool_cap)
            if not self.llm_tool:
                label = "thinking"
            body = Text()
            body.append(f"{self._spin()}  {label}\n", style="bold magenta")
            body.append(f"{self._model_label()} · {self._elapsed_s()}s\n", style="cyan")
            if self.llm_tool:
                body.append(f"last: {self.llm_tool}\n", style="dim")
            body.append("no secrets on the wire", style="dim")
            parts.append(
                Panel(
                    Align.center(body),
                    title="[bold magenta]Writing narrative[/]",
                    border_style="magenta",
                    padding=(0, 2),
                )
            )
        return Group(*parts)


def _print_results(console: Console, state: _LiveState, report: Path) -> None:
    fails = [
        (check_id, row)
        for check_id, row in state.rows.items()
        if row["status"] in {"fail", "error"}
    ]
    counts = Counter(row["status"] for row in state.rows.values() if row["status"])
    console.print()
    summary = Text()
    summary.append("Results  ", style="bold")
    summary.append(f"PASS {counts.get('pass', 0)}", style="bold green")
    summary.append("  ")
    summary.append(f"FAIL {counts.get('fail', 0)}", style="bold red")
    if counts.get("error"):
        summary.append("  ")
        summary.append(f"ERR {counts.get('error', 0)}", style="bold yellow")
    console.print(summary)
    console.print()

    if fails:
        table = Table(show_header=True, header_style="bold", title="Findings")
        table.add_column("Sev", width=6)
        table.add_column("Check")
        table.add_column("Why")
        for check_id, row in fails:
            table.add_row(
                row["severity"] or "—",
                state.titles.get(check_id, check_id),
                row["diagnostic"] or check_id,
            )
        console.print(table)
        console.print()

    if state.llm_status == "skipped":
        console.print("[dim]Narrative: skeleton (no LLM configured)[/dim]")
    elif state.llm_status == "fallback":
        console.print("[yellow]Narrative: skeleton (LLM failed)[/yellow]")
        if state.llm_detail:
            console.print(f"[dim]{state.llm_detail}[/dim]")
        console.print("[dim]Re-run with ./omf -v to see DEBUG on stderr.[/dim]")
    elif state.llm_model:
        console.print(f"[dim]Narrative: {state.llm_model}[/dim]")
    console.print(f"[bold]Report:[/bold] {report}")


__all__ = [
    "run",
]
