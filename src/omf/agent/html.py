"""Self-contained HTML audit report. No JS, no CDN, no secrets."""

from __future__ import annotations

import getpass
import math
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from omf.schema.evidence import CheckResult

DISCLAIMER = (
    "This was a read-only assessment. Mitigations are examples. "
    "The auditor is responsible for any change."
)

_STATUS_ORDER = ("pass", "fail", "error", "skipped")
_SEV_ORDER = ("high", "medium", "low", "info")
_STATUS_COLOR = {
    "pass": "#027a48",
    "fail": "#b42318",
    "error": "#b54708",
    "skipped": "#667085",
}
_SEV_COLOR = {
    "high": "#b42318",
    "medium": "#dc6803",
    "low": "#ca8a04",
    "info": "#667085",
}
_CHECK_ID = re.compile(r"^[A-Z]{2,}(?:-[A-Z0-9]+)+-\d+$")


@dataclass(frozen=True)
class ReportStats:
    total: int
    by_status: dict[str, int]
    fail_by_severity: dict[str, int]


def summarize(findings: Sequence[CheckResult]) -> ReportStats:
    by_status = {key: 0 for key in _STATUS_ORDER}
    fail_by_severity = {key: 0 for key in _SEV_ORDER}
    for finding in findings:
        if finding.status in by_status:
            by_status[finding.status] += 1
        if finding.status == "fail" and finding.severity in fail_by_severity:
            fail_by_severity[finding.severity] += 1
    return ReportStats(total=len(findings), by_status=by_status, fail_by_severity=fail_by_severity)


def status_donut_svg(stats: ReportStats, copy: dict[str, str]) -> str:
    r, cx, cy = 36, 50, 50
    circ = 2 * math.pi * r
    total = stats.total
    track = (
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
        f'stroke="#e4e7ec" stroke-width="12"/>'
    )
    arcs: list[str] = []
    offset = 0.0
    if total:
        for key in _STATUS_ORDER:
            n = stats.by_status.get(key, 0)
            if not n:
                continue
            length = (n / total) * circ
            arcs.append(
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
                f'stroke="{_STATUS_COLOR[key]}" stroke-width="12" '
                f'stroke-dasharray="{length:.3f} {circ:.3f}" '
                f'stroke-dashoffset="{-offset:.3f}" '
                f'transform="rotate(-90 {cx} {cy})"/>'
            )
            offset += length
    legend_items = "".join(
        f'<li><span class="swatch" style="background:{_STATUS_COLOR[key]}"></span>'
        f'{_esc(copy.get(key, key))} {stats.by_status.get(key, 0)}</li>'
        for key in _STATUS_ORDER
    )
    return (
        f'<svg viewBox="0 0 100 100" role="img" aria-label="{_esc(copy.get("status", "Status"))}">'
        f"<title>{_esc(copy.get('status', 'Status'))}</title>{track}{''.join(arcs)}</svg>"
        f'<ul class="legend">{legend_items}</ul>'
    )


def severity_bars_svg(stats: ReportStats, copy: dict[str, str]) -> str:
    max_n = max(stats.fail_by_severity.values() or [0]) or 1
    rows: list[str] = []
    y = 8
    for key in _SEV_ORDER:
        n = stats.fail_by_severity.get(key, 0)
        width = 0 if n == 0 else max(4, int(120 * n / max_n))
        rows.append(
            f'<text x="0" y="{y + 11}" class="bar-label">{key}</text>'
            f'<rect x="44" y="{y}" width="{width}" height="14" rx="2" fill="{_SEV_COLOR[key]}"/>'
            f'<text x="{48 + width}" y="{y + 11}" class="bar-n">{n}</text>'
        )
        y += 22
    title = _esc(copy.get("severity", "Severity"))
    return (
        f'<svg viewBox="0 0 200 96" role="img" aria-label="{title}">'
        f"<title>{title}</title>{''.join(rows)}</svg>"
    )


def operator_username() -> str:
    try:
        name = getpass.getuser().strip()
    except Exception:
        name = ""
    if not name:
        name = (
            os.environ.get("USER")
            or os.environ.get("LOGNAME")
            or os.environ.get("USERNAME")
            or ""
        ).strip()
    return name or "unknown"


def _esc(value: object) -> str:
    from html import escape
    return escape(str(value), quote=True)


def _is_fence(line: str) -> bool:
    return line.strip().startswith("```")


def _heading_id(text: str) -> str | None:
    token = text.split(None, 1)[0] if text.strip() else ""
    return token if _CHECK_ID.match(token) else None


def markdown_to_html(text: str) -> str:
    lines = text.splitlines()
    heading_ids: set[str] = set()
    for line in lines:
        if line.startswith("### "):
            hid = _heading_id(line[4:])
            if hid:
                heading_ids.add(hid)
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        if _is_fence(line):
            i += 1
            code: list[str] = []
            while i < len(lines) and not _is_fence(lines[i]):
                code.append(lines[i])
                i += 1
            if i < len(lines):
                i += 1
            out.append("<pre><code>" + _esc("\n".join(code)) + "</code></pre>")
            continue
        if line.startswith("### "):
            title = line[4:]
            hid = _heading_id(title)
            if hid:
                out.append(f'<h3 id="{_esc(hid)}">{_inline(title)}</h3>')
            else:
                out.append(f"<h3>{_inline(title)}</h3>")
            i += 1
            continue
        if line.startswith("## "):
            out.append(f"<h2>{_inline(line[3:])}</h2>")
            i += 1
            continue
        if line.startswith("# "):
            out.append(f"<h1>{_inline(line[2:])}</h1>")
            i += 1
            continue
        if line.startswith("|"):
            rows: list[str] = []
            while i < len(lines) and lines[i].startswith("|"):
                cells = [cell.strip() for cell in lines[i].strip().strip("|").split("|")]
                if all(set(cell) <= set("-: ") and cell for cell in cells):
                    i += 1
                    continue
                tag = "th" if not rows else "td"
                rows.append(
                    "<tr>"
                    + "".join(_table_cell(tag, c, heading_ids) for c in cells)
                    + "</tr>"
                )
                i += 1
            out.append('<div class="table-wrap"><table>' + "".join(rows) + "</table></div>")
            continue
        if line.startswith("- "):
            items: list[str] = []
            while i < len(lines) and lines[i].startswith("- "):
                items.append(f"<li>{_inline(lines[i][2:])}</li>")
                i += 1
            out.append("<ul>" + "".join(items) + "</ul>")
            continue
        para: list[str] = []
        while (
            i < len(lines)
            and lines[i].strip()
            and not lines[i].startswith(("#", "|", "- "))
            and not _is_fence(lines[i])
        ):
            para.append(lines[i].strip())
            i += 1
        if not para:
            i += 1
            continue
        out.append("<p>" + _inline(" ".join(para)) + "</p>")
    return "\n".join(out)


def _codespan(text: str) -> str:
    parts = text.split("`")
    if len(parts) == 1 or len(parts) % 2 == 0:
        return text
    built: list[str] = []
    for idx, part in enumerate(parts):
        if idx % 2:
            built.append(f"<code>{part}</code>")
        else:
            built.append(part)
    return "".join(built)


def _table_cell(tag: str, text: str, heading_ids: set[str]) -> str:
    inner = _inline(text)
    if tag == "td" and text in heading_ids:
        inner = f'{inner} <a href="#{_esc(text)}" class="jump">#</a>'
    key = text.lower()
    if tag == "td" and key in _SEV_COLOR:
        return f'<{tag} class="sev-{key}">{inner}</{tag}>'
    return f"<{tag}>{inner}</{tag}>"


def _inline(text: str) -> str:
    escaped = _esc(text)
    # **bold** after escape so model asterisks cannot open tags
    parts = escaped.split("**")
    if len(parts) != 1 and len(parts) % 2:
        built: list[str] = []
        for idx, part in enumerate(parts):
            if idx % 2:
                built.append(f"<strong>{part}</strong>")
            else:
                built.append(part)
        escaped = "".join(built)
    return _codespan(escaped)


_CSS = """
:root { --fg:#1a1a1a; --muted:#667085; --line:#e4e7ec; --bg:#fff; }
html {
  font: 15px/1.5 "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  color: var(--fg); background: var(--bg);
}
body { max-width: 52rem; margin: 2rem auto; padding: 0 1.25rem 3rem; }
header h1 { margin: 0 0 .75rem; font-size: 1.6rem; }
.disclaimer {
  color: var(--muted); border: 1px solid var(--line); border-radius: 6px;
  padding: .65rem .85rem; margin: 0 0 1rem; font-size: .9rem;
}
.meta { list-style: none; padding: 0; margin: 0 0 1.5rem; color: var(--muted); }
.meta li { margin: .15rem 0; }
.kpis { display: flex; gap: .75rem; flex-wrap: wrap; }
.kpi { flex: 1 1 6rem; border: 1px solid var(--line); border-radius: 8px; padding: .75rem; }
.kpi-label { display: block; font-size: .8rem; color: var(--muted); }
.kpi-n { font-size: 1.6rem; font-weight: 650; }
.kpi-fail .kpi-n { color: #b42318; }
.kpi-pass .kpi-n { color: #027a48; }
.kpi-total { color: var(--muted); margin: .5rem 0 1rem; }
.charts { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin: 0 0 1.25rem; }
figure { margin: 0; border: 1px solid var(--line); border-radius: 8px; padding: .75rem; }
figcaption { font-weight: 600; margin-bottom: .5rem; }
.chart-row { display: flex; align-items: center; gap: .75rem; }
.chart-row svg { width: 8rem; height: 8rem; }
.legend { list-style: none; padding: 0; margin: 0; font-size: .9rem; }
.legend li { display: flex; align-items: center; gap: .4rem; margin: .2rem 0; }
.swatch { width: .7rem; height: .7rem; border-radius: 2px; display: inline-block; }
.bar-label, .bar-n { font-size: 10px; fill: var(--fg); }
.table-wrap { overflow-x: auto; max-width: 100%; margin: 1rem 0; }
table { border-collapse: collapse; width: max-content; min-width: 100%; margin: 0; }
th, td {
  border: 1px solid var(--line); padding: .5rem .65rem; text-align: left;
}
th {
  background: #f2f4f7; font-weight: 650; white-space: nowrap; vertical-align: bottom;
}
td {
  vertical-align: top; overflow-wrap: anywhere; word-break: break-word; max-width: 20rem;
}
.sev-high { color: #b42318; font-weight: 650; }
.sev-medium { color: #dc6803; font-weight: 650; }
.sev-low { color: #ca8a04; font-weight: 650; }
.sev-info { color: #667085; font-weight: 400; }
h2 { margin-top: 1.5rem; }
main h3 {
  margin: 2.75rem 0 1rem; padding-top: 1.75rem;
  border-top: 1px solid var(--line);
  scroll-margin-top: 1rem;
}
a.jump { color: var(--muted); text-decoration: none; margin-left: .15rem; }
a.jump:hover { color: var(--fg); }
code, pre { font-family: inherit; }
p code, li code, td code {
  background: #f2f4f7; padding: .1em .35em; border-radius: 4px; font-size: .9em;
}
pre {
  background: #f2f4f7; border: 1px solid var(--line); border-radius: 6px;
  padding: .75rem 1rem; overflow-x: auto; font-size: .85rem; line-height: 1.4;
  white-space: pre;
}
pre code { background: none; padding: 0; font-size: inherit; }
@media print {
  .charts { grid-template-columns: 1fr; break-inside: avoid; }
  .table-wrap { overflow: visible; }
  th { white-space: normal; }
}
@media (max-width: 40rem) { .charts { grid-template-columns: 1fr; } }
"""


def _inject_after_first_h2(body_html: str, dashboard: str) -> str:
    marker = "</h2>"
    idx = body_html.find(marker)
    if idx == -1:
        return dashboard + body_html
    end = idx + len(marker)
    return body_html[:end] + dashboard + body_html[end:]


def _dashboard(stats: ReportStats, copy: dict[str, str]) -> str:
    cards = "".join(
        f'<div class="kpi kpi-{key}"><span class="kpi-label">{_esc(copy[key])}</span>'
        f'<span class="kpi-n">{stats.by_status[key]}</span></div>'
        for key in _STATUS_ORDER
    )
    total = (
        f'<p class="kpi-total">{stats.total} {_esc(copy["checks"])}</p>'
    )
    return (
        f'<section class="dashboard">'
        f'<div class="kpis">{cards}</div>{total}'
        f'<div class="charts">'
        f'<figure><figcaption>{_esc(copy["status"])}</figcaption>'
        f'<div class="chart-row">{status_donut_svg(stats, copy)}</div></figure>'
        f'<figure><figcaption>{_esc(copy["severity"])}</figcaption>'
        f'{severity_bars_svg(stats, copy)}</figure>'
        f'</div></section>'
    )


def render_html_report(
    body: str,
    *,
    findings: Sequence[CheckResult],
    vendor: str,
    url: str,
    started_at: datetime,
    version: str,
    language: str,
) -> str:
    from omf.agent.report import copy_for  # lazy import to avoid cycle
    copy = copy_for(language)
    stats = summarize(findings)
    dashboard = _dashboard(stats, copy)
    body_html = markdown_to_html(body)
    body_html = _inject_after_first_h2(body_html, dashboard)
    title = copy["title"]
    disclaimer = f'<p class="disclaimer">{_esc(DISCLAIMER)}</p>'
    meta = (
        "<ul class=\"meta\">"
        f"<li>Author: {_esc(operator_username())}</li>"
        f"<li>Date: {_esc(started_at.date().isoformat())}</li>"
        f"<li>Target: {_esc(vendor)} · {_esc(url)}</li>"
        f"<li>Tool: OMF {_esc(version)}</li>"
        "</ul>"
    )
    return (
        "<!DOCTYPE html>\n"
        f"<html lang=\"{_esc(language)}\">\n"
        "<head><meta charset=\"utf-8\">"
        f"<title>{_esc(title)}</title>"
        f"<style>{_CSS}</style></head>\n"
        f"<body><header><h1>{_esc(title)}</h1>{disclaimer}{meta}</header>\n"
        f"<main>{body_html}</main></body></html>\n"
    )
