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

_STATUS_ORDER = ("fail", "pass", "error", "skipped")
_STRIP_ORDER = ("fail", "error", "skipped", "pass")
_SEV_ORDER = ("high", "medium", "low", "info")
_STATUS_COLOR = {
    "fail": "#d93025",
    "pass": "#1e8e3e",
    "error": "#e37400",
    "skipped": "#5f6368",
}
_SEV_COLOR = {
    "high": "#d93025",
    "medium": "#e37400",
    "low": "#f9ab00",
    "info": "#1a73e8",
}
_CHECK_ID = re.compile(r"^[A-Z]{2,}(?:-[A-Z0-9]+)+-\d+$")
_H3 = re.compile(r'^<h3 id="([^"]+)">(.*)</h3>$')
_SEV_LI = re.compile(r"<li><strong>[^<]+:</strong>\s*(?:high|medium|low|info)</li>")


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


def posture_strip(stats: ReportStats, copy: dict[str, str]) -> str:
    segs: list[str] = []
    total = stats.total
    if total:
        for key in _STRIP_ORDER:
            n = stats.by_status.get(key, 0)
            if not n:
                continue
            pct = 100.0 * n / total
            label = _esc(copy.get(key, key))
            segs.append(
                f'<span class="posture-seg posture-{key}" style="width:{pct:.3f}%" '
                f'title="{label} {n}"></span>'
            )
    if not segs:
        segs.append('<span class="posture-seg posture-empty"></span>')
    label = _esc(copy.get("status", "Status"))
    return f'<div class="posture" role="img" aria-label="{label}">{"".join(segs)}</div>'


def severity_chips(stats: ReportStats, copy: dict[str, str]) -> str:
    items = "".join(
        f'<span class="chip chip-{key}">{_esc(key)} {stats.fail_by_severity.get(key, 0)}</span>'
        for key in _SEV_ORDER
    )
    title = _esc(copy.get("severity", "Severity"))
    return f'<div class="sev-chips" aria-label="{title}">{items}</div>'


def status_donut_svg(stats: ReportStats, copy: dict[str, str]) -> str:
    r, cx, cy = 36, 50, 50
    circ = 2 * math.pi * r
    total = stats.total
    track = (
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
        f'stroke="#dadce0" stroke-width="12"/>'
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
    fails = stats.by_status.get("fail", 0)
    hole = (
        f'<text x="{cx}" y="{cy - 1}" text-anchor="middle" class="donut-n" '
        f'font-size="20" font-weight="500">{fails}</text>'
        f'<text x="{cx}" y="{cy + 14}" text-anchor="middle" class="donut-l" font-size="8">'
        f'{_esc(copy.get("fail", "fail"))}</text>'
    )
    legend_items = "".join(
        f'<li><span class="swatch" style="background:{_STATUS_COLOR[key]}"></span>'
        f'{_esc(copy.get(key, key))} {stats.by_status.get(key, 0)}</li>'
        for key in _STATUS_ORDER
    )
    label = _esc(copy.get("status", "Status"))
    return (
        f'<div class="chart-body">'
        f'<svg viewBox="0 0 100 100" role="img" aria-label="{label}">'
        f"<title>{label}</title>{track}{''.join(arcs)}{hole}</svg>"
        f'<ul class="legend">{legend_items}</ul></div>'
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


def _title_from_h3(hid: str, inner: str) -> str:
    for sep in (f"{hid} — ", f"{hid} – ", f"{hid} - "):
        if inner.startswith(sep):
            return inner[len(sep):]
    return inner


def _strip_severity_item(block: str) -> str:
    out = _SEV_LI.sub("", block)
    if out == "<ul></ul>":
        return ""
    return out


def _wrap_findings(body_html: str, findings: Sequence[CheckResult]) -> str:
    sev_by_id = {item.check_id: item.severity for item in findings}
    blocks = body_html.split("\n")
    out: list[str] = []
    i = 0
    while i < len(blocks):
        match = _H3.match(blocks[i])
        if not match:
            out.append(blocks[i])
            i += 1
            continue
        hid, inner = match.group(1), match.group(2)
        sev = sev_by_id.get(hid, "info")
        if sev not in _SEV_COLOR:
            sev = "info"
        title = _title_from_h3(hid, inner)
        body_parts: list[str] = []
        i += 1
        while i < len(blocks) and not blocks[i].startswith(("<h2", "<h3")):
            stripped = _strip_severity_item(blocks[i])
            if stripped:
                body_parts.append(stripped)
            i += 1
        out.append(
            f'<article class="finding sev-{sev}" id="{_esc(hid)}">'
            f'<header class="finding-head">'
            f'<span class="finding-id">{_esc(hid)}</span>'
            f'<span class="chip chip-{sev}">{_esc(sev)}</span>'
            f"<h3>{title}</h3></header>"
        )
        out.extend(body_parts)
        out.append("</article>")
    return "\n".join(out)


_CSS = """
:root {
  --blue:#1a73e8; --ink:#202124; --muted:#5f6368; --line:#dadce0;
  --canvas:#f8f9fa; --surface:#fff;
  --pass:#1e8e3e; --fail:#d93025; --error:#e37400; --skipped:#5f6368;
  --high:#d93025; --medium:#e37400; --low:#f9ab00; --info:#1a73e8;
  --sans:"Google Sans Text","Google Sans",Roboto,"Helvetica Neue",Arial,sans-serif;
  --mono:"Roboto Mono",ui-monospace,"JetBrains Mono",Menlo,Consolas,monospace;
}
html { font: 14px/1.5 var(--sans); color: var(--ink); background: var(--canvas); }
body { margin: 0; }
.shell { max-width: 72rem; margin: 0 auto; padding: 0 1.5rem; }
.appbar { background: var(--surface); padding: 1.35rem 0 1.1rem; }
.appbar h1 { margin: 0; font-size: 1.5rem; font-weight: 400; letter-spacing: -.015em; }
.posture { display: flex; height: 3px; width: 100%; background: var(--line); }
.posture-seg { display: block; height: 100%; }
.posture-fail { background: var(--fail); }
.posture-error { background: var(--error); }
.posture-skipped { background: var(--skipped); }
.posture-pass { background: var(--pass); }
.posture-empty { flex: 1; background: var(--line); }
header .lede {
  display: flex; flex-direction: column; gap: .75rem; margin-top: 1.25rem;
}
.identity {
  background: var(--surface); border: 1px solid var(--line); border-radius: 8px;
  padding: 1rem 1.25rem;
}
.notice {
  display: flex; align-items: flex-start; gap: .65rem;
  background: #fef7e0; border: 1px solid #f9ab00; border-radius: 8px;
  padding: .85rem 1.1rem; color: #7a4f01;
}
.notice-icon { flex: none; line-height: 1.35; font-size: 1.05rem; }
.disclaimer { margin: 0; font-size: .85rem; color: inherit; }
.meta {
  list-style: none; padding: 0; margin: 0;
  display: flex; flex-direction: column; gap: .45rem;
  color: var(--ink); font-size: .9rem;
}
.meta li {
  display: grid; grid-template-columns: 7rem minmax(0, 1fr);
  column-gap: 1rem; align-items: baseline;
}
.meta-k { color: var(--muted); font-size: .8rem; }
.meta-v { overflow-wrap: anywhere; }
.kpis { display: flex; gap: .75rem; flex-wrap: wrap; }
.kpi {
  flex: 1 1 6rem; background: var(--surface); border: 1px solid var(--line);
  border-radius: 8px; padding: .85rem 1rem;
}
.kpi-label { display: block; font-size: .75rem; color: var(--muted); }
.kpi-n { font-size: 1.75rem; font-weight: 400; letter-spacing: -.02em; }
.kpi-fail .kpi-n { color: var(--fail); }
.kpi-pass .kpi-n { color: var(--pass); }
.kpi-error .kpi-n { color: var(--error); }
.kpi-total { color: var(--muted); margin: .65rem 0 .75rem; }
.sev-chips { display: flex; flex-wrap: wrap; gap: .4rem; margin: 0 0 .85rem; }
.charts {
  display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin: 0 0 1.25rem;
  align-items: start;
}
figure {
  margin: 0; background: var(--surface); border: 1px solid var(--line);
  border-radius: 8px; padding: 1rem 1.15rem 1.15rem;
}
figcaption { font-weight: 500; margin: 0 0 .75rem; font-size: .85rem; }
.chart-body { display: flex; align-items: center; gap: 1.25rem; }
.chart-status svg { width: 10.5rem; height: 10.5rem; flex: none; display: block; }
.chart-severity svg { width: 100%; max-width: 22rem; height: auto; display: block; }
.legend { list-style: none; padding: 0; margin: 0; font-size: .85rem; }
.legend li { display: flex; align-items: center; gap: .4rem; margin: .2rem 0; }
.swatch { width: .7rem; height: .7rem; border-radius: 2px; display: inline-block; flex: none; }
.bar-label, .bar-n { font-size: 10px; fill: var(--ink); }
.donut-n { fill: var(--fail); }
.donut-l { fill: var(--muted); }
.chip {
  display: inline-flex; align-items: center; border-radius: 4px;
  padding: .15rem .5rem; font-size: .7rem; font-weight: 500;
  letter-spacing: .04em; text-transform: uppercase;
}
.chip-high { background: #fce8e6; color: #c5221f; }
.chip-medium { background: #feefe3; color: #b06000; }
.chip-low { background: #fef7e0; color: #b06000; }
.chip-info { background: #e8f0fe; color: #1967d2; }
.table-wrap { overflow-x: auto; max-width: 100%; margin: 1rem 0; }
table { border-collapse: collapse; width: max-content; min-width: 100%; margin: 0; }
th, td { padding: .65rem .75rem; text-align: left; border-bottom: 1px solid var(--line); }
th {
  background: var(--canvas); font-weight: 500; white-space: nowrap; vertical-align: bottom;
  color: var(--muted); font-size: .75rem; letter-spacing: .02em;
}
td { vertical-align: top; overflow-wrap: anywhere; word-break: break-word; max-width: 20rem; }
td.sev-high, td.sev-medium, td.sev-low, td.sev-info {
  font-size: .7rem; font-weight: 500; letter-spacing: .04em; text-transform: uppercase;
}
td.sev-high { color: #c5221f; }
td.sev-medium { color: #b06000; }
td.sev-low { color: #b06000; }
td.sev-info { color: #1967d2; }
h2 { margin: 1.75rem 0 .75rem; font-size: 1.125rem; font-weight: 500; }
article.finding {
  background: var(--surface); border: 1px solid var(--line); border-radius: 8px;
  border-left-width: 4px; padding: 1.15rem 1.35rem 1.35rem; margin: 1.15rem 0;
  scroll-margin-top: 1rem;
}
article.finding.sev-high { border-left-color: var(--high); }
article.finding.sev-medium { border-left-color: var(--medium); }
article.finding.sev-low { border-left-color: var(--low); }
article.finding.sev-info { border-left-color: var(--info); }
.finding-head {
  display: flex; flex-wrap: wrap; align-items: center; gap: .4rem .75rem; margin-bottom: .85rem;
}
.finding-id { font-family: var(--mono); font-size: .8rem; color: var(--muted); }
.finding-head h3 {
  flex: 1 1 100%; margin: 0; padding: 0; border: 0; font-size: 1.125rem; font-weight: 500;
}
article.finding ul { list-style: none; padding: 0; margin: 0 0 .5rem; }
article.finding li { margin: .4rem 0; }
article.finding li strong {
  display: block; color: var(--muted); font-size: .75rem; font-weight: 500;
  letter-spacing: .02em; margin-bottom: .2rem;
}
a.jump { color: var(--blue); text-decoration: none; margin-left: .15rem; }
a.jump:hover { text-decoration: underline; }
a.jump:focus-visible { outline: 2px solid var(--blue); outline-offset: 2px; }
code, pre { font-family: var(--mono); }
p code, li code, td code {
  background: var(--canvas); padding: .1em .35em; border-radius: 4px; font-size: .9em;
}
pre {
  background: var(--canvas); border: 1px solid var(--line); border-radius: 8px;
  padding: .75rem 1rem; overflow-x: auto; font-size: .85rem; line-height: 1.4;
  white-space: pre;
}
pre code { background: none; padding: 0; font-size: inherit; }
@media print {
  html, body { background: #fff; }
  article.finding { break-inside: avoid; }
  .charts { grid-template-columns: 1fr; break-inside: avoid; }
  .table-wrap { overflow: visible; }
  th { white-space: normal; }
}
@media (max-width: 40rem) {
  .kpis { flex-direction: column; }
  .charts { grid-template-columns: 1fr; }
  .chart-body { flex-direction: column; align-items: flex-start; }
}
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
    total = f'<p class="kpi-total">{stats.total} {_esc(copy["checks"])}</p>'
    return (
        f'<section class="dashboard">'
        f'<div class="kpis">{cards}</div>{total}'
        f"{severity_chips(stats, copy)}"
        f'<div class="charts">'
        f'<figure class="chart-status"><figcaption>{_esc(copy["status"])}</figcaption>'
        f"{status_donut_svg(stats, copy)}</figure>"
        f'<figure class="chart-severity"><figcaption>{_esc(copy["severity"])}</figcaption>'
        f"{severity_bars_svg(stats, copy)}</figure>"
        f"</div></section>"
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
    body_html = _wrap_findings(body_html, findings)
    title = copy["title"]
    disclaimer = (
        f'<p class="disclaimer">{_esc(DISCLAIMER)}</p>'
    )
    meta = (
        '<ul class="meta">'
        f'<li><span class="meta-k">{_esc(copy["author"])}</span>'
        f'<span class="meta-v">{_esc(operator_username())}</span></li>'
        f'<li><span class="meta-k">{_esc(copy["date"])}</span>'
        f'<span class="meta-v">{_esc(started_at.date().isoformat())}</span></li>'
        f'<li><span class="meta-k">{_esc(copy["target"])}</span>'
        f'<span class="meta-v">{_esc(vendor)} · {_esc(url)}</span></li>'
        f'<li><span class="meta-k">{_esc(copy["tool"])}</span>'
        f'<span class="meta-v">OMF {_esc(version)}</span></li>'
        "</ul>"
    )
    appbar = (
        f'<div class="appbar"><div class="shell"><h1>{_esc(title)}</h1></div></div>'
    )
    return (
        "<!DOCTYPE html>\n"
        f'<html lang="{_esc(language)}">\n'
        "<head><meta charset=\"utf-8\">"
        f"<title>{_esc(title)}</title>"
        f"<style>{_CSS}</style></head>\n"
        f"<body><header>{appbar}{posture_strip(stats, copy)}"
        f'<div class="lede shell">'
        f'<div class="identity">{meta}</div>'
        f'<div class="notice" role="note">'
        f'<span class="notice-icon" aria-hidden="true">⚠</span>'
        f"{disclaimer}</div>"
        f"</div></header>\n"
        f'<main class="shell">{body_html}</main></body></html>\n'
    )
