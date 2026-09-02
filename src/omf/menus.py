"""Questionary select/confirm helpers for the English TUI."""

from __future__ import annotations

from typing import TypeVar

import questionary
from questionary import Choice, Style

from omf.vendors import menu_options

T = TypeVar("T")

# TUI order only. Catalog merge still follows vendors.menu_options() / _SPECS.
_TUI_VENDOR_ORDER = ("fortinet", "mikrotik")


def _vendor_options() -> tuple[tuple[str, str], ...]:
    by_id = {vendor_id: label for label, vendor_id in menu_options()}
    ordered: list[tuple[str, str]] = []
    for vendor_id in _TUI_VENDOR_ORDER:
        label = by_id.pop(vendor_id, None)
        if label is not None:
            ordered.append((label, vendor_id))
    ordered.extend((label, vendor_id) for vendor_id, label in by_id.items())
    return tuple(ordered)


VENDOR_OPTIONS: tuple[tuple[str, str], ...] = _vendor_options()

COMING_SOON_VENDORS: tuple[str, ...] = (
    "SonicWall (coming soon)",
    "pfSense (coming soon)",
)

LANGUAGE_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Catalan", "ca"),
    ("Spanish", "es"),
    ("English", "en"),
)

REPORT_MODE_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Evaluation only (no LLM)", "eval"),
    ("LLM narrative", "llm"),
)

_STYLE = Style(
    [
        ("qmark", "fg:cyan bold"),
        ("question", "bold"),
        ("answer", "fg:cyan bold"),
        ("pointer", "fg:cyan bold"),
        ("highlighted", "fg:cyan bold"),
        ("selected", "fg:cyan"),
        ("disabled", "fg:ansibrightblack italic"),
        ("instruction", "fg:ansibrightblack"),
    ]
)


class MenuCancelled(Exception):
    """User aborted a select/confirm prompt (Esc / Ctrl+C)."""


def select_value(
    message: str,
    options: tuple[tuple[str, T], ...],
    default: T | None = None,
    *,
    ask=None,
    disabled_labels: tuple[str, ...] = (),
) -> T:
    choices = [Choice(title=label, value=value) for label, value in options]
    choices.extend(Choice(title=label, disabled=True) for label in disabled_labels)
    picker = questionary.select(
        message,
        choices=choices,
        default=default,
        instruction="(↑/↓ and enter)",
        use_shortcuts=True,
        use_indicator=True,
        style=_STYLE,
    )
    result = (ask or picker.ask)()
    if result is None:
        raise MenuCancelled
    return result


def confirm(message: str, default: bool = False, *, ask=None) -> bool:
    picker = questionary.confirm(
        message,
        default=default,
        instruction="(↑/↓ or y/n)",
        style=_STYLE,
    )
    result = (ask or picker.ask)()
    if result is None:
        raise MenuCancelled
    return bool(result)
