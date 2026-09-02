"""Questionary select/confirm helpers for the English TUI."""

from __future__ import annotations

from typing import TypeVar

import questionary
from questionary import Choice, Style

from omf.vendors import menu_options

T = TypeVar("T")

VENDOR_OPTIONS: tuple[tuple[str, str], ...] = menu_options()

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
) -> T:
    choices = [Choice(title=label, value=value) for label, value in options]
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
