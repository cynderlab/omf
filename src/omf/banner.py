"""Colored ASCII banner shown before the audit wizard."""

from __future__ import annotations

from rich.align import Align
from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.text import Text

from omf import __version__

_ART = (
    r"  ██████╗ ███╗   ███╗███████╗",
    r" ██╔═══██╗████╗ ████║██╔════╝",
    r" ██║   ██║██╔████╔██║█████╗  ",
    r" ██║   ██║██║╚██╔╝██║██╔══╝  ",
    r" ╚██████╔╝██║ ╚═╝ ██║██║     ",
    r"  ╚═════╝ ╚═╝     ╚═╝╚═╝     ",
)

_GRADIENT = (
    "bright_cyan",
    "cyan",
    "deep_sky_blue1",
    "medium_purple",
    "magenta",
    "bright_magenta",
)


def build_banner() -> RenderableType:
    art = Text()
    for index, line in enumerate(_ART):
        art.append(line + "\n", style=f"bold {_GRADIENT[index]}")
    title = Text("OH MY FORTRESS", style="bold white")
    subtitle = Text(
        f"v{__version__}  ·  read-only multi-vendor audit",
        style="dim",
    )
    author = Text("by Pere Casas  ·  pcasas@cynderlab.com", style="italic cyan")
    body = Group(
        Align.center(art),
        Align.center(title),
        Align.center(subtitle),
        Align.center(author),
    )
    return Panel(
        body,
        border_style="bright_cyan",
        padding=(1, 2),
    )


def print_banner(console: Console) -> None:
    console.print()
    console.print(build_banner())
    console.print()
