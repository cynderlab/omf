from rich.console import Console

from omf.banner import build_banner, print_banner


def test_banner_contains_app_name():
    console = Console(record=True, width=80, color_system="truecolor", force_terminal=True)
    print_banner(console)
    text = console.export_text()
    assert "OH MY FORTRESS" in text
    assert "██████" in text
    assert "read-only" in text
    assert "Pere Casas" in text
    assert "pcasas@cynderlab.com" in text


def test_banner_is_a_panel():
    from rich.panel import Panel

    assert isinstance(build_banner(), Panel)
