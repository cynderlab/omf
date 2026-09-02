import pytest

from questionary import Choice

from omf.menus import (
    COMING_SOON_VENDORS,
    LANGUAGE_OPTIONS,
    REPORT_MODE_OPTIONS,
    VENDOR_OPTIONS,
    MenuCancelled,
    confirm,
    select_value,
)


def test_select_value_returns_mapped_choice():
    assert (
        select_value("Vendor", VENDOR_OPTIONS, "fortinet", ask=lambda: "mikrotik")
        == "mikrotik"
    )


def test_coming_soon_vendors_are_labeled_read_only():
    assert COMING_SOON_VENDORS == (
        "SonicWall (coming soon)",
        "pfSense (coming soon)",
    )
    assert VENDOR_OPTIONS[0][1] == "fortinet"
    assert {value for _, value in VENDOR_OPTIONS} == {"fortinet", "mikrotik"}


def test_select_value_marks_coming_soon_choices_disabled(monkeypatch):
    captured: dict[str, list[Choice]] = {}

    def fake_select(message, choices=None, **kwargs):
        captured["choices"] = list(choices)
        class Picker:
            def ask(self):
                return "fortinet"

        return Picker()

    monkeypatch.setattr("omf.menus.questionary.select", fake_select)
    assert (
        select_value(
            "Vendor",
            VENDOR_OPTIONS,
            "fortinet",
            disabled_labels=COMING_SOON_VENDORS,
        )
        == "fortinet"
    )
    titles = [choice.title for choice in captured["choices"]]
    assert titles[:2] == [VENDOR_OPTIONS[0][0], VENDOR_OPTIONS[1][0]]
    assert titles[-2:] == list(COMING_SOON_VENDORS)
    selectable = {choice.value for choice in captured["choices"] if not choice.disabled}
    assert selectable == {value for _, value in VENDOR_OPTIONS}
    for choice in captured["choices"][-2:]:
        assert choice.disabled
        assert choice.value not in selectable


def test_select_value_none_is_cancel():
    with pytest.raises(MenuCancelled):
        select_value("Vendor", VENDOR_OPTIONS, ask=lambda: None)


def test_language_options_cover_catalog_codes():
    assert {code for _, code in LANGUAGE_OPTIONS} == {"ca", "es", "en"}


def test_report_mode_options():
    assert REPORT_MODE_OPTIONS == (
        ("Evaluation only (no LLM)", "eval"),
        ("LLM narrative", "llm"),
    )


def test_confirm_cancel():
    with pytest.raises(MenuCancelled):
        confirm("Proceed?", ask=lambda: None)


def test_confirm_yes():
    assert confirm("Proceed?", ask=lambda: True) is True
