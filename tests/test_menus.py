import pytest

from omf.menus import (
    LANGUAGE_OPTIONS,
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


def test_select_value_none_is_cancel():
    with pytest.raises(MenuCancelled):
        select_value("Vendor", VENDOR_OPTIONS, ask=lambda: None)


def test_language_options_cover_catalog_codes():
    assert {code for _, code in LANGUAGE_OPTIONS} == {"ca", "es", "en"}


def test_confirm_cancel():
    with pytest.raises(MenuCancelled):
        confirm("Proceed?", ask=lambda: None)


def test_confirm_yes():
    assert confirm("Proceed?", ask=lambda: True) is True
