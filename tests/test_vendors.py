import pytest

from omf.vendors import get, ids, menu_options


def test_registered_ids_are_the_current_vendors():
    assert ids() == frozenset({"mikrotik", "fortinet"})


def test_unknown_vendor_raises():
    with pytest.raises(ValueError, match="unknown vendor"):
        get("paloalto")


def test_mikrotik_spec_owns_connection_not_the_kernel():
    spec = get("mikrotik")
    assert spec.id == "mikrotik"
    assert spec.group == "firewall"
    assert spec.target_kind == "url"
    assert spec.target_label == "Device URL"
    assert spec.tls_verify is False
    assert spec.tls_notice
    assert spec.target_noun == "firewall"


def test_fortinet_spec_is_a_firewall_url_target():
    spec = get("fortinet")
    assert spec.group == "firewall"
    assert spec.target_kind == "url"
    assert spec.tls_verify is False
    assert spec.target_noun == "firewall"


def test_menu_options_come_from_the_registry():
    options = menu_options()
    assert options[0][1] == "mikrotik"
    assert options[1][1] == "fortinet"
    assert {value for _, value in options} == ids()
