import pytest
from omf.wizard import parse_vendor, parse_url, parse_language, parse_yes_no, ValidationError


def test_vendor():
    assert parse_vendor("MikroTik") == "mikrotik"
    assert parse_vendor("FORTINET") == "fortinet"
    with pytest.raises(ValidationError):
        parse_vendor("palo")


def test_url_https_ok():
    assert parse_url("https://192.0.2.1") == "https://192.0.2.1"
    assert parse_url("https://fw.example:8443/") == "https://fw.example:8443"


def test_url_rejects_embedded_userinfo():
    with pytest.raises(ValidationError):
        parse_url("https://admin:secret@192.0.2.1")


def test_url_rejects_non_http():
    with pytest.raises(ValidationError):
        parse_url("ftp://192.0.2.1")


def test_language():
    assert parse_language("CA") == "ca"
    with pytest.raises(ValidationError):
        parse_language("fr")


def test_yes_no_default():
    assert parse_yes_no("", default=True) is True
    assert parse_yes_no("n", default=True) is False
    assert parse_yes_no("yes", default=False) is True
