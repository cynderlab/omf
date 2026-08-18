import logging

from omf.log import configure, get_logger, http_target


def test_default_is_warning():
    configure()
    assert get_logger().level == logging.WARNING


def test_debug_is_debug():
    configure(debug=True)
    assert get_logger().level == logging.DEBUG


def test_http_target_joins_base_and_path():
    assert http_target("http://192.168.1.1", "/rest/system/identity") == (
        "http://192.168.1.1/rest/system/identity"
    )


def test_http_target_strips_userinfo():
    assert http_target("https://admin:secret@fw.example", "/rest/user") == (
        "https://fw.example/rest/user"
    )


def test_debug_http_logger_does_not_include_password(capsys):
    configure(debug=True)
    get_logger("omf.http").debug("%s %s -> %s", "GET", "/rest/user", 401)
    err = capsys.readouterr().err
    assert "/rest/user" in err
    assert "password" not in err.lower()
    assert "authorization" not in err.lower()
