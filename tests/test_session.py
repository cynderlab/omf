from omf.session import Session


def test_clear_secrets_wipes_creds_keeps_url():
    s = Session(
        vendor="mikrotik",
        url="https://192.0.2.1",
        username="admin",
        password="p@ss",
        token="tok",
        verify_tls=True,
        report_language="ca",
    )
    s.clear_secrets()
    assert s.password == ""
    assert s.token == ""
    assert s.username == ""
    assert s.url == "https://192.0.2.1"
    assert s.vendor == "mikrotik"


def test_default_report_mode_is_llm():
    s = Session("mikrotik", "https://x", "", "", "", True, "en")
    assert s.report_mode == "llm"
