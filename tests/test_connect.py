from omf.adapters.base import ProbeError
from omf.connect import check_host_reachable, explain_probe_error


def test_explain_auth_failure():
    text = explain_probe_error(ProbeError("/rest/system/identity", 401, "GET returned 401"))
    assert "Authentication failed" in text
    assert "401" in text


def test_explain_forbidden():
    text = explain_probe_error(ProbeError("/rest/system/identity", 403, "forbidden"))
    assert "Authentication failed" in text


def test_explain_not_found():
    text = explain_probe_error(ProbeError("/rest/system/identity", 404, "missing"))
    assert "not found" in text.lower()


def test_explain_connection_refused():
    text = explain_probe_error(
        ProbeError("/rest/system/identity", None, "All connection attempts failed: Connection refused")
    )
    assert "Could not reach the device" in text
    assert "http/https" in text


def test_explain_timeout():
    text = explain_probe_error(ProbeError("/rest/system/identity", None, "Connect timeout"))
    assert "Could not reach the device" in text


def test_explain_other_http():
    text = explain_probe_error(ProbeError("/rest/system/identity", 500, "boom"))
    assert "500" in text


class _FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class _FakeClient:
    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def head(self, url):
        return _FakeResponse(200)

    def get(self, url):
        return _FakeResponse(200)


class _FailingClient(_FakeClient):
    def head(self, url):
        raise __import__("httpx").ConnectError("[Errno 65] No route to host")


def test_reachable_ok(monkeypatch):
    monkeypatch.setattr("omf.connect.httpx.Client", _FakeClient)
    assert check_host_reachable("http://192.168.1.1") is None


def test_reachable_uses_no_env_proxy(monkeypatch):
    seen = {}

    def fake_client(**kwargs):
        seen.update(kwargs)
        return _FakeClient(**kwargs)

    monkeypatch.setattr("omf.connect.httpx.Client", fake_client)
    assert check_host_reachable("http://192.168.1.1") is None
    assert seen.get("trust_env") is False


def test_reachable_no_route(monkeypatch):
    monkeypatch.setattr("omf.connect.httpx.Client", _FailingClient)
    message = check_host_reachable("http://192.168.1.1")
    assert message is not None
    assert "No route" in message
    assert "192.168.1.1:80" in message
