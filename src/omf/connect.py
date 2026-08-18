"""Host reachability check and human-readable probe error text."""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from omf.adapters.base import ProbeError
from omf.log import get_logger, http_target

_log = get_logger("omf.connect")

CONNECT_ACTIONS: tuple[tuple[str, str], ...] = (
    ("Retry connection", "retry"),
    ("Change credentials", "creds"),
    ("Change device URL", "url"),
    ("Abort", "abort"),
)

URL_REACH_ACTIONS: tuple[tuple[str, str], ...] = (
    ("Retry", "retry"),
    ("Change device URL", "url"),
    ("Abort", "abort"),
)


def check_host_reachable(url: str, timeout: float = 5.0) -> str | None:
    """HTTP HEAD/GET like curl -I. Any HTTP response means reachable. None = ok."""
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return "URL has no host"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    target = http_target(url, "/")
    try:
        with httpx.Client(
            timeout=timeout,
            verify=False,
            trust_env=False,
            follow_redirects=False,
        ) as client:
            response = client.head(url)
            if response.status_code == 405:
                response = client.get(url)
        _log.debug("reachability %s -> %s", target, response.status_code)
        return None
    except httpx.RequestError as exc:
        _log.debug("reachability %s failed: %s", target, exc)
        text = str(exc)
        if "65" in text or "no route" in text.lower():
            return (
                f"No route to {host}:{port} ({exc}). "
                "curl works from this Mac? Then Python may be blocked "
                "(System Settings → Privacy → Local Network) or a proxy is interfering."
            )
        return f"Cannot reach {host}:{port} ({exc})."


def explain_probe_error(exc: ProbeError) -> str:
    status = exc.status
    message = (exc.message or str(exc)).strip()
    lowered = message.lower()
    path = exc.path or ""

    if status in {401, 403}:
        return (
            "Authentication failed "
            f"(HTTP {status} on {path or 'probe'}). "
            "Check username and password."
        )
    if status == 404:
        return (
            f"API path not found (HTTP 404 on {path or 'probe'}). "
            "Is this RouterOS 7+ REST / FortiOS REST at this URL?"
        )
    if status is not None:
        return f"Device rejected the probe (HTTP {status} on {path or 'probe'})."

    if "certificate" in lowered or "ssl" in lowered or "tls" in lowered:
        return f"TLS error while reaching the device: {message}"
    return (
        "Could not reach the device"
        f"{f' ({message})' if message else ''}. "
        "Check the URL, scheme (http/https), port, and that the API is enabled."
    )
