"""Build a vendor adapter. The HTTP client is created here from the session."""

from __future__ import annotations

import httpx

from omf.adapters.base import VendorAdapter
from omf.adapters.fortinet import FortinetAdapter
from omf.adapters.mikrotik import MikrotikAdapter
from omf.session import Session


def build_adapter(session: Session, client: httpx.Client | None = None) -> VendorAdapter:
    if session.vendor == "mikrotik":
        adapter_cls: type[VendorAdapter] = MikrotikAdapter
    elif session.vendor == "fortinet":
        adapter_cls = FortinetAdapter
    else:
        raise ValueError(f"unknown vendor: {session.vendor}")
    if client is None:
        client = httpx.Client(
            base_url=session.url,
            timeout=httpx.Timeout(30.0, connect=15.0),
            verify=session.verify_tls,
            trust_env=False,
        )
    return adapter_cls(session, client)


__all__ = ["build_adapter"]
