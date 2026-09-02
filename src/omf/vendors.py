"""Vendor registry. Kernel looks up a spec; it does not know the technology."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import httpx

from omf.adapters.base import VendorAdapter
from omf.adapters.fortinet import FortinetAdapter
from omf.adapters.mikrotik import MikrotikAdapter
from omf.session import Session

TargetKind = Literal["url"]


@dataclass(frozen=True)
class VendorSpec:
    id: str
    label: str
    group: str
    target_kind: TargetKind
    target_label: str
    tls_verify: bool
    tls_notice: str | None
    target_noun: str
    hint: str | None = None


_SPECS: tuple[VendorSpec, ...] = (
    VendorSpec(
        id="mikrotik",
        label="MikroTik REST API (/rest, www-ssl)",
        group="firewall",
        target_kind="url",
        target_label="Device URL",
        tls_verify=False,
        tls_notice=(
            "TLS certificate verification is off "
            "(self-signed management certs are accepted)."
        ),
        target_noun="firewall",
        hint=(
            "MikroTik uses RouterOS REST "
            "(GET https://IP/rest/..., HTTP Basic on www-ssl). "
            "The binary API on tcp/8728 is not used."
        ),
    ),
    VendorSpec(
        id="fortinet",
        label="Fortinet (FortiOS REST)",
        group="firewall",
        target_kind="url",
        target_label="Device URL",
        tls_verify=False,
        tls_notice=(
            "TLS certificate verification is off "
            "(self-signed management certs are accepted)."
        ),
        target_noun="firewall",
        hint=None,
    ),
)

_BY_ID: dict[str, VendorSpec] = {spec.id: spec for spec in _SPECS}

_ADAPTERS = {
    "mikrotik": MikrotikAdapter,
    "fortinet": FortinetAdapter,
}


def ids() -> frozenset[str]:
    return frozenset(_BY_ID)


def get(vendor_id: str) -> VendorSpec:
    try:
        return _BY_ID[vendor_id]
    except KeyError as exc:
        raise ValueError(f"unknown vendor: {vendor_id}") from exc


def menu_options() -> tuple[tuple[str, str], ...]:
    return tuple((spec.label, spec.id) for spec in _SPECS)


def build_adapter(session: Session, client: httpx.Client | None = None) -> VendorAdapter:
    spec = get(session.vendor)
    adapter_cls = _ADAPTERS[spec.id]
    if client is None:
        if spec.target_kind != "url":
            raise ValueError(f"{spec.id} does not use an HTTP URL target")
        client = httpx.Client(
            base_url=session.url,
            timeout=httpx.Timeout(30.0, connect=15.0),
            verify=session.verify_tls,
            trust_env=False,
        )
    return adapter_cls(session, client)


__all__ = [
    "VendorSpec",
    "build_adapter",
    "get",
    "ids",
    "menu_options",
]
