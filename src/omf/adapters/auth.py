"""Vendor authentication schemes. The TUI prompts only the listed fields."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

AuthField = Literal["username", "password", "token"]


@dataclass(frozen=True)
class AuthScheme:
    """How a vendor adapter authenticates. The TUI only prompts these fields."""

    id: str
    label: str
    fields: tuple[AuthField, ...]


# Single source of truth for wizard + adapters.
VENDOR_AUTH_SCHEMES: dict[str, tuple[AuthScheme, ...]] = {
    "mikrotik": (
        AuthScheme(
            id="basic",
            label="REST HTTP Basic (username + password)",
            fields=("username", "password"),
        ),
    ),
    "fortinet": (
        AuthScheme(
            id="token",
            label="API token (Bearer)",
            fields=("token",),
        ),
        AuthScheme(
            id="session",
            label="Username and password",
            fields=("username", "password"),
        ),
    ),
}


def auth_schemes(vendor: str) -> tuple[AuthScheme, ...]:
    try:
        return VENDOR_AUTH_SCHEMES[vendor]
    except KeyError as exc:
        raise ValueError(f"unknown vendor: {vendor}") from exc


def scheme_by_id(vendor: str, scheme_id: str) -> AuthScheme:
    for scheme in auth_schemes(vendor):
        if scheme.id == scheme_id:
            return scheme
    raise ValueError(f"unknown auth scheme {scheme_id!r} for {vendor}")
