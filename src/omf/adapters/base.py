"""Adapter protocol and collect/probe errors."""

from __future__ import annotations

from typing import Protocol

from omf.schema.evidence import Evidence


class CollectError(Exception):
    def __init__(self, capability: str, path: str, status: int | None, message: str) -> None:
        super().__init__(message)
        self.capability = capability
        self.path = path
        self.status = status
        self.message = message


class ProbeError(Exception):
    def __init__(self, path: str, status: int | None, message: str) -> None:
        super().__init__(message)
        self.path = path
        self.status = status
        self.message = message


class VendorAdapter(Protocol):
    vendor: str

    def probe(self) -> None: ...

    def collect(self, capability: str) -> tuple[Evidence, object]: ...

    def implemented(self) -> frozenset[str]: ...

    def close(self) -> None: ...


__all__ = [
    "CollectError",
    "ProbeError",
    "VendorAdapter",
]
