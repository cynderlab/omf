"""Vendor HTTP adapters. Normalize to frozen capability models. Read-only."""

from omf.adapters.base import CollectError, ProbeError, VendorAdapter

__all__ = [
    "CollectError",
    "ProbeError",
    "VendorAdapter",
]
