"""Load per-vendor catalogs and profiles. Kernel does not own a global CORE catalog."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from omf.schema import Severity
from omf.vendors import menu_options

_BASE = Path(__file__).parent


def _catalog_text(value: object, vendor: str) -> str:
    if isinstance(value, dict):
        raw = value.get(vendor) or value.get("generic") or ""
    else:
        raw = value or ""
    return " ".join(str(raw).split())


@dataclass(frozen=True)
class CheckDef:
    id: str
    title: str
    severity: Severity
    needs: tuple[str, ...]
    evaluator: str
    params: dict
    mitigation: str
    description: str = ""


def _load_yaml(path: Path) -> Any:
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def _vendor_dir(vendor: str) -> Path:
    path = _BASE / "vendors" / vendor
    if not path.is_dir():
        raise ValueError(f"unknown vendor: {vendor}")
    return path


@lru_cache(maxsize=8)
def load_catalog(vendor: str | None = None) -> tuple[CheckDef, ...]:
    if vendor is None:
        seen: dict[str, CheckDef] = {}
        for _, vendor_id in menu_options():
            for check in load_catalog(vendor_id):
                seen.setdefault(check.id, check)
        return tuple(seen.values())
    raw = _load_yaml(_vendor_dir(vendor) / "catalog.yaml")
    checks: list[CheckDef] = []
    for entry in raw["checks"]:
        mitigation = entry.get("mitigation") or ""
        if isinstance(mitigation, dict):
            mitigation = mitigation.get(vendor) or mitigation.get("generic") or ""
        checks.append(
            CheckDef(
                id=entry["id"],
                title=entry["title"],
                severity=entry["severity"],
                needs=tuple(entry["needs"]),
                evaluator=entry["evaluator"],
                params=dict(entry.get("params") or {}),
                mitigation=str(mitigation),
                description=_catalog_text(entry.get("description"), vendor),
            )
        )
    return tuple(checks)


@lru_cache(maxsize=8)
def load_profile(vendor: str) -> dict:
    path = _vendor_dir(vendor) / "profile.yaml"
    data = _load_yaml(path)
    return dict(data or {})


def resolve_params(check: CheckDef, vendor: str) -> dict:
    """Check params first, then vendor profile keys if unset."""
    merged: dict[str, Any] = dict(check.params)
    for key, value in load_profile(vendor).items():
        if key not in merged:
            merged[key] = value
    return merged


def checks_for(vendor: str) -> tuple[CheckDef, ...]:
    return load_catalog(vendor)


def mitigation_for(check: CheckDef, vendor: str) -> str:
    return check.mitigation


__all__ = [
    "CheckDef",
    "checks_for",
    "load_catalog",
    "load_profile",
    "mitigation_for",
    "resolve_params",
]
