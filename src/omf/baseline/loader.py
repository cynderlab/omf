from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from omf.schema import Severity

_BASE = Path(__file__).parent
_PROFILE_KEYS = (
    "forbidden_services",
    "mgmt_services",
    "default_hostnames",
    "wan_mgmt",
    "isdb_inbound",
    "isdb_outbound",
)


@dataclass(frozen=True)
class CheckDef:
    id: str
    title: str
    severity: Severity
    applies_to: tuple[str, ...]
    needs: tuple[str, ...]
    evaluator: str
    params: dict
    mitigation: dict[str, str]


def _load_yaml(path: Path) -> Any:
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


@lru_cache(maxsize=1)
def load_catalog() -> tuple[CheckDef, ...]:
    raw = _load_yaml(_BASE / "catalog.yaml")
    checks: list[CheckDef] = []
    for entry in raw["checks"]:
        checks.append(
            CheckDef(
                id=entry["id"],
                title=entry["title"],
                severity=entry["severity"],
                applies_to=tuple(entry["applies_to"]),
                needs=tuple(entry["needs"]),
                evaluator=entry["evaluator"],
                params=dict(entry.get("params") or {}),
                mitigation=dict(entry.get("mitigation") or {}),
            )
        )
    return tuple(checks)


@lru_cache(maxsize=8)
def load_profile(vendor: str) -> dict:
    path = _BASE / "profiles" / f"{vendor}.yaml"
    data = _load_yaml(path)
    return dict(data or {})


def resolve_params(check: CheckDef, vendor: str) -> dict:
    """Shallow-merge params.default, params[vendor], then profile keys if unset."""
    merged: dict[str, Any] = {}
    default = check.params.get("default") or {}
    vendor_params = check.params.get(vendor) or {}
    merged.update(default)
    merged.update(vendor_params)

    profile = load_profile(vendor)
    for key in _PROFILE_KEYS:
        if key not in merged and key in profile:
            merged[key] = profile[key]
    return merged


def checks_for(vendor: str) -> tuple[CheckDef, ...]:
    return tuple(c for c in load_catalog() if vendor in c.applies_to)


def mitigation_for(check: CheckDef, vendor: str) -> str:
    return check.mitigation.get(vendor) or check.mitigation.get("generic") or ""
