from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict

Vendor = Literal["mikrotik", "fortinet"]
Status = Literal["pass", "fail", "error", "skipped"]
Severity = Literal["info", "low", "medium", "high"]

T = TypeVar("T")


class Evidence(BaseModel, Generic[T]):
    model_config = ConfigDict(frozen=True, extra="forbid")

    capability: str
    vendor: Vendor
    schema_version: int = 1
    collected_at: datetime
    payload: T


class CheckResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    check_id: str
    status: Status
    severity: Severity
    diagnostic: str
    capability_refs: tuple[str, ...]
    observed: dict[str, Any]
