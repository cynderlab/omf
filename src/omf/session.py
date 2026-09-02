"""In-memory audit session. Password and token never leave this object."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass
class Session:
    vendor: str
    url: str
    username: str
    password: str
    token: str
    verify_tls: bool
    report_language: Literal["ca", "es", "en"]
    report_mode: Literal["eval", "llm"] = "llm"

    def clear_secrets(self) -> None:
        self.username = ""
        self.password = ""
        self.token = ""
