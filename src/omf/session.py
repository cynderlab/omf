from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass
class Session:
    vendor: Literal["mikrotik", "fortinet"]
    url: str
    username: str
    password: str
    token: str
    verify_tls: bool
    report_language: Literal["ca", "es", "en"]

    def clear_secrets(self) -> None:
        self.username = ""
        self.password = ""
        self.token = ""
