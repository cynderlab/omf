from __future__ import annotations

import re
from typing import Any

ALLOWLIST = frozenset({
    "admin", "administrator", "root", "guest", "public", "private",
    "accept", "deny", "drop", "any", "mikrotik", "fortinet",
})
STRIP_KEYS = frozenset({
    "password", "passwd", "passphrase", "secret", "psk", "private_key", "api_key",
})

_USER_KEYS = frozenset({"name", "username"})
_SERIAL_KEYS = frozenset({"serial", "serial_number"})
_COMMUNITY_PARENTS = frozenset({"communities", "community"})

_H = r"[0-9A-Fa-f]{1,4}"
_V4 = (
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
)

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_IPV4_RE = re.compile(rf"\b{_V4}\b")
# IPv4-tail forms first so ::ffff:10.0.0.1 is not split into prefix + dotted quad.
_IPV6_RE = re.compile(
    rf"(?<![0-9A-Fa-f:])(?:"
    rf"(?:{_H}:){{6}}{_V4}"
    rf"|::(?:{_H}:){{5}}{_V4}"
    rf"|(?:{_H})?::(?:{_H}:){{0,4}}{_V4}"
    rf"|(?:{_H}:){_H}?::(?:{_H}:){{0,3}}{_V4}"
    rf"|(?:{_H}:){{2}}{_H}?::(?:{_H}:){{0,2}}{_V4}"
    rf"|(?:{_H}:){{3}}{_H}?::(?:{_H}:){{0,1}}{_V4}"
    rf"|(?:{_H}:){{4}}{_H}?::{_V4}"
    rf"|(?:{_H}:){{7}}{_H}"
    rf"|(?:{_H}:){{1,7}}:"
    rf"|:(?::{_H}){{1,7}}"
    rf"|(?:{_H}:){{1,6}}:{_H}"
    rf"|(?:{_H}:){{1,5}}(?::{_H}){{1,2}}"
    rf"|(?:{_H}:){{1,4}}(?::{_H}){{1,3}}"
    rf"|(?:{_H}:){{1,3}}(?::{_H}){{1,4}}"
    rf"|(?:{_H}:){{1,2}}(?::{_H}){{1,5}}"
    rf"|{_H}:(?::{_H}){{1,6}}"
    rf")(?![0-9A-Fa-f:])"
)
_HOSTNAME_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,}\b"
)
_SERIAL_RE = re.compile(r"^[A-Z0-9]{8,}$")
_TOKEN_RE = re.compile(r"\[[A-Z]+_\d+\]")


class Redactor:
    def __init__(self) -> None:
        # Same original value → same token (kind only picks the prefix on first sight).
        self._forward: dict[str, str] = {}
        self._reverse: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    def redact_text(self, text: str) -> str:
        # URLs before hostnames so the host inside a URL is not double-tokenized.
        text = _URL_RE.sub(lambda m: self._tokenize("URL", m.group(0)), text)
        text = _IPV6_RE.sub(lambda m: self._tokenize("IP", m.group(0)), text)
        text = _IPV4_RE.sub(lambda m: self._tokenize("IP", m.group(0)), text)
        text = _HOSTNAME_RE.sub(lambda m: self._hostname_sub(m.group(0)), text)
        return text

    def redact_obj(self, obj: Any, *, _parent_key: str | None = None) -> Any:
        if hasattr(obj, "model_dump") and callable(obj.model_dump):
            obj = obj.model_dump(mode="json")

        if isinstance(obj, dict):
            out: dict[Any, Any] = {}
            for key, value in obj.items():
                key_l = key.lower() if isinstance(key, str) else None
                if key_l is not None and key_l in STRIP_KEYS:
                    out[key] = "[STRIPPED]"
                elif key_l is not None and key_l in _SERIAL_KEYS and isinstance(value, str):
                    out[key] = self._redact_serial(value)
                elif key_l is not None and key_l in _USER_KEYS and isinstance(value, str):
                    out[key] = self._redact_name(value, parent_key=_parent_key)
                else:
                    out[key] = self.redact_obj(value, _parent_key=key_l)
            return out

        if isinstance(obj, list):
            return [self.redact_obj(item, _parent_key=_parent_key) for item in obj]

        if isinstance(obj, tuple):
            return tuple(self.redact_obj(item, _parent_key=_parent_key) for item in obj)

        if isinstance(obj, str):
            return self.redact_text(obj)

        return obj

    def destokenize(self, text: str) -> str:
        def repl(match: re.Match[str]) -> str:
            token = match.group(0)
            return self._reverse.get(token, token)

        return _TOKEN_RE.sub(repl, text)

    def token_map(self) -> dict[str, str]:
        return dict(self._reverse)

    def _tokenize(self, kind: str, original: str) -> str:
        existing = self._forward.get(original)
        if existing is not None:
            return existing
        n = self._counters.get(kind, 0) + 1
        self._counters[kind] = n
        token = f"[{kind}_{n}]"
        self._forward[original] = token
        self._reverse[token] = original
        return token

    def _is_allowlisted(self, value: str) -> bool:
        return value.lower() in ALLOWLIST

    def _hostname_sub(self, host: str) -> str:
        if self._is_allowlisted(host):
            return host
        return self._tokenize("HOST", host)

    def _redact_name(self, value: str, *, parent_key: str | None) -> str:
        if self._is_allowlisted(value):
            return value
        kind = "SECRET" if parent_key in _COMMUNITY_PARENTS else "USER"
        return self._tokenize(kind, value)

    def _redact_serial(self, value: str) -> str:
        if self._is_allowlisted(value):
            return value
        if _SERIAL_RE.fullmatch(value):
            return self._tokenize("SERIAL", value)
        return self.redact_text(value)
