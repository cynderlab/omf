"""Deterministic identifier tokenization. The model only ever sees tokens."""

from __future__ import annotations

import re
from typing import Any

ALLOWLIST = frozenset({
    "admin", "administrator", "root", "guest", "public", "private",
    "accept", "deny", "drop", "any", "mikrotik", "fortinet", "fortigate",
    "ftp", "ssh", "telnet", "http", "https", "www", "www-ssl", "api", "api-ssl",
    "winbox", "ntp", "dns", "dhcp", "ping", "snmp", "pptp", "l2tp", "ike",
})
STRIP_KEYS = frozenset({
    "password", "passwd", "passphrase", "secret", "psk", "private_key", "api_key",
})

_USER_KEYS = frozenset({"name", "username"})
_HOST_KEYS = frozenset({"hostname", "host"})
_SERIAL_KEYS = frozenset({"serial", "serial_number"})
_COMMUNITY_PARENTS = frozenset({"communities", "community"})

_H = r"[0-9A-Fa-f]{1,4}"
_V4 = (
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
)

_URL_RE = re.compile(r"(?:https?|ftp)://[^\s<>\"']+", re.IGNORECASE)
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b"
)
_IPV4_RE = re.compile(rf"\b{_V4}\b")
_IPV4_CIDR_RE = re.compile(rf"\b{_V4}/(?:3[0-2]|[12]?\d)\b")
_IPV4_RANGE_RE = re.compile(rf"\b{_V4}-{_V4}\b")
# IPv4-tail forms first so ::ffff:10.0.0.1 is not split into prefix + dotted quad.
_IPV6_CORE = (
    rf"(?:"
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
    rf")"
)
_IPV6_RE = re.compile(rf"(?<![0-9A-Fa-f:]){_IPV6_CORE}(?![0-9A-Fa-f:])")
_IPV6_CIDR_RE = re.compile(
    rf"(?<![0-9A-Fa-f:]){_IPV6_CORE}/(?:12[0-8]|1[01]\d|[1-9]?\d)(?!\d)"
)
_IPV6_RANGE_RE = re.compile(
    rf"(?<![0-9A-Fa-f:]){_IPV6_CORE}-{_IPV6_CORE}(?![0-9A-Fa-f:])"
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
        # URL → email → IPv6 ranges → IPv6 → IPv4 ranges → IPv4 → FQDN.
        # CIDR/hyphen ranges before bare addresses so 10.0.0.0/24 is one token.
        text = _URL_RE.sub(lambda m: self._tokenize("URL", m.group(0)), text)
        text = _EMAIL_RE.sub(lambda m: self._tokenize("USER", m.group(0)), text)
        text = _IPV6_CIDR_RE.sub(lambda m: self._tokenize("IP", m.group(0)), text)
        text = _IPV6_RANGE_RE.sub(lambda m: self._tokenize("IP", m.group(0)), text)
        text = _IPV6_RE.sub(lambda m: self._tokenize("IP", m.group(0)), text)
        text = _IPV4_CIDR_RE.sub(lambda m: self._tokenize("IP", m.group(0)), text)
        text = _IPV4_RANGE_RE.sub(lambda m: self._tokenize("IP", m.group(0)), text)
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
                elif key_l is not None and key_l in _HOST_KEYS and isinstance(value, str):
                    out[key] = self._redact_host_value(value)
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

    def apply_known(self, obj: Any) -> Any:
        """Rewrite already-seen originals in every string (longest first)."""
        replacements = sorted(
            ((original, token) for original, token in self._forward.items() if original),
            key=lambda item: len(item[0]),
            reverse=True,
        )
        return self._apply_known(obj, replacements)

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

    def _redact_host_value(self, value: str) -> str:
        if not value.strip() or self._is_allowlisted(value):
            return value
        return self._tokenize("HOST", value)

    def _apply_known(self, obj: Any, replacements: list[tuple[str, str]]) -> Any:
        if isinstance(obj, dict):
            return {key: self._apply_known(value, replacements) for key, value in obj.items()}
        if isinstance(obj, list):
            return [self._apply_known(item, replacements) for item in obj]
        if isinstance(obj, tuple):
            return tuple(self._apply_known(item, replacements) for item in obj)
        if isinstance(obj, str):
            for original, token in replacements:
                if original in obj:
                    obj = obj.replace(original, token)
            return obj
        return obj

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


def leak_hits(obj: Any) -> list[str]:
    """IPv4 / IPv6 / URLs still in the clear. Token strings do not match."""
    found: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        if value and value not in seen:
            seen.add(value)
            found.append(value)

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for item in value.values():
                walk(item)
            return
        if isinstance(value, (list, tuple)):
            for item in value:
                walk(item)
            return
        if isinstance(value, str):
            rest = value
            for rx in (
                _URL_RE,
                _EMAIL_RE,
                _IPV6_CIDR_RE,
                _IPV6_RANGE_RE,
                _IPV6_RE,
                _IPV4_CIDR_RE,
                _IPV4_RANGE_RE,
                _IPV4_RE,
            ):
                for match in rx.finditer(rest):
                    add(match.group(0))
                rest = rx.sub(" ", rest)

    walk(obj)
    return found
