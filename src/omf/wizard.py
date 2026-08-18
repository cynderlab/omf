"""Pure validators for vendor, URL, language, and yes/no answers."""

from __future__ import annotations

from typing import Literal
from urllib.parse import urlparse

_ALLOWED_VENDORS = frozenset({"mikrotik", "fortinet"})
_ALLOWED_LANGUAGES = frozenset({"ca", "es", "en"})
_YES = frozenset({"y", "yes", "true", "1"})
_NO = frozenset({"n", "no", "false", "0"})


class ValidationError(ValueError):
    pass


def parse_vendor(raw: str) -> Literal["mikrotik", "fortinet"]:
    value = raw.strip().lower()
    if value not in _ALLOWED_VENDORS:
        raise ValidationError(f"unsupported vendor: {raw!r}")
    return value  # type: ignore[return-value]


def _clean_pasted_url(raw: str) -> str:
    text = (
        raw.replace("\u00a0", " ")
        .replace("\r", "")
        .replace("\n", "")
        .replace("\t", "")
    )
    text = "".join(ch for ch in text if ch.isprintable())
    return text.strip().strip("\"'“”‘’«»<>")


def parse_url(raw: str) -> str:
    text = _clean_pasted_url(raw)
    if not text:
        raise ValidationError("URL host is required")
    if "://" not in text:
        text = f"https://{text}"
    parsed = urlparse(text)
    if parsed.scheme not in {"http", "https"}:
        raise ValidationError(f"URL scheme must be http or https: {raw!r}")
    if not parsed.netloc:
        raise ValidationError(f"URL host is required: {raw!r}")
    if parsed.username is not None or parsed.password is not None:
        raise ValidationError("credentials must not be embedded in the URL")
    path = parsed.path.rstrip("/")
    lowered = path.lower()
    if (
        lowered in {"/rest", "/webfig", "/login", "/index.html"}
        or lowered.startswith("/rest/")
        or lowered.startswith("/webfig")
    ):
        path = ""
    result = f"{parsed.scheme}://{parsed.netloc}{path}"
    if parsed.query:
        result += f"?{parsed.query}"
    if parsed.fragment:
        result += f"#{parsed.fragment}"
    return result


def parse_language(raw: str) -> Literal["ca", "es", "en"]:
    value = raw.strip().lower()
    if value not in _ALLOWED_LANGUAGES:
        raise ValidationError(f"unsupported language: {raw!r}")
    return value  # type: ignore[return-value]


def parse_yes_no(raw: str, *, default: bool) -> bool:
    value = raw.strip().lower()
    if not value:
        return default
    if value in _YES:
        return True
    if value in _NO:
        return False
    raise ValidationError(f"expected yes/no: {raw!r}")
