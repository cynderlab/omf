from __future__ import annotations

_ANY_LITERALS = frozenset({"", "*", "all", "any"})
_ANY_EXACT = frozenset({"0.0.0.0/0", "::/0"})


def as_any_token(value: object) -> str:
    if value is None:
        return "any"
    text = str(value).strip()
    if text.lower() in _ANY_LITERALS or text in _ANY_EXACT:
        return "any"
    return str(value)


__all__ = ["as_any_token"]
