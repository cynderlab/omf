"""Process logging. Debug may include request URLs; never userinfo or secrets."""

from __future__ import annotations

import logging
import sys

ROOT = "omf"


def configure(*, debug: bool = False) -> logging.Logger:
    level = logging.DEBUG if debug else logging.WARNING

    logger = logging.getLogger(ROOT)
    logger.setLevel(level)
    logger.propagate = False
    logger.handlers.clear()
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)
    if debug:
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)s [%(name)s] %(message)s",
            datefmt="%H:%M:%S",
        )
    else:
        formatter = logging.Formatter("%(levelname)s: %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.debug("logging at %s", logging.getLevelName(level))
    return logger


def http_target(base_url: object, path: str) -> str:
    """Full request URL for debug logs. Never includes userinfo."""
    raw = str(base_url or "").strip().rstrip("/")
    if "://" in raw:
        scheme, rest = raw.split("://", 1)
        host = rest.split("@")[-1]
        raw = f"{scheme}://{host}"
    suffix = path if path.startswith("/") else f"/{path}"
    return f"{raw}{suffix}"


def get_logger(name: str = ROOT) -> logging.Logger:
    if name != ROOT and not name.startswith(f"{ROOT}."):
        name = f"{ROOT}.{name}"
    return logging.getLogger(name)


def debug_enabled() -> bool:
    return get_logger().isEnabledFor(logging.DEBUG)
