from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml
from dotenv import dotenv_values

from omf import DISCLAIMER_VERSION

_ALLOWED_LANGUAGES = frozenset({"ca", "es", "en"})
_ALLOWED_VENDORS = frozenset({"mikrotik", "fortinet"})
_ALLOWED_API_STYLES = frozenset({"openai", "anthropic"})


@dataclass(frozen=True)
class LlmSettings:
    base_url: str | None
    api_key: str | None
    model: str | None
    api_style: Literal["openai", "anthropic"]

    def is_configured(self) -> bool:
        return bool(self.base_url and self.api_key and self.model)


@dataclass
class UserPrefs:
    disclaimer_accepted: bool
    disclaimer_version: int
    default_report_language: Literal["ca", "es", "en"]
    last_vendor: Literal["mikrotik", "fortinet"] | None


def _empty_to_none(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _default_prefs() -> UserPrefs:
    return UserPrefs(
        disclaimer_accepted=False,
        disclaimer_version=0,
        default_report_language="ca",
        last_vendor=None,
    )


def load_llm_settings(cwd: Path, config_dir: Path) -> LlmSettings:
    env_path: Path | None = None
    for candidate in (cwd / ".env", config_dir / ".env"):
        if candidate.is_file():
            env_path = candidate
            break

    values = dotenv_values(env_path) if env_path is not None else {}
    style = (values.get("OMF_LLM_API_STYLE") or "").strip()
    if style not in _ALLOWED_API_STYLES:
        style = "openai"

    return LlmSettings(
        base_url=_empty_to_none(values.get("OMF_LLM_BASE_URL")),
        api_key=_empty_to_none(values.get("OMF_LLM_API_KEY")),
        model=_empty_to_none(values.get("OMF_LLM_MODEL")),
        api_style=style,  # type: ignore[arg-type]
    )


def _parse_prefs(data: object) -> UserPrefs:
    if not isinstance(data, dict):
        raise ValueError("config.yaml root must be a mapping")

    lang = data.get("default_report_language", "ca")
    if lang not in _ALLOWED_LANGUAGES:
        lang = "ca"

    vendor = data.get("last_vendor")
    if vendor not in _ALLOWED_VENDORS:
        vendor = None

    version = data.get("disclaimer_version", 0)
    try:
        version_int = int(version)
    except (TypeError, ValueError):
        version_int = 0

    return UserPrefs(
        disclaimer_accepted=bool(data.get("disclaimer_accepted", False)),
        disclaimer_version=version_int,
        default_report_language=lang,  # type: ignore[arg-type]
        last_vendor=vendor,  # type: ignore[arg-type]
    )


def load_user_prefs(config_dir: Path) -> tuple[UserPrefs, str | None]:
    path = config_dir / "config.yaml"
    if not path.is_file():
        prefs = _default_prefs()
        save_user_prefs(config_dir, prefs)
        return prefs, f"Missing {path.name}; using defaults"

    try:
        raw = path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw)
        prefs = _parse_prefs(data)
        return prefs, None
    except (OSError, yaml.YAMLError, ValueError, TypeError) as exc:
        prefs = _default_prefs()
        save_user_prefs(config_dir, prefs)
        return prefs, f"Broken {path.name} ({exc}); using defaults"


def save_user_prefs(config_dir: Path, prefs: UserPrefs) -> None:
    config_dir.mkdir(parents=True, exist_ok=True)
    path = config_dir / "config.yaml"
    payload = {
        "disclaimer_accepted": prefs.disclaimer_accepted,
        "disclaimer_version": prefs.disclaimer_version,
        "default_report_language": prefs.default_report_language,
        "last_vendor": prefs.last_vendor,
    }
    path.write_text(
        yaml.safe_dump(payload, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )


def needs_disclaimer(prefs: UserPrefs) -> bool:
    return (not prefs.disclaimer_accepted) or (
        prefs.disclaimer_version != DISCLAIMER_VERSION
    )
