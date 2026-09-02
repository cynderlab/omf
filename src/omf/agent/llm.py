"""One-shot httpx JSON analysis. No adapter, session, or token_map."""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx

from omf.agent.report import ReportNarrative, narrative_body
from omf.agent.tools import AnalysisContext, fail_pack, status_counts
from omf.config import LlmSettings
from omf.log import debug_enabled, get_logger
from omf.redactor import leak_hits

_log = get_logger("omf.agent.llm")
_LLM_TIMEOUT = httpx.Timeout(120.0, connect=15.0)
_CATALOG_FIELDS = frozenset({"description"})

_SYSTEM_PROMPT = """You write a configuration audit report in language code: {language}.
Use only the packed findings in the user message. Adapt catalog descriptions to the redacted evidence.
Do not invent vendor CLI or API.
Do not write mitigation or remediation steps; those are assembled locally from the catalog.
Do not ask for credentials. Do not guess hidden IPs, hostnames, or URLs.
Do not write a title or metadata block (author, date, target, tool). Those are prepended locally.

Return structured narrative only:
- executive_summary: one short paragraph with scope, fail/pass/error/skipped counts, and main risks.
- vulnerabilities: one item per fail finding, highest severity first.
  - check_id from the pack
  - title in the report language
  - description: catalog description, rephrased into the report language and bound to observed/diagnostic. Do not invent rationale beyond that catalog text.

Rules:
- Fail findings only. Do not write items for pass, error, or skipped.
- Every fail in the pack must appear as a vulnerability.
- Narrative and titles are in the report language.
- Status words (pass, fail, error, skipped) and severity tokens stay English.
- Do not include evidence tables or vendor CLI; those are assembled locally.

Terminology when language is ca or es:
Write as a consultant auditor. Use established cybersecurity terms in that language. Never invent a literal translation of English jargon. If a calque and the English term both exist, keep the English term.

Fail items are vulnerabilitats (ca) or vulnerabilidades (es). Never troballes, hallazgos, or "findings" in the report body.

{noun_line}

Established target-language terms (use these, not English): xifratge/cifrado, autenticació/autenticación, credencials/credenciales, contrasenya/contraseña, amenaça/amenaza, política, interfície/interfaz, registre (for logs).

Keep English loanwords and vendor, product, protocol, and feature names as-is, including: backdoor (not porta del darrere / puerta de atrás), exploit, payload, bypass, handshake (not encaixada de mans / apretón de manos), timeout, hardening, dump, sniffing, spoofing, MITM (not home al mig / hombre en el medio), trusthost (not amfitrió de confiança / anfitrión de confiança), stitch (not puntada), WinBox, local-in, virtual patch, allowaccess, neighbor discovery, strong-crypto, RouterOS, FortiOS, syslog, SNMP, NTP, TLS, SSH, PPTP, IPS, IDS, UTM, HA, ISDB, WAN, VLAN, NAT.

Keep as-is: check ids, capability names, CLI/API, redaction tokens such as [IP_n], and policy tokens accept, deny, drop, any."""


class LlmNotConfigured(Exception):
    pass


class LlmPayloadLeak(Exception):
    """Redacted findings/evidence still contain identifiers. Do not call the model."""


def _noun_line(target_noun: str) -> str:
    if target_noun == "firewall":
        return "Device noun: ca tallafoc; es firewall (not cortafuegos)."
    return f"Target noun: {target_noun}."


def _target_noun(vendor: str) -> str:
    from omf.vendors import get as vendor_spec

    try:
        return vendor_spec(vendor).target_noun
    except ValueError:
        return "firewall"


def _prompt_for(language: str, target_noun: str = "firewall") -> str:
    return _SYSTEM_PROMPT.format(
        language=language,
        noun_line=_noun_line(target_noun),
    )


def _user_prompt(ctx: AnalysisContext, pack: list[dict], counts: dict[str, int]) -> str:
    payload = {"counts": counts, "fails": pack}
    return (
        "Write the audit narrative from this packed data only. "
        "Return executive_summary and one vulnerability per fail "
        f"(title+description in language {ctx.language}).\n"
        + json.dumps(payload, ensure_ascii=False)
    )


def _strip_secret(text: str, secret: str | None) -> str:
    if secret:
        return text.replace(secret, "[STRIPPED]")
    return text


def _endpoint(base_url: str, suffix: str) -> str:
    url = base_url.rstrip("/")
    if not url.endswith(suffix):
        url = f"{url}{suffix}"
    return url


def _complete(settings: LlmSettings, system: str, user: str) -> str:
    style = settings.api_style
    base = settings.base_url or ""
    if style == "anthropic":
        url = _endpoint(base, "/v1/messages")
        headers = {
            "x-api-key": settings.api_key or "",
            "anthropic-version": "2023-06-01",
        }
        payload: dict = {
            "model": settings.model,
            "max_tokens": 8192,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
    else:
        url = _endpoint(base, "/chat/completions")
        headers = {"Authorization": f"Bearer {settings.api_key or ''}"}
        payload = {
            "model": settings.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {"type": "json_object"},
        }
    with httpx.Client(timeout=_LLM_TIMEOUT, trust_env=False) as client:
        response = client.post(url, headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()
    if style == "anthropic":
        text = data["content"][0]["text"]
    else:
        text = data["choices"][0]["message"]["content"]
    if not isinstance(text, str):
        raise RuntimeError("LLM response content is not text")
    return text


def _keep_transcript(
    ctx: AnalysisContext,
    system: str,
    user: str,
    raw: str,
    secret: str | None,
) -> None:
    ctx.transcript = _strip_secret(f"{system}\n{user}\n{raw}", secret)
    if debug_enabled():
        _log.debug("%s", ctx.transcript)


def run_analysis(
    ctx: AnalysisContext,
    settings: LlmSettings,
    on_event: Callable[[dict], None] | None = None,
) -> str:
    del on_event
    if not settings.is_configured():
        raise LlmNotConfigured("LLM base_url, api_key, and model are required")

    pack = fail_pack(ctx)
    counts = status_counts(ctx)
    leaks = leak_hits({
        "findings": [
            {key: value for key, value in row.items() if key not in _CATALOG_FIELDS}
            for row in pack
        ],
        "counts": counts,
    })
    if leaks:
        _log.warning("llm payload leak count=%s", len(leaks))
        raise LlmPayloadLeak(
            f"redacted payload still contains identifiers ({leaks[0]})"
        )

    system = _prompt_for(ctx.language, _target_noun(ctx.vendor))
    user = _user_prompt(ctx, pack, counts)
    last_exc: BaseException | None = None
    for _ in range(2):
        try:
            raw = _complete(settings, system, user)
            _keep_transcript(ctx, system, user, raw, settings.api_key)
            narrative = ReportNarrative.model_validate(json.loads(raw))
            _log.info("llm done")
            return narrative_body(
                narrative,
                ctx.findings,
                ctx.checks,
                ctx.vendor,
                language=ctx.language,
            )
        except Exception as exc:
            last_exc = exc
    assert last_exc is not None
    raise last_exc
