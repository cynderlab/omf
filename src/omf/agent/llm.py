"""Pydantic AI analysis agent. No adapter, session, or token_map."""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx
from pydantic_ai import Agent, capture_run_messages
from pydantic_ai.models.anthropic import AnthropicModel
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.anthropic import AnthropicProvider
from pydantic_ai.providers.openai import OpenAIProvider

from omf.agent.report import ReportNarrative, narrative_body
from omf.agent.tools import AnalysisContext, fail_pack, status_counts
from omf.agent.trace import format_transcript, instrumentation_settings
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


def _http_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=_LLM_TIMEOUT)


def _model_for(settings: LlmSettings):
    model_name = settings.model or ""
    if settings.api_style == "anthropic":
        return AnthropicModel(
            model_name,
            provider=AnthropicProvider(
                api_key=settings.api_key,
                base_url=settings.base_url,
                http_client=_http_client(),
            ),
        )
    return OpenAIChatModel(
        model_name,
        provider=OpenAIProvider(
            api_key=settings.api_key,
            base_url=settings.base_url,
            http_client=_http_client(),
        ),
    )


def build_agent(ctx: AnalysisContext, settings: LlmSettings) -> Agent:
    return Agent(
        _model_for(settings),
        system_prompt=_prompt_for(ctx.language, _target_noun(ctx.vendor)),
        output_type=ReportNarrative,
        name="omf_analysis",
    )


def run_analysis(
    ctx: AnalysisContext,
    settings: LlmSettings,
    on_event: Callable[[dict], None] | None = None,
) -> str:
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

    agent = build_agent(ctx, settings)
    if on_event is not None:
        agent.instrument = instrumentation_settings(on_event)

    last_exc: BaseException | None = None
    messages: list = []
    prompt = _user_prompt(ctx, pack, counts)
    for _ in range(2):
        try:
            with capture_run_messages() as messages:
                result = agent.run_sync(prompt)
            _keep_transcript(ctx, messages, settings.api_key)
            output = result.output
            if not isinstance(output, ReportNarrative):
                last_exc = RuntimeError("agent did not return a report narrative")
                continue
            usage = getattr(result, "usage", None)
            if callable(usage):
                usage = usage()
            _log.info("llm done requests=%s", getattr(usage, "requests", None))
            return narrative_body(
                output,
                ctx.findings,
                ctx.checks,
                ctx.vendor,
                language=ctx.language,
            )
        except Exception as exc:
            _keep_transcript(ctx, messages, settings.api_key)
            last_exc = exc
    assert last_exc is not None
    raise last_exc


def _keep_transcript(ctx: AnalysisContext, messages: list, secret: str | None) -> None:
    if not messages:
        return
    text = format_transcript(messages, secret=secret, max_part=None)
    system = _prompt_for(ctx.language, _target_noun(ctx.vendor))
    if system not in text:
        text = f"SystemPromptPart {system}\n{text}"
    ctx.transcript = text
    _dump_transcript(messages, secret)


def _dump_transcript(messages: list, secret: str | None) -> None:
    if not debug_enabled() or not messages:
        return
    _log.debug("%s", format_transcript(messages, secret=secret))
