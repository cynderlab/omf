"""Pydantic AI analysis agent. No adapter, session, or token_map."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable

from pydantic_ai import Agent, capture_run_messages
from pydantic_ai.models.anthropic import AnthropicModel
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.anthropic import AnthropicProvider
from pydantic_ai.providers.openai import OpenAIProvider

from omf.agent.report import copy_for
from omf.agent.tools import AnalysisContext, make_tools
from omf.agent.trace import format_transcript, instrumentation_settings
from omf.config import LlmSettings
from omf.log import debug_enabled, get_logger

_log = get_logger("omf.agent.llm")

_SYSTEM_PROMPT = """You write a firewall audit report in language code: {language}.
Use only tool data. Adapt catalog mitigations to the redacted evidence.
Do not invent vendor CLI or API beyond that mitigation text.
State that mitigations are examples and the auditor owns any change.
Do not ask for credentials. Do not guess hidden IPs, hostnames, or URLs.
Do not write a title or metadata block (author, date, firewall, tool). Those are prepended locally.

Call submit_report with the markdown body in this exact shape:

## {exec}

<one short paragraph: scope, fail/pass/error/skipped counts, main risks>

| id | severity | title |
| --- | --- | --- |
<one row per fail finding only; title in the report language>

## {vulns}

### <check_id> — <title in the report language>
**Severity:** <info|low|medium|high>
**Description:** <what is wrong and why it matters>
**Evidence:** <redacted facts from tools>
**Mitigation:** <catalog text, adapted to this evidence>

Rules:
- Vulnerabilities section: fail findings only, highest severity first.
- Do not write sections for pass, error, or skipped.
- Every fail from list_findings must appear in the table and as a vulnerability."""

_USER_PROMPT = "Write the firewall audit report using only the tools."


class LlmNotConfigured(Exception):
    pass


def _prompt_for(language: str) -> str:
    copy = copy_for(language)
    return _SYSTEM_PROMPT.format(
        language=language, exec=copy["exec"], vulns=copy["vulns"]
    )


def _model_for(settings: LlmSettings):
    model_name = settings.model or ""
    if settings.api_style == "anthropic":
        return AnthropicModel(
            model_name,
            provider=AnthropicProvider(api_key=settings.api_key, base_url=settings.base_url),
        )
    return OpenAIChatModel(
        model_name,
        provider=OpenAIProvider(api_key=settings.api_key, base_url=settings.base_url),
    )


def build_agent(
    ctx: AnalysisContext,
    settings: LlmSettings,
    on_tool: Callable[[dict], None] | None = None,
) -> Agent:
    return Agent(
        _model_for(settings),
        system_prompt=_prompt_for(ctx.language),
        tools=make_tools(ctx, on_tool=on_tool),
        name="omf_analysis",
    )


def _invoke_run(agent: Agent) -> None:
    result = agent.run(_USER_PROMPT)
    if inspect.isawaitable(result):
        asyncio.run(result)


def run_analysis(
    ctx: AnalysisContext,
    settings: LlmSettings,
    on_event: Callable[[dict], None] | None = None,
) -> str:
    if not settings.is_configured():
        raise LlmNotConfigured("LLM base_url, api_key, and model are required")

    def on_tool(event: dict) -> None:
        if on_event is None:
            return
        _log.info("[llm] %s", event.get("tool"))
        payload = {"phase": "llm", "status": "tool"}
        payload.update(event)
        on_event(payload)

    agent = build_agent(ctx, settings, on_tool=on_tool)
    if on_event is not None:
        agent.instrument = instrumentation_settings(on_event)

    last_exc: BaseException | None = None
    messages: list = []
    for _ in range(2):
        try:
            with capture_run_messages() as messages:
                _invoke_run(agent)
            _dump_transcript(messages, settings.api_key)
            if ctx.submitted:
                return ctx.submitted[-1]
            last_exc = RuntimeError("agent did not call submit_report")
        except Exception as exc:
            _dump_transcript(messages, settings.api_key)
            last_exc = exc
    assert last_exc is not None
    raise last_exc


def _dump_transcript(messages: list, secret: str | None) -> None:
    if not debug_enabled() or not messages:
        return
    _log.debug("%s", format_transcript(messages, secret=secret))
