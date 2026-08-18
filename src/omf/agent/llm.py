from __future__ import annotations

import asyncio
import inspect

from pydantic_ai import Agent
from pydantic_ai.models.anthropic import AnthropicModel
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.anthropic import AnthropicProvider
from pydantic_ai.providers.openai import OpenAIProvider

from omf.agent.tools import AnalysisContext, make_tools
from omf.config import LlmSettings

_SYSTEM_PROMPT = """You write a firewall audit report in language code: {language}.
Use only tool data. Adapt catalog mitigations to the redacted evidence.
Do not invent vendor CLI or API beyond that mitigation text.
State that mitigations are examples and the auditor owns any change.
Do not ask for credentials. Do not guess hidden IPs, hostnames, or URLs.
Call submit_report with the full markdown body (no title header)."""

_USER_PROMPT = "Write the firewall audit report using only the tools."


class LlmNotConfigured(Exception):
    pass


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


def build_agent(ctx: AnalysisContext, settings: LlmSettings) -> Agent:
    return Agent(
        _model_for(settings),
        system_prompt=_SYSTEM_PROMPT.format(language=ctx.language),
        tools=make_tools(ctx),
        name="omf_analysis",
    )


def _invoke_run(agent: Agent) -> None:
    result = agent.run(_USER_PROMPT)
    if inspect.isawaitable(result):
        asyncio.run(result)


def run_analysis(ctx: AnalysisContext, settings: LlmSettings) -> str:
    if not settings.is_configured():
        raise LlmNotConfigured("LLM base_url, api_key, and model are required")

    agent = build_agent(ctx, settings)
    last_exc: BaseException | None = None
    for _ in range(2):
        try:
            _invoke_run(agent)
            if ctx.submitted:
                return ctx.submitted[-1]
            last_exc = RuntimeError("agent did not call submit_report")
        except Exception as exc:
            last_exc = exc
    assert last_exc is not None
    raise last_exc
