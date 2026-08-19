"""In-process OpenTelemetry spans for the TUI, plus a debug transcript dump."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from opentelemetry.sdk.trace import ReadableSpan, SpanProcessor, TracerProvider
from pydantic_ai.models.instrumented import InstrumentationSettings

_MAX_PART = 2000


def debug_strip(text: str, secret: str | None) -> str:
    if secret:
        text = text.replace(secret, "[STRIPPED]")
    return text


def span_to_event(span: Any, *, ended: bool) -> dict:
    name = _span_name(span)
    event: dict = {
        "phase": "llm",
        "status": "span",
        "name": name,
        "state": "end" if ended else "start",
    }
    if ended:
        event["ms"] = _span_ms(span)
    return event


def _span_name(span: Any) -> str:
    raw = str(getattr(span, "name", "") or "span")
    attrs = getattr(span, "attributes", None) or {}
    model = attrs.get("gen_ai.request.model") or attrs.get("gen_ai.response.model")
    if isinstance(model, str) and model:
        short = model.rsplit("/", 1)[-1]
        raw = raw.replace(model, short)
        if short not in raw:
            raw = f"{raw} {short}"
    return raw[:160]


def _span_ms(span: Any) -> int | None:
    start = getattr(span, "start_time", None)
    end = getattr(span, "end_time", None)
    if start is None or end is None:
        return None
    return max(0, int((end - start) / 1_000_000))


class LlmSpanProcessor(SpanProcessor):
    def __init__(self, on_event: Callable[[dict], None]) -> None:
        self._on_event = on_event

    def on_start(self, span, parent_context=None) -> None:
        self._safe_emit(span, ended=False)

    def on_end(self, span: ReadableSpan) -> None:
        self._safe_emit(span, ended=True)

    def _safe_emit(self, span: Any, *, ended: bool) -> None:
        try:
            self._on_event(span_to_event(span, ended=ended))
        except Exception:
            return

    def shutdown(self) -> None:
        return None

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True


def instrumentation_settings(on_event: Callable[[dict], None]) -> InstrumentationSettings:
    provider = TracerProvider()
    provider.add_span_processor(LlmSpanProcessor(on_event))
    return InstrumentationSettings(
        tracer_provider=provider,
        include_content=False,
        include_binary_content=False,
        include_model_request_parameters=False,
    )


def format_transcript(messages: list, *, secret: str | None = None) -> str:
    lines = ["--- LLM transcript (what the model saw; already redacted) ---"]
    for message in messages:
        parts = getattr(message, "parts", None) or ()
        if not parts:
            lines.append(type(message).__name__)
            continue
        for part in parts:
            lines.append(_format_part(part))
    return debug_strip("\n".join(lines), secret)


def _format_part(part: Any) -> str:
    label = type(part).__name__
    tool = getattr(part, "tool_name", None)
    args = getattr(part, "args", None)
    content = getattr(part, "content", None)
    if tool and args is not None:
        return f"{label} {tool} {_clip(args)}"
    if tool is not None and content is not None:
        return f"{label} {tool} {_clip(content)}"
    if content is not None:
        return f"{label} {_clip(content)}"
    if tool:
        return f"{label} {tool}"
    return label


def _clip(value: object) -> str:
    text = value if isinstance(value, str) else repr(value)
    if len(text) > _MAX_PART:
        return text[:_MAX_PART] + "…[truncated]"
    return text
