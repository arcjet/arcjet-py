"""Model-visible denial payload for a Managed Agents custom-tool result.

LangChain and CrewAI raise typed errors from their checkpoints. Claude
Managed Agents cannot: the session is idle on ``agent.custom_tool_use``
until the client sends ``user.custom_tool_result``. The honest deny is
that event, with error text the model can read. The events schema
includes optional ``is_error`` — use it; do not invent a second field.

The envelope is the one every JS adapter already uses. Python has no
second shape for a model-facing tool result — do not invent one.
"""

from __future__ import annotations

import json
import math
import time
from typing import Any, NoReturn, Optional, TypedDict

from .._types import Decision
from ._import import load_tool_error

UNAVAILABLE_RETRY_AFTER_SECONDS: int = 5


class _ArcjetDenialRequired(TypedDict):
    """Required fields of the model-visible denial envelope."""

    arcjetDenied: bool
    reason: str
    message: str
    retryable: bool


class ArcjetDenialResult(_ArcjetDenialRequired, total=False):
    """JSON object the model reads from the custom-tool result text block.

    Keys stay camelCase so a model (and a shared Sequence reader) sees the
    same envelope the JS adapters already emit.
    """

    retryAfterSeconds: int


def retry_after_seconds(decision: Decision) -> Optional[int]:
    """Seconds until a rate-limited call may be retried.

    Only meaningful for a ``RATE_LIMIT`` denial. A co-occurring rule that
    allowed can still leave a ``reset_at_unix_seconds`` in ``decision.results``;
    ignore it when the denying reason is not a rate limit — same rule as JS
    ``denial.ts``.
    """
    if decision.reason != "RATE_LIMIT":
        return None
    now = time.time()
    found: Optional[int] = None
    for result in decision.results:
        if getattr(result, "conclusion", None) != "DENY":
            continue
        if getattr(result, "reason", None) != "RATE_LIMIT":
            continue
        reset = getattr(result, "reset_at_unix_seconds", None)
        if isinstance(reset, int) and reset > 0:
            seconds = max(0, math.ceil(reset - now))
            if found is None or seconds < found:
                found = seconds
    return found


def denied_message(decision: Decision) -> str:
    """Human- and model-readable explanation of a real DENY."""
    if decision.reason == "RATE_LIMIT":
        retry_after = retry_after_seconds(decision)
        suffix = " later." if retry_after is None else f" after {retry_after} seconds."
        return f"Arcjet denied this call ({decision.reason}). It may be retried{suffix}"
    return (
        f"Arcjet denied this call ({decision.reason}). Do not retry; explain "
        f"the denial to the user or try a different approach."
    )


def unavailable_message() -> str:
    return "Arcjet security check could not be completed; please retry later."


def denial_result(decision: Decision) -> ArcjetDenialResult:
    """Structured payload for an evaluated DENY."""
    is_rate_limit = decision.reason == "RATE_LIMIT"
    payload: ArcjetDenialResult = {
        "arcjetDenied": True,
        "reason": decision.reason,
        "message": denied_message(decision),
        "retryable": is_rate_limit,
    }
    if is_rate_limit:
        retry_after = retry_after_seconds(decision)
        if retry_after is not None:
            payload["retryAfterSeconds"] = retry_after
    return payload


def unavailable_result() -> ArcjetDenialResult:
    """Structured payload when policy could not be evaluated and we fail closed."""
    return {
        "arcjetDenied": True,
        "reason": "ERROR",
        "message": unavailable_message(),
        "retryable": True,
        "retryAfterSeconds": UNAVAILABLE_RETRY_AFTER_SECONDS,
    }


def dumps_denial(payload: ArcjetDenialResult) -> str:
    """JSON the model receives in a ``user.custom_tool_result`` text block."""
    return json.dumps(payload, separators=(",", ":"))


def payload_from_block(decision: Optional[Decision]) -> ArcjetDenialResult:
    """DENY uses the decision; everything else is an unavailability envelope.

    Action is kept on the capture, not in this envelope: the model-facing
    shape is shared with JS and has no action field.
    """
    if decision is not None and getattr(decision, "conclusion", None) == "DENY":
        return denial_result(decision)
    return unavailable_result()


def custom_tool_result_event(
    *,
    custom_tool_use_id: str,
    payload: ArcjetDenialResult,
    session_thread_id: Optional[str] = None,
) -> dict[str, Any]:
    """A real ``user.custom_tool_result`` body for ``sessions.events.send``.

    Field names match the Managed Agents events schema
    (``BetaManagedAgentsUserCustomToolResultEventParams``): ``type``,
    ``custom_tool_use_id``, ``content``, optional ``is_error``, optional
    ``session_thread_id``. ``is_error`` is on the schema — include it.
    """
    event: dict[str, Any] = {
        "type": "user.custom_tool_result",
        "custom_tool_use_id": custom_tool_use_id,
        "content": [{"type": "text", "text": dumps_denial(payload)}],
        "is_error": True,
    }
    if session_thread_id:
        event["session_thread_id"] = session_thread_id
    return event


class WorkerToolDenied(Exception):
    """Raised from a wrapped worker ``call`` when Guard denies.

    Used when ``anthropic.ToolError`` is not importable (unit tests /
    extra absent). ``SessionToolRunner`` maps any exception to
    ``is_error=True``; prefer ``ToolError`` so the model sees the
    envelope as ``content`` rather than ``repr(exc)``.
    """

    def __init__(self, content: str) -> None:
        super().__init__(content)
        self.content = content


def raise_worker_denial(payload: ArcjetDenialResult) -> NoReturn:
    """Fail a worker ``call`` so the runner posts ``is_error=True``.

    Raises Anthropic's ``ToolError`` when the extra is installed, otherwise
    :class:`WorkerToolDenied`. Both carry the denial JSON as ``content``.
    """
    text = dumps_denial(payload)
    tool_error = load_tool_error()
    if tool_error is not None:
        raise tool_error(text)
    raise WorkerToolDenied(text)
