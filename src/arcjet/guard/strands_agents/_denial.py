"""Model-visible denial payload for a Strands Agents tool result.

LangChain and CrewAI raise typed errors from their checkpoints. Strands
cannot: an exception from an authored ``@tool`` handler is wrapped as
``Error: {Type} - {message}`` and the structured envelope is lost. The
honest deny from ``guard_tool`` is a returned ``ArcjetDenialResult`` dict
— ``DecoratedFunctionTool._wrap_tool_result`` JSON-serializes any other
mapping into a success tool-result text block.

``guard_hooks`` denies on ``BeforeToolCallEvent.cancel_tool``. A string
becomes the error tool-result message; ``True`` uses Strands' default
cancel text. The string is the same JSON envelope so the model can read
it. ``event.interrupt()`` is HITL, not a policy gate.

The envelope is the one every JS adapter already uses. Python has no second
shape for a model-facing tool result — do not invent one.
"""

from __future__ import annotations

import json
import math
import time
from typing import Optional, TypedDict

from .._types import Decision

UNAVAILABLE_RETRY_AFTER_SECONDS: int = 5


class _ArcjetDenialRequired(TypedDict):
    """Required fields of the model-visible denial envelope."""

    arcjetDenied: bool
    reason: str
    message: str
    retryable: bool


class ArcjetDenialResult(_ArcjetDenialRequired, total=False):
    """JSON object the model reads from the tool result.

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
    """JSON the model receives in a tool-result text block or cancel message."""
    return json.dumps(payload, separators=(",", ":"))


def payload_from_block(decision: Optional[Decision]) -> ArcjetDenialResult:
    """DENY uses the decision; everything else is an unavailability envelope.

    Action is kept on the capture, not in this envelope: the model-facing
    shape is shared with JS and has no action field.
    """
    if decision is not None and getattr(decision, "conclusion", None) == "DENY":
        return denial_result(decision)
    return unavailable_result()


def cancel_tool_value(payload: ArcjetDenialResult) -> str:
    """``BeforeToolCallEvent.cancel_tool`` string that still carries the envelope.

    A string is placed in an error-status tool result. ``True`` would skip
    the handler with Strands' default cancel text and drop these fields.
    """
    return dumps_denial(payload)
