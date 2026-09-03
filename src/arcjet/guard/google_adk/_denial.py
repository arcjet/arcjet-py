"""Model-visible denial payload for a Google ADK ``before_tool_callback``.

LangChain and CrewAI raise typed errors from their checkpoints. Google ADK
cannot: a throw from ``before_tool_callback`` is a plugin / callback error,
not skip. The honest deny is a returned dict — ADK treats any mapping,
including ``{}``, as the tool result and skips the original function.
``None`` is the only allow. Never return ``{}`` to allow.

The envelope is the one every JS adapter already uses. Python has no second
shape for a model-facing tool result — do not invent one.
"""

from __future__ import annotations

import math
import time
from typing import Any, Optional, TypedDict

from .._types import Decision

UNAVAILABLE_RETRY_AFTER_SECONDS: int = 5


class _ArcjetDenialRequired(TypedDict):
    """Required fields of the model-visible denial envelope."""

    arcjetDenied: bool
    reason: str
    message: str
    retryable: bool


class ArcjetDenialResult(_ArcjetDenialRequired, total=False):
    """JSON object ``before_tool_callback`` returns to skip the tool.

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


def payload_from_block(decision: Optional[Decision]) -> ArcjetDenialResult:
    """DENY uses the decision; everything else is an unavailability envelope.

    Action is kept on the capture, not in this envelope: the model-facing
    shape is shared with JS and has no action field.
    """
    if decision is not None and getattr(decision, "conclusion", None) == "DENY":
        return denial_result(decision)
    return unavailable_result()


def deny_dict(payload: ArcjetDenialResult) -> dict[str, Any]:
    """Skip-with-result mapping. Never empty — ADK treats ``{}`` as skip too."""
    result: dict[str, Any] = {**payload}
    if not result:
        return {**unavailable_result()}
    return result
