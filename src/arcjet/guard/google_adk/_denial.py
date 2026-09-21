"""Model-visible denial payload for a Google ADK tool skip.

LangChain and CrewAI raise typed errors from their checkpoints. Google
ADK cannot: a throw from ``before_tool_callback`` is the wrong envelope,
and ``request_confirmation`` / ``require_confirmation`` are HITL, not
deny. The honest deny is a returned skip dict. ``None`` executes the
tool. An empty ``{}`` is falsy in ADK's callback chain and would let the
tool run — a silent fail-open — so this module never returns one.

The envelope is the one every JS adapter already uses. Python has no
second shape for a model-facing tool result — do not invent one.
"""

from __future__ import annotations

from typing import Any, Optional, TypedDict

from .._retry_after import retry_after_seconds
from .._types import Decision

UNAVAILABLE_RETRY_AFTER_SECONDS: int = 5


class _ArcjetDenialRequired(TypedDict):
    """Required fields of the model-visible denial envelope."""

    arcjetDenied: bool
    reason: str
    message: str
    retryable: bool


class ArcjetDenialResult(_ArcjetDenialRequired, total=False):
    """Skip dict ``before_tool_callback`` / the plugin returns to ADK.

    Keys stay camelCase so a model (and a shared Sequence reader) sees the
    same envelope the JS adapters already emit. Always truthy — never
    ``{}``.
    """

    retryAfterSeconds: int


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


def skip_dict(payload: ArcjetDenialResult) -> dict[str, Any]:
    """The callback / plugin return that skips the tool.

    Must be truthy. An empty dict is falsy in ADK's ``before_tool`` chain
    and would let the next callback — and then the tool — run.
    """
    result = dict(payload)
    if not result:
        raise RuntimeError(
            "arcjet.guard.google_adk deny payload must be truthy; "
            "an empty dict would not skip the tool"
        )
    return result
