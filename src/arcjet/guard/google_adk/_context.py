"""Caller-owned correlation for a Google ADK run.

JS ``@arcjet/guard/google-adk/v2`` reads ``correlationId`` then
``sessionId`` then ``conversationId``. This helper reads the same slots,
with snake_case aliases so a Python caller is not dropped over spelling.
It never mints. It never reads ``trace_id``. It never reads an
ADK-generated ``invocation_id``. It never reads ``toolContext.sessionId``
or ``session.id`` — ADK can generate a session or invocation id when you
omit one, and joining a Sequence on that value is one nobody can look
up.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Optional

from arcjet._logging import logger
from arcjet._metadata import Metadata

from .._context import _validated, current_correlation_id

#: Names read off the caller-owned object, in preference order. Each slot
#: lists the JS camelCase spelling first (the JS adapter's contract) and
#: the Python snake_case alias second. Every name in a slot is offered as
#: a candidate, so a present-but-invalid one does not hide its alias.
_ID_SLOTS: tuple[tuple[str, ...], ...] = (
    ("correlationId", "correlation_id"),
    ("sessionId", "session_id"),
    ("conversationId", "conversation_id"),
)

#: Never read as correlation. The SDK / a tracer can mint a trace id or
#: an invocation id when one is omitted; joining a Sequence on it is one
#: nobody can look up. ``session.id`` / ``toolContext.sessionId`` are
#: ADK-owned and are never a source — do not walk into ``.session``.
_NEVER_READ = frozenset(
    {
        "trace_id",
        "traceId",
        "invocation_id",
        "invocationId",
        "session.id",
    }
)

#: Attributes that look like an ADK-generated session / invocation id on
#: a ``ToolContext``. Reading them would join the Sequence to an id the
#: caller did not pass. ``state`` is application-owned and is read.
_ADK_GENERATED = frozenset(
    {
        "sessionId",
        "session_id",
        "invocationId",
        "invocation_id",
    }
)


@dataclass(frozen=True, slots=True)
class GoogleAdkContext:
    """What :func:`google_adk_context` derived.

    ``correlation_id`` is ``None`` when nothing valid was present — this
    helper never mints one.
    """

    correlation_id: Optional[str] = None
    metadata: Optional[Metadata] = None


def _readable(value: Any) -> Any:
    """*value* if named fields can be read off it, else ``None``."""
    if value is None or isinstance(
        value, (str, bytes, bytearray, list, tuple, set, frozenset)
    ):
        return None
    return value


def _looks_like_tool_context(source: Any) -> bool:
    """True when *source* exposes an ADK ``session`` object.

    Those objects carry a generated ``session.id``. This helper must not
    treat that as caller-owned, and must not read ``session_id`` off the
    context itself either — JS never reads ``toolContext.sessionId``.
    """
    if source is None or isinstance(source, Mapping):
        return False
    session = getattr(source, "session", None)
    return session is not None and not isinstance(
        session, (str, bytes, bytearray, list, tuple, set, frozenset)
    )


def _read(source: Any, name: str) -> Any:
    """*name* off a mapping or an object, whichever *source* is."""
    if source is None or name in _NEVER_READ:
        return None
    if _looks_like_tool_context(source) and name in _ADK_GENERATED:
        return None
    if isinstance(source, Mapping):
        return source.get(name)
    return getattr(source, name, None)


def _state(source: Any) -> Any:
    """Application-owned ``state`` mapping, if *source* has one.

    On a ``ToolContext`` that is ``source.state``. On a bare mapping it
    is not consulted twice — the mapping itself is the source. The
    ``session`` object is never consulted.
    """
    if source is None:
        return None
    nested = _readable(_read(source, "state"))
    return nested


def _candidates(source: Any, prefix: str = "") -> list[tuple[Any, str]]:
    found: list[tuple[Any, str]] = []
    for names in _ID_SLOTS:
        for name in names:
            value = _read(source, name)
            if value is not None:
                found.append((value, f"{prefix}{name}"))
    return found


def _valid_id(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    try:
        return _validated(value)
    except (TypeError, ValueError):
        return None


def _first_valid_id(*values: Any) -> Optional[str]:
    for value in values:
        valid = _valid_id(value)
        if valid is not None:
            return valid
    return None


def google_adk_context(
    source: Any = None,
    *,
    correlation_id: Optional[str] = None,
    session_id: Optional[str] = None,
    conversation_id: Optional[str] = None,
    metadata: Optional[Metadata] = None,
) -> GoogleAdkContext:
    """Read a caller-owned correlation id from a Google ADK invocation.

    Preference order:

    1. Fields the integrator put on the object (or a bare mapping):
       ``correlationId`` / ``correlation_id``, then ``sessionId`` /
       ``session_id``, then ``conversationId`` / ``conversation_id``
    2. The same names on ``source.state`` (application-owned session
       state)
    3. ``correlation_id=`` / ``session_id=`` / ``conversation_id=``
       passed here
    4. The enclosing :func:`~arcjet.guard.arcjet_sequence`, if any

    ``trace_id`` is never read. An ADK-generated ``invocation_id`` is
    never read. ``toolContext.sessionId`` and ``session.id`` are never
    read — this function never walks into ``.session`` and never
    constructs a session. An invalid candidate is skipped, and so is a
    non-string one, so a valid alias behind it is still found. If
    nothing valid remains, ``correlation_id`` is ``None`` and the
    decision is uncorrelated rather than joined to a generated id
    nobody has.

    Args:
        source: A caller-owned mapping, ``ToolContext.state``, or
            ``None``. A ``ToolContext`` itself is accepted only so
            ``state`` can be read; its ``session`` is not.
        correlation_id: Caller-owned fallback, used only if *source*
            carries nothing valid.
        session_id: Same, for an id the application calls a session.
        conversation_id: Same, for an id the application calls a
            conversation.
        metadata: Merged over the session / conversation metadata
            derived from *source*.

    Returns:
        The correlation id and metadata to pass to ``guard()``.
    """
    envelope = _readable(source)
    state = _state(envelope)

    candidates = _candidates(envelope)
    if state is not None and state is not envelope:
        candidates += _candidates(state, prefix="state.")
    if correlation_id is not None:
        candidates.append((correlation_id, "correlation_id"))
    if session_id is not None:
        candidates.append((session_id, "session_id"))
    if conversation_id is not None:
        candidates.append((conversation_id, "conversation_id"))

    resolved: Optional[str] = None
    rejected: Optional[str] = None
    for value, label in candidates:
        valid = _valid_id(value)
        if valid is not None:
            resolved = valid
            break
        if isinstance(value, str):
            rejected = label

    if resolved is None:
        resolved = current_correlation_id()

    if rejected is not None and resolved is None:
        logger.warning(
            "arcjet: Google ADK %s rejected; no valid caller-owned "
            "correlation / session / conversation id, leaving the call "
            "uncorrelated",
            rejected,
        )

    derived: dict[str, Any] = {}
    session = _first_valid_id(
        _read(envelope, "session_id"),
        _read(envelope, "sessionId"),
        _read(state, "session_id"),
        _read(state, "sessionId"),
        session_id,
    )
    if session is not None:
        derived["google-adk.session"] = session
    conversation = _first_valid_id(
        _read(envelope, "conversation_id"),
        _read(envelope, "conversationId"),
        _read(state, "conversation_id"),
        _read(state, "conversationId"),
        conversation_id,
    )
    if conversation is not None:
        derived["google-adk.conversation"] = conversation

    merged: dict[str, Any] = {**derived}
    if metadata:
        merged.update(metadata)

    return GoogleAdkContext(correlation_id=resolved, metadata=merged or None)
