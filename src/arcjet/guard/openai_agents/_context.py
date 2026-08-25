"""Caller-owned correlation for an OpenAI Agents run.

``RunContext`` / ``ToolContext`` have no session id of their own. The app
object passed to ``Runner.run(..., context=...)`` is where an integrator
puts one. This helper reads it. It never mints. It never reads ``trace_id``
(the SDK mints one when omitted). It never constructs
``OpenAIConversationsSession()`` just to ask it for an id.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from arcjet._logging import logger
from arcjet._metadata import Metadata

from .._context import _validated, current_correlation_id

#: Fields on the app context, in preference order. Each slot accepts the
#: Python name first and the JS camelCase alias second, so a caller-owned id
#: is not dropped because of spelling.
_APP_ID_SLOTS: tuple[tuple[str, ...], ...] = (
    ("correlation_id", "correlationId"),
    ("session_id", "sessionId"),
    ("conversation_id", "conversationId"),
    ("group_id", "groupId"),
)

#: Envelope copies (a ``RunContext``-shaped object or run options) after the
#: app object, still caller-owned, still never minted.
_ENVELOPE_ID_SLOTS: tuple[tuple[str, ...], ...] = (
    ("conversation_id", "conversationId"),
    ("group_id", "groupId"),
    ("session_id", "sessionId"),
    ("correlation_id", "correlationId"),
)

_TRACE_NAMES = frozenset({"trace_id", "traceId"})


@dataclass(frozen=True, slots=True)
class OpenAIAgentsContext:
    """What :func:`openai_agents_context` derived. ``correlation_id`` is omitted
    when nothing valid was present — this helper never mints one.
    """

    correlation_id: Optional[str] = None
    metadata: Optional[Metadata] = None


def _as_mapping(value: Any) -> Optional[Any]:
    if value is None or not isinstance(value, object):
        return None
    if isinstance(value, (str, bytes, bytearray)):
        return None
    return value


def _read_attr(source: Any, name: str) -> Any:
    if source is None:
        return None
    if isinstance(source, dict):
        return source.get(name)
    return getattr(source, name, None)


def _app_object(source: Any) -> Any:
    """The integrator-owned app object.

    On a ``RunContext`` / ``ToolContext`` / run-options envelope that is
    ``source.context``. On a bare app object it is the source itself.
    """
    if source is None:
        return None
    nested = _read_attr(source, "context")
    if isinstance(nested, (str, bytes, bytearray, list, tuple)):
        return source
    if _as_mapping(nested) is not None:
        return nested
    return source


def _candidate_string(source: Any, names: tuple[str, ...]) -> tuple[Any, Optional[str]]:
    """The first present field among *names*, and the name it was found under."""
    if source is None:
        return None, None
    for name in names:
        if name in _TRACE_NAMES:
            continue
        value = _read_attr(source, name)
        if value is None:
            continue
        return value, name
    return None, None


def _valid_id(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    try:
        return _validated(value)
    except (TypeError, ValueError):
        return None


def openai_agents_context(
    source: Any = None,
    *,
    correlation_id: Optional[str] = None,
    session_id: Optional[str] = None,
    metadata: Optional[Metadata] = None,
) -> OpenAIAgentsContext:
    """Read a caller-owned correlation id from an OpenAI Agents run.

    Preference order:

    1. Fields the integrator put on ``runContext.context`` (or a bare app
       object): ``correlation_id``, then ``session_id``, then
       ``conversation_id``, then ``group_id``
    2. The same names on the envelope itself (run options / ``RunContext``)
    3. ``correlation_id=`` / ``session_id=`` passed here
    4. The enclosing :func:`~arcjet.guard.arcjet_sequence`, if any

    ``trace_id`` is never read. An invalid candidate is skipped. If nothing
    valid remains, ``correlation_id`` is ``None`` so the decision is
    uncorrelated rather than joined to a generated id nobody has.

    This function never constructs a session and never calls
    ``getSessionId()``.
    """
    envelope = _as_mapping(source)
    app = _app_object(envelope)

    candidates: list[tuple[Any, str]] = []
    for names in _APP_ID_SLOTS:
        value, label = _candidate_string(app, names)
        if label is not None:
            candidates.append((value, f"context.{label}"))
    for names in _ENVELOPE_ID_SLOTS:
        value, label = _candidate_string(envelope, names)
        if label is not None:
            candidates.append((value, label))
    if correlation_id is not None:
        candidates.append((correlation_id, "correlation_id"))
    if session_id is not None:
        candidates.append((session_id, "session_id"))

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
            "arcjet: OpenAI Agents %s rejected; no valid session / "
            "conversation / group id, leaving the call uncorrelated",
            rejected,
        )

    derived: dict[str, Any] = {}
    session = _first_valid_string(
        _read_attr(app, "session_id"),
        _read_attr(app, "sessionId"),
        _read_attr(envelope, "session_id"),
        _read_attr(envelope, "sessionId"),
        session_id,
    )
    if session is not None:
        derived["openai-agents.session"] = session
    conversation = _first_valid_string(
        _read_attr(app, "conversation_id"),
        _read_attr(app, "conversationId"),
        _read_attr(envelope, "conversation_id"),
        _read_attr(envelope, "conversationId"),
    )
    if conversation is not None:
        derived["openai-agents.conversation"] = conversation
    group = _first_valid_string(
        _read_attr(app, "group_id"),
        _read_attr(app, "groupId"),
        _read_attr(envelope, "group_id"),
        _read_attr(envelope, "groupId"),
    )
    if group is not None:
        derived["openai-agents.group"] = group

    merged: dict[str, Any] = {**derived}
    if metadata:
        merged.update(metadata)

    return OpenAIAgentsContext(
        correlation_id=resolved,
        metadata=merged or None,
    )


def _first_valid_string(*values: Any) -> Optional[str]:
    for value in values:
        if isinstance(value, str) and value:
            return value
    return None
