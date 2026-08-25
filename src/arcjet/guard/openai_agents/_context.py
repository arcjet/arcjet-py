"""Caller-owned correlation for an OpenAI Agents run.

``RunContext`` / ``ToolContext`` have no session id of their own. The app
object passed to ``Runner.run(..., context=...)`` is where an integrator
puts one. This helper reads it. It never mints. It never reads ``trace_id``
(the SDK mints one when omitted). It never constructs
``OpenAIConversationsSession()`` just to ask it for an id.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Optional

from arcjet._logging import logger
from arcjet._metadata import Metadata

from .._context import _validated, current_correlation_id

#: Names read off the app context, in preference order. Each slot lists the
#: Python spelling first and the JS camelCase alias second, so a caller-owned
#: id is not dropped over spelling. Every name in a slot is offered as a
#: candidate, so a present-but-invalid one does not hide its alias.
_APP_ID_SLOTS: tuple[tuple[str, ...], ...] = (
    ("correlation_id", "correlationId"),
    ("session_id", "sessionId"),
    ("conversation_id", "conversationId"),
    ("group_id", "groupId"),
)

#: Envelope copies (a ``RunContext``-shaped object or run options), read after
#: the app object. Still caller-owned, still never minted.
_ENVELOPE_ID_SLOTS: tuple[tuple[str, ...], ...] = (
    ("conversation_id", "conversationId"),
    ("group_id", "groupId"),
    ("session_id", "sessionId"),
    ("correlation_id", "correlationId"),
)

#: Never read as correlation. The SDK mints a trace id when one is omitted, so
#: a Sequence joined on it is one nobody can look up.
_NEVER_READ = frozenset({"trace_id", "traceId"})


@dataclass(frozen=True, slots=True)
class OpenAIAgentsContext:
    """What :func:`openai_agents_context` derived.

    ``correlation_id`` is ``None`` when nothing valid was present — this
    helper never mints one.
    """

    correlation_id: Optional[str] = None
    metadata: Optional[Metadata] = None


def _readable(value: Any) -> Any:
    """*value* if named fields can be read off it, else ``None``.

    A string, bytes, or a plain sequence carries no named id, and treating one
    as a context source would read attributes off the wrong kind of object.
    """
    if value is None or isinstance(
        value, (str, bytes, bytearray, list, tuple, set, frozenset)
    ):
        return None
    return value


def _read(source: Any, name: str) -> Any:
    """*name* off a mapping or an object, whichever *source* is."""
    if source is None or name in _NEVER_READ:
        return None
    if isinstance(source, Mapping):
        return source.get(name)
    return getattr(source, name, None)


def _app_object(source: Any) -> Any:
    """The integrator-owned app object.

    On a ``RunContext`` / ``ToolContext`` / run-options envelope that is
    ``source.context``. On a bare app object it is the source itself.
    """
    if source is None:
        return None
    nested = _readable(_read(source, "context"))
    return nested if nested is not None else source


def _candidates(
    source: Any, slots: tuple[tuple[str, ...], ...], prefix: str = ""
) -> list[tuple[Any, str]]:
    found: list[tuple[Any, str]] = []
    for names in slots:
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


def _first_string(*values: Any) -> Optional[str]:
    for value in values:
        if isinstance(value, str) and value:
            return value
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

    1. Fields the integrator put on ``run_context.context`` (or a bare app
       object): ``correlation_id``, then ``session_id``, then
       ``conversation_id``, then ``group_id``
    2. The same names on the envelope itself (``RunContext`` / run options)
    3. ``correlation_id=`` / ``session_id=`` passed here
    4. The enclosing :func:`~arcjet.guard.arcjet_sequence`, if any

    ``trace_id`` is never read. An invalid candidate is skipped, and so is a
    non-string one, so a valid alias behind it is still found. If nothing
    valid remains, ``correlation_id`` is ``None`` and the decision is
    uncorrelated rather than joined to a generated id nobody has.

    This function never constructs a session and never resolves one's id.

    Args:
        source: A ``ToolContext`` / ``RunContext``, the app object itself, or
            a run-options mapping.
        correlation_id: Caller-owned fallback, used only if *source* carries
            nothing valid.
        session_id: Same, for an id the application calls a session.
        metadata: Merged over the session / conversation / group metadata
            derived from *source*.

    Returns:
        The correlation id and metadata to pass to ``guard()``.
    """
    envelope = _readable(source)
    app = _app_object(envelope)

    candidates = _candidates(app, _APP_ID_SLOTS, prefix="context.")
    # `app is envelope` for a bare app object, where the two would be the same
    # read twice.
    if envelope is not app:
        candidates += _candidates(envelope, _ENVELOPE_ID_SLOTS)
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
    session = _first_string(
        _read(app, "session_id"),
        _read(app, "sessionId"),
        _read(envelope, "session_id"),
        _read(envelope, "sessionId"),
        session_id,
    )
    if session is not None:
        derived["openai-agents.session"] = session
    conversation = _first_string(
        _read(app, "conversation_id"),
        _read(app, "conversationId"),
        _read(envelope, "conversation_id"),
        _read(envelope, "conversationId"),
    )
    if conversation is not None:
        derived["openai-agents.conversation"] = conversation
    group = _first_string(
        _read(app, "group_id"),
        _read(app, "groupId"),
        _read(envelope, "group_id"),
        _read(envelope, "groupId"),
    )
    if group is not None:
        derived["openai-agents.group"] = group

    merged: dict[str, Any] = {**derived}
    if metadata:
        merged.update(metadata)

    return OpenAIAgentsContext(correlation_id=resolved, metadata=merged or None)
