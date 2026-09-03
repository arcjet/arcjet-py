"""Caller-owned correlation for a Strands Agents run.

JS ``@arcjet/guard/strands-agents/v1`` reads ``invocationState.correlationId``
then ``sessionId`` then ``requestId``. This helper reads the same slots, with
snake_case aliases so a Python caller is not dropped over spelling. It never
mints. It never reads ``trace_id``. It never reads ``agent.id`` and never
constructs a ``SessionManager`` just to ask it for an id.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Optional

from arcjet._logging import logger
from arcjet._metadata import Metadata

from .._context import _validated, current_correlation_id

#: Names read off invocation state, in preference order. Each slot lists the
#: JS camelCase spelling first (the JS adapter's contract) and the Python
#: snake_case alias second. Every name in a slot is offered as a candidate,
#: so a present-but-invalid one does not hide its alias.
_ID_SLOTS: tuple[tuple[str, ...], ...] = (
    ("correlationId", "correlation_id"),
    ("sessionId", "session_id"),
    ("requestId", "request_id"),
)

#: Never read as correlation. The SDK / a tracer can mint a trace id when
#: one is omitted; joining a Sequence on it is one nobody can look up.
#: ``agent.id`` and SessionManager auto-ids are also never a source.
_NEVER_READ = frozenset(
    {
        "trace_id",
        "traceId",
        "agent_id",
        "agentId",
        "agent.id",
    }
)


@dataclass(frozen=True, slots=True)
class StrandsAgentContext:
    """What :func:`strands_agent_context` derived.

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


def _read(source: Any, name: str) -> Any:
    """*name* off a mapping or an object, whichever *source* is."""
    if source is None or name in _NEVER_READ:
        return None
    if isinstance(source, Mapping):
        return source.get(name)
    return getattr(source, name, None)


def _invocation_state(source: Any) -> Any:
    """The caller-owned invocation-state mapping, if *source* has one.

    On a ``BeforeToolCallEvent`` / ``AfterToolCallEvent`` that is
    ``source.invocation_state``. On a bare mapping it is the source itself.
    The agent object is never consulted.
    """
    if source is None:
        return None
    nested = _readable(_read(source, "invocation_state"))
    if nested is None:
        nested = _readable(_read(source, "invocationState"))
    if nested is not None:
        return nested
    return source if isinstance(source, Mapping) else None


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


def strands_agent_context(
    source: Any = None,
    *,
    correlation_id: Optional[str] = None,
    session_id: Optional[str] = None,
    request_id: Optional[str] = None,
    metadata: Optional[Metadata] = None,
) -> StrandsAgentContext:
    """Read a caller-owned correlation id from a Strands Agents invocation.

    Preference order:

    1. Fields the integrator put on ``invocation_state`` (or a bare mapping):
       ``correlationId`` / ``correlation_id``, then ``sessionId`` /
       ``session_id``, then ``requestId`` / ``request_id``
    2. The same names on the envelope itself (a hook event)
    3. ``correlation_id=`` / ``session_id=`` / ``request_id=`` passed here
    4. The enclosing :func:`~arcjet.guard.arcjet_sequence`, if any

    ``trace_id`` is never read. ``agent.id`` and SessionManager auto-ids are
    never read. An invalid candidate is skipped, and so is a non-string one,
    so a valid alias behind it is still found. If nothing valid remains,
    ``correlation_id`` is ``None`` and the decision is uncorrelated rather
    than joined to a generated id nobody has.

    This function never constructs a session and never resolves one's id.

    Args:
        source: A ``BeforeToolCallEvent`` / ``AfterToolCallEvent``, the
            ``invocation_state`` mapping, or ``None``.
        correlation_id: Caller-owned fallback, used only if *source* carries
            nothing valid.
        session_id: Same, for an id the application calls a session.
        request_id: Same, for an id the application calls a request.
        metadata: Merged over the session / request / tool metadata derived
            from *source*.

    Returns:
        The correlation id and metadata to pass to ``guard()``.
    """
    envelope = _readable(source)
    state = _invocation_state(envelope)

    candidates = _candidates(state, prefix="invocation_state.")
    if envelope is not state:
        candidates += _candidates(envelope)
    if correlation_id is not None:
        candidates.append((correlation_id, "correlation_id"))
    if session_id is not None:
        candidates.append((session_id, "session_id"))
    if request_id is not None:
        candidates.append((request_id, "request_id"))

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
            "arcjet: Strands Agents %s rejected; no valid caller-owned "
            "correlation / session / request id, leaving the call uncorrelated",
            rejected,
        )

    derived: dict[str, Any] = {}
    session = _first_valid_id(
        _read(state, "session_id"),
        _read(state, "sessionId"),
        _read(envelope, "session_id"),
        _read(envelope, "sessionId"),
        session_id,
    )
    if session is not None:
        derived["strands.session"] = session
    request = _first_valid_id(
        _read(state, "request_id"),
        _read(state, "requestId"),
        _read(envelope, "request_id"),
        _read(envelope, "requestId"),
        request_id,
    )
    if request is not None:
        derived["strands.request"] = request

    tool_use = _read(envelope, "tool_use") or _read(envelope, "toolUse")
    tool_name = None
    if isinstance(tool_use, Mapping):
        raw_name = tool_use.get("name")
        if isinstance(raw_name, str) and raw_name:
            tool_name = raw_name
    if tool_name is None:
        selected = _read(envelope, "selected_tool") or _read(envelope, "selectedTool")
        selected_name = getattr(selected, "tool_name", None)
        if isinstance(selected_name, str) and selected_name:
            tool_name = selected_name
    if tool_name is not None:
        derived["strands.tool"] = tool_name

    merged: dict[str, Any] = {**derived}
    if metadata:
        merged.update(metadata)

    return StrandsAgentContext(correlation_id=resolved, metadata=merged or None)
