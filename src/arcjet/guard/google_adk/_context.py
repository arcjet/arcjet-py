"""Caller-owned correlation for a Google ADK run.

JS ``@arcjet/guard/google-adk/v2`` ``googleAdkContext`` reads a caller-owned
id from helper options or a bag the integrator put on the run. This helper
reads the same slots, with snake_case aliases so a Python caller is not
dropped over spelling. It never mints. It never reads ``trace_id``. It
never reads an ADK-generated ``invocation_id``. It never reads
``toolContext.session_id`` or ``session.id``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Optional

from arcjet._logging import logger
from arcjet._metadata import Metadata

from .._context import _validated, current_correlation_id

#: Names read off a caller-owned bag, in preference order. Each slot lists
#: the JS camelCase spelling first (the JS adapter's contract) and the
#: Python snake_case alias second. Every name in a slot is offered as a
#: candidate, so a present-but-invalid one does not hide its alias.
_ID_SLOTS: tuple[tuple[str, ...], ...] = (
    ("correlationId", "correlation_id"),
    ("sessionId", "session_id"),
    ("conversationId", "conversation_id"),
)

#: Never read as correlation. ADK always generates ``invocationId``. The
#: SDK / a tracer can mint a trace id when one is omitted. ``functionCallId``
#: is per-call. ``toolContext.sessionId`` / ``session.id`` can be
#: session-service auto-ids.
_NEVER_READ = frozenset(
    {
        "trace_id",
        "traceId",
        "invocation_id",
        "invocationId",
        "function_call_id",
        "functionCallId",
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


def _read(source: Any, name: str) -> Any:
    """*name* off a mapping or an object, whichever *source* is."""
    if source is None or name in _NEVER_READ:
        return None
    if isinstance(source, Mapping):
        return source.get(name)
    return getattr(source, name, None)


def _raw_get(source: Any, name: str) -> Any:
    """Read *name* even when it is in ``_NEVER_READ`` (envelope detection)."""
    if source is None:
        return None
    if isinstance(source, Mapping):
        return source.get(name)
    return getattr(source, name, None)


def _is_adk_context_envelope(source: Any) -> bool:
    """ADK ``Context`` / ``ToolContext`` always carries ``invocationId``.

    An envelope that looks like one must not be mined for ``sessionId`` —
    that field is the session-service id and can be ephemeral. JS
    ``isAdkContextEnvelope`` is the same rule. ``invocationId`` is in
    ``_NEVER_READ``, so this uses a raw get.
    """
    invocation = _raw_get(source, "invocationId")
    if invocation is None:
        invocation = _raw_get(source, "invocation_id")
    return isinstance(invocation, str) and bool(invocation)


def _as_record(value: Any) -> Optional[dict[str, Any]]:
    if value is None or isinstance(value, (str, bytes, bytearray, list, tuple)):
        return None
    if isinstance(value, Mapping):
        return dict(value)
    return None


def _read_state_bag(state: Any) -> Optional[dict[str, Any]]:
    """Session ``state`` as a mapping. ``toRecord()`` / ``get()`` / object."""
    if state is None or isinstance(state, (str, bytes, bytearray, list, tuple)):
        return None
    to_record = getattr(state, "toRecord", None)
    if to_record is None:
        to_record = getattr(state, "to_record", None)
    if callable(to_record):
        return _as_record(to_record())
    getter = getattr(state, "get", None)
    if callable(getter) and not isinstance(state, Mapping):
        bag: dict[str, Any] = {}
        for names in _ID_SLOTS:
            for name in names:
                value = getter(name)
                if value is not None:
                    bag[name] = value
        return bag or None
    if isinstance(state, Mapping):
        return dict(state)
    readable = _readable(state)
    if readable is None:
        return None
    bag = {}
    for names in _ID_SLOTS:
        for name in names:
            value = _read(readable, name)
            if value is not None:
                bag[name] = value
    return bag or None


def _app_context(source: Any) -> Any:
    """The integrator-owned app object.

    On a wrap ``{context: appContext}`` that is ``source.context``. ADK
    ``Context`` / ``toolContext`` has no such field — an envelope with
    ``invocationId`` is not mined as an app object.
    """
    if source is None:
        return None
    nested = _readable(_read(source, "context"))
    if nested is not None:
        return nested
    if _is_adk_context_envelope(source):
        return None
    return source


def _candidates_from(source: Any, prefix: str = "") -> list[tuple[Any, str]]:
    found: list[tuple[Any, str]] = []
    if source is None:
        return found
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
    metadata: Optional[Metadata] = None,
) -> GoogleAdkContext:
    """Read a caller-owned correlation id from a Google ADK invocation.

    Preference order:

    1. Fields the integrator put on a caller-owned wrap
       (``google_adk_context({"context": app_context})``):
       ``correlationId`` / ``correlation_id``, then ``sessionId`` /
       ``session_id``, then ``conversationId`` / ``conversation_id``.
       ADK ``Context`` / ``toolContext`` has no such ``context`` field.
    2. ``correlation_id=`` / ``session_id=`` passed here (helper options /
       ``guard_plugin(session_id=...)``). This wins over durable session
       ``state``.
    3. The same keys on session ``state`` (``toRecord()`` / ``get()`` /
       object)
    4. Documented copies on a bare app object (not an ADK Context envelope)
    5. The enclosing :func:`~arcjet.guard.arcjet_sequence`, if any

    ``trace_id`` is never read. ``invocation_id`` is never read (ADK
    always generates it). ``function_call_id`` is never read.
    ``toolContext.session_id`` / ``session.id`` are never read — those
    can be ephemeral / session-service auto-ids. An invalid candidate is
    skipped, and so is a non-string one, so a valid alias behind it is
    still found. If nothing valid remains, ``correlation_id`` is ``None``
    and the decision is uncorrelated rather than joined to a generated
    id nobody has.

    This function never constructs a session and never resolves one's id.

    Args:
        source: A ``ToolContext`` envelope, a ``{context: app}`` wrap,
            session ``state``, a bare app object, or ``None``.
        correlation_id: Caller-owned fallback, used only if *source*
            carries nothing valid in a higher-preference slot.
        session_id: Same, for an id the application calls a session.
        metadata: Merged over the session / conversation metadata
            derived from *source*.

    Returns:
        The correlation id and metadata to pass to ``guard()``.
    """
    envelope = _readable(source)
    app = _app_context(envelope)
    state = _read_state_bag(_read(envelope, "state") if envelope is not None else None)
    envelope_is_adk = envelope is not None and _is_adk_context_envelope(envelope)

    candidates: list[tuple[Any, str]] = []
    candidates += _candidates_from(app, prefix="context.")
    if correlation_id is not None:
        candidates.append((correlation_id, "correlation_id"))
    if session_id is not None:
        candidates.append((session_id, "session_id"))
    candidates += _candidates_from(state, prefix="state.")
    if envelope is not None and envelope is not app and not envelope_is_adk:
        candidates += _candidates_from(envelope)

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
        _read(app, "session_id"),
        _read(app, "sessionId"),
        session_id,
        _read(state, "session_id") if state else None,
        _read(state, "sessionId") if state else None,
        None
        if envelope_is_adk
        else _first_valid_id(
            _read(envelope, "session_id"),
            _read(envelope, "sessionId"),
        ),
    )
    if session is not None:
        derived["google-adk.session"] = session
    conversation = _first_valid_id(
        _read(app, "conversation_id"),
        _read(app, "conversationId"),
        _read(state, "conversation_id") if state else None,
        _read(state, "conversationId") if state else None,
        None
        if envelope_is_adk
        else _first_valid_id(
            _read(envelope, "conversation_id"),
            _read(envelope, "conversationId"),
        ),
    )
    if conversation is not None:
        derived["google-adk.conversation"] = conversation

    merged: dict[str, Any] = {**derived}
    if metadata:
        merged.update(metadata)

    return GoogleAdkContext(correlation_id=resolved, metadata=merged or None)
