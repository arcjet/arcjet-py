"""Caller-owned correlation for a Claude Managed Agents session.

Anthropic mints session ids (``ses_...``) and event ids (``sevt_...``).
This helper never treats those as ids we created. It reads a caller-owned
``correlation_id`` / ``session_id`` the application already has. It never
mints. It never reads ``trace_id``. It never reads ``id`` / ``event_id``
off an Anthropic session or event object.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Optional

from arcjet._logging import logger
from arcjet._metadata import Metadata

from .._context import _validated, current_correlation_id

#: Capture metadata key for the caller-owned session id. Reserved — adapters
#: re-apply it after user metadata so a caller cannot wipe or forge it.
SESSION_METADATA_KEY = "claude-managed-agents.session"

#: Names read off a caller-owned app object, in preference order. Each
#: slot lists the Python spelling first and the JS camelCase alias second.
#: Anthropic-minted ``id`` / ``event_id`` are not in this list.
_APP_ID_SLOTS: tuple[tuple[str, ...], ...] = (
    ("correlation_id", "correlationId"),
    ("session_id", "sessionId"),
)

#: Never read as correlation. The SDK / API mint a session and event id;
#: joining a Sequence on a generated id is one nobody can look up. ``id``
#: and ``event_id`` on an Anthropic object are theirs, not ours.
_NEVER_READ = frozenset(
    {
        "trace_id",
        "traceId",
        "id",
        "event_id",
        "eventId",
        "event_ids",
        "eventIds",
    }
)


@dataclass(frozen=True, slots=True)
class ClaudeManagedAgentsContext:
    """What :func:`claude_managed_agents_context` derived.

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


def _valid_id(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    try:
        return _validated(value)
    except (TypeError, ValueError):
        return None


def claude_managed_agents_context(
    source: Any = None,
    *,
    correlation_id: Optional[str] = None,
    session_id: Optional[str] = None,
    metadata: Optional[Metadata] = None,
) -> ClaudeManagedAgentsContext:
    """Read a caller-owned correlation id for a Managed Agents run.

    Preference order:

    1. Fields the integrator put on *source*: ``correlation_id``, then
       ``session_id`` (Python or JS camelCase)
    2. ``correlation_id=`` / ``session_id=`` passed here
    3. The enclosing :func:`~arcjet.guard.arcjet_sequence`, if any

    Anthropic session / event ``id`` values are never read. ``trace_id``
    is never read. An invalid candidate is skipped. If nothing valid
    remains, ``correlation_id`` is ``None`` and the decision is
    uncorrelated rather than joined to a generated id nobody has.

    This function never constructs a session and never resolves one's id.

    Args:
        source: A caller-owned mapping / object. An Anthropic Session or
            event object is safe to pass — ``id`` is ignored.
        correlation_id: Caller-owned fallback, used only if *source*
            carries nothing valid.
        session_id: Same, for an id the application calls a session. This
            is the application's id, not Anthropic's ``ses_...``.
        metadata: Merged over the session metadata derived from *source*.

    Returns:
        The correlation id and metadata to pass to ``guard()``.
    """
    envelope = _readable(source)

    candidates: list[tuple[Any, str]] = []
    if envelope is not None:
        for names in _APP_ID_SLOTS:
            for name in names:
                value = _read(envelope, name)
                if value is not None:
                    candidates.append((value, name))
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
            "arcjet: Claude Managed Agents %s rejected; no valid "
            "caller-owned correlation / session id, leaving the call "
            "uncorrelated",
            rejected,
        )

    derived: dict[str, Any] = {}
    owned_session = _valid_id(_read(envelope, "session_id")) or _valid_id(
        _read(envelope, "sessionId")
    )
    if owned_session is None:
        owned_session = _valid_id(session_id)
    if owned_session is not None:
        derived[SESSION_METADATA_KEY] = owned_session

    merged: dict[str, Any] = {**derived}
    if metadata:
        merged.update(metadata)

    return ClaudeManagedAgentsContext(correlation_id=resolved, metadata=merged or None)
