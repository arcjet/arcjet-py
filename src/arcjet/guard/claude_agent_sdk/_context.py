"""Caller-owned correlation for a Claude Agent SDK run.

Hook input carries ``session_id``. ``ClaudeAgentOptions.session_id`` must be
a UUID the application already minted — the CLI exits on anything else, and
reusing a session id on a second ``query()`` exits with "already in use".
This helper reads that id. It never mints. It never reads ``trace_id``.
It never constructs a session just to ask it for an id.

An authored ``SdkMcpTool.handler`` has no ``extra.session_id``. Pass the
same caller-owned UUID as ``session_id=`` on :func:`guard_tool` /
:func:`guard_hooks`.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Optional

from arcjet._logging import logger
from arcjet._metadata import Metadata

from .._context import _validated, current_correlation_id

#: Never read as correlation. The SDK / CLI can mint a session when one is
#: omitted; joining a Sequence on a generated id is one nobody can look up.
_NEVER_READ = frozenset({"trace_id", "traceId"})


@dataclass(frozen=True, slots=True)
class ClaudeAgentContext:
    """What :func:`claude_agent_context` derived.

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


def _valid_session_id(value: Any) -> Optional[str]:
    """A caller-owned UUID the CLI will accept as ``session_id``.

    Anything else is skipped, not minted. Used when reading hook input,
    which may carry garbage; wrap-time arguments use
    :func:`_require_session_id` so a non-UUID is refused instead of
    accepted and then dropped here.
    """
    if not isinstance(value, str):
        return None
    try:
        return _require_session_id(value)
    except (TypeError, ValueError):
        return None


def _require_session_id(value: str) -> str:
    """Raise unless *value* is a caller-owned UUID the CLI will accept.

    Wrap-time counterpart of :func:`_valid_session_id`. ``_validated``
    accepts any printable-ASCII Sequence id; the Claude CLI additionally
    requires a UUID for ``ClaudeAgentOptions.session_id``. Refusing here
    keeps ``guard_tool(..., correlation_id="run-abc")`` from succeeding
    and then leaving the call uncorrelated.
    """
    validated = _validated(value)
    try:
        uuid.UUID(validated)
    except ValueError as exc:
        raise ValueError(
            "session_id must be a UUID the Claude Agent SDK will accept "
            "(the same value you pass to ClaudeAgentOptions.session_id); "
            f"got {value!r}"
        ) from exc
    return validated


def claude_agent_context(
    source: Any = None,
    *,
    session_id: Optional[str] = None,
    metadata: Optional[Metadata] = None,
) -> ClaudeAgentContext:
    """Read a caller-owned session UUID from a Claude Agent SDK hook.

    Preference order:

    1. ``session_id`` on hook input (or a mapping / object that looks like
       one)
    2. ``session_id=`` passed here — the policy fallback an authored
       handler needs, because it has no ``extra.session_id``
    3. The enclosing :func:`~arcjet.guard.arcjet_sequence`, if any

    ``trace_id`` is never read. A non-UUID or otherwise invalid candidate
    is skipped. If nothing valid remains, ``correlation_id`` is ``None``
    and the decision is uncorrelated rather than joined to a generated id
    nobody has.

    Subagent ``agent_id`` is recorded as ``claude.agent`` metadata only.

    Args:
        source: A hook input mapping (``session_id``, optional
            ``agent_id`` / ``tool_name``), or ``None``.
        session_id: Caller-owned UUID fallback, used only if *source*
            carries nothing valid.
        metadata: Merged over the session / tool / agent metadata derived
            from *source*.

    Returns:
        The correlation id and metadata to pass to ``guard()``.
    """
    envelope = _readable(source)

    candidates: list[tuple[Any, str]] = []
    hook_session = _read(envelope, "session_id")
    if hook_session is None:
        hook_session = _read(envelope, "sessionId")
    if hook_session is not None:
        candidates.append((hook_session, "session_id"))
    if session_id is not None:
        candidates.append((session_id, "session_id"))

    resolved: Optional[str] = None
    rejected: Optional[str] = None
    for value, label in candidates:
        valid = _valid_session_id(value)
        if valid is not None:
            resolved = valid
            break
        if isinstance(value, str):
            rejected = label

    if resolved is None:
        resolved = current_correlation_id()

    if rejected is not None and resolved is None:
        logger.warning(
            "arcjet: Claude Agent SDK %s rejected; no valid caller-owned "
            "UUID session_id, leaving the call uncorrelated",
            rejected,
        )

    derived: dict[str, Any] = {}
    session = _valid_session_id(hook_session) or _valid_session_id(session_id)
    if session is not None:
        derived["claude.session"] = session
    tool_name = _read(envelope, "tool_name")
    if isinstance(tool_name, str) and tool_name:
        derived["claude.tool"] = tool_name
    agent_id = _read(envelope, "agent_id")
    if agent_id is None:
        agent_id = _read(envelope, "agentId")
    if isinstance(agent_id, str) and agent_id:
        derived["claude.agent"] = agent_id

    merged: dict[str, Any] = {**derived}
    if metadata:
        merged.update(metadata)

    return ClaudeAgentContext(correlation_id=resolved, metadata=merged or None)
