"""Ambient correlation context for Arcjet Sequences.

A Sequence is the joined trace of every decision and capture belonging to one
run.  Joining happens on ``site_id`` plus a correlation ID, so the correlation
ID has to reach every checkpoint along the way.  Threading it through as an
argument means every intermediate function grows a parameter it does not
otherwise care about, so it is carried ambiently instead.

Ambient, not global.  ``arcjet.guard._registry`` explains why *registration*
is a module global: each thread starts with a fresh context, so a value set
once at startup is invisible to a WSGI worker thread.  Correlation is the
opposite problem — it is set per run, on the path that will read it — which is
exactly what a :class:`~contextvars.ContextVar` is for.

Propagation is not universal, and the gaps are documented rather than papered
over.  A value set here is visible inside ``asyncio.create_task()`` and
``asyncio.to_thread()``.  It is **not** visible inside a bare
``ThreadPoolExecutor.submit()``, ``loop.run_in_executor()``, or across a task
broker; for those, read the ID out with :func:`current_correlation_id`, carry
it yourself, and reopen :func:`arcjet_sequence` on the far side.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator, Optional

from arcjet._ids import new_correlation_id
from arcjet._metadata import Metadata

__all__ = [
    "arcjet_sequence",
    "current_correlation_id",
    "current_sequence_metadata",
]

MAX_CORRELATION_ID_BYTES = 256
"""Server-side bound on a correlation ID, matched here so an over-long value
fails loudly at the call site instead of being silently dropped on the wire."""

_correlation_id: ContextVar[Optional[str]] = ContextVar(
    "arcjet_correlation_id", default=None
)
_sequence_metadata: ContextVar[Optional[Metadata]] = ContextVar(
    "arcjet_sequence_metadata", default=None
)


def _validated(correlation_id: str) -> str:
    """Return *correlation_id* if the server will accept it, else raise.

    Rejecting beats truncating.  A truncated ID still looks like an ID and
    still joins *something* — just the wrong Sequence, silently, and only in
    the runs whose IDs happened to be long.
    """
    if not isinstance(correlation_id, str):
        raise TypeError(
            f"correlation_id must be a str, got {type(correlation_id).__name__}"
        )
    if not correlation_id:
        raise ValueError("correlation_id must not be empty")
    if not correlation_id.isascii() or not correlation_id.isprintable():
        raise ValueError(
            "correlation_id must be printable ASCII "
            "(no control characters, no non-ASCII)"
        )
    size = len(correlation_id.encode("utf-8"))
    if size > MAX_CORRELATION_ID_BYTES:
        raise ValueError(
            f"correlation_id must be at most {MAX_CORRELATION_ID_BYTES} bytes, "
            f"got {size}"
        )
    return correlation_id


@contextmanager
def arcjet_sequence(
    *,
    correlation_id: Optional[str] = None,
    metadata: Optional[Metadata] = None,
) -> Iterator[str]:
    """Scope a correlation ID over a block, yielding the active ID.

    Derive the ID from something the application already has — a session id, a
    thread id, a job id — so a Sequence lines up with the thing a human would
    go looking for.  Omit it and a sortable one is generated, which is the
    right answer only for a genuinely new entrypoint.

    Passing *metadata* attaches it to the block; passing ``None`` inherits
    whatever an enclosing block set rather than clearing it, so a nested block
    that only re-declares the ID does not drop the outer metadata.

    Restores the previous values on exit, including when the body raises.

    Args:
        correlation_id: The ID for this Sequence. Validated as at most 256
            bytes of printable ASCII.
        metadata: Optional metadata to associate with the block.

    Yields:
        The active correlation ID.

    Raises:
        TypeError: If *correlation_id* is given and is not a ``str``.
        ValueError: If *correlation_id* is empty, is not printable ASCII, or
            exceeds 256 bytes.

    Example:
        ::

            from arcjet.guard import arcjet_sequence

            with arcjet_sequence(correlation_id=session.id):
                await handle_request()
    """
    resolved = (
        new_correlation_id() if correlation_id is None else _validated(correlation_id)
    )

    # `Token` only becomes a context manager in Python 3.14; on the supported
    # 3.10 floor `try` / `finally` is the whole protocol.
    id_token = _correlation_id.set(resolved)
    metadata_token = None if metadata is None else _sequence_metadata.set(metadata)
    try:
        yield resolved
    finally:
        if metadata_token is not None:
            _sequence_metadata.reset(metadata_token)
        _correlation_id.reset(id_token)


def current_correlation_id() -> Optional[str]:
    """Return the correlation ID of the enclosing sequence, or ``None``.

    ``None`` is an ordinary state, not an error: code outside any sequence
    still evaluates policy, it just produces decisions that join no Sequence.
    """
    return _correlation_id.get()


def current_sequence_metadata() -> Optional[Metadata]:
    """Return the metadata of the enclosing sequence, or ``None``."""
    return _sequence_metadata.get()
