"""Local diagnostics for problems that cannot travel over the wire.

Most SDK-side validation problems reach you as ``decision.warnings``: the SDK
reports them to the server in ``local_warnings`` and they come back attached to
the decision.  Capture has no such channel.  It is fire-and-forget, so an event
dropped before it was sent has no response to carry a warning back on — if we
do not report it locally, nobody ever finds out.

Diagnostics therefore go to the ``arcjet`` stdlib logger, which is silent by
default (a ``NullHandler``) and which applications already configure to control
Arcjet's output.  See :mod:`arcjet._logging`.

Messages are static text plus counts.  They never contain metadata values,
capture actions, credentials, headers, or request bodies — only the escaped and
length-bounded key names that :mod:`arcjet._metadata` already sanitizes.
"""

from __future__ import annotations

import time
from typing import Callable, Protocol

from arcjet._logging import logger

CAPTURE_INPUT_INVALID = "AJ3000"
"""A capture call's input could not be normalized; the event was dropped."""

CAPTURE_QUEUE_FULL = "AJ3001"
"""The send queue was full; the newest events were dropped."""

CAPTURE_SEND_FAILED = "AJ3002"
"""A batch send failed; its events were dropped without retry."""

CAPTURE_FLUSH_EXPIRED = "AJ3003"
"""A ``flush()`` deadline expired; the remaining events were dropped."""

OPTION_DROPPED = "AJ1001"
"""A field was rejected during validation and dropped."""

METADATA_ENCODE_FAILED = "AJ1017"
"""A metadata key could not be encoded and was dropped."""

_MESSAGES = {
    CAPTURE_INPUT_INVALID: "Capture input was invalid; the event was dropped",
    CAPTURE_QUEUE_FULL: "Capture queue is full; newest events were dropped",
    CAPTURE_SEND_FAILED: (
        "Capture batch send failed; events were dropped without retry"
    ),
    CAPTURE_FLUSH_EXPIRED: (
        "Capture flush deadline expired; remaining events were dropped"
    ),
    # Validation codes. On a guard() call these reach you as decision.warnings;
    # a capture() call has no response to carry them, so they come through here
    # as well. They are also still sent in the event's local_warnings.
    OPTION_DROPPED: "A capture field was invalid and was dropped",
    METADATA_ENCODE_FAILED: "Metadata keys could not be encoded and were dropped",
}

_COALESCE_SECONDS = 60.0
"""How long a code stays quiet after being logged, while counts accumulate.

Capture is called on a request path, so a persistent problem — a full queue
under sustained load, an unreachable API — would otherwise emit one log line per
event and turn a best-effort telemetry drop into a logging incident.  Counts are
accumulated while a code is quiet and reported with the next line, so the
volume is bounded without losing the total.
"""


class Diagnose(Protocol):
    """Reports one local diagnostic.  Never raises."""

    def __call__(self, code: str, count: int = 1) -> None: ...


def create_diagnose(
    *,
    monotonic: Callable[[], float] = time.monotonic,
    coalesce_seconds: float = _COALESCE_SECONDS,
) -> Diagnose:
    """Build a coalescing diagnostics reporter.

    Each code is logged at most once per *coalesce_seconds*.  Events dropped
    while a code is quiet are counted and included in the next line for that
    code, so the reported total is never short even though the line count is
    bounded.

    Args:
        monotonic: Clock used for the coalescing window.  Injectable so tests
            do not have to sleep.
        coalesce_seconds: Quiet period per code.  ``0`` logs every diagnostic.

    Returns:
        A callable taking ``(code, count)``.  It never raises: a diagnostics
        sink is observational and must not break application control flow or
        the background delivery worker.
    """
    # Not lock-guarded. Concurrent reports can race to emit an extra line or
    # briefly double-count, which costs a duplicate log entry; taking a lock on
    # every dropped event would put contention on the request path to protect
    # nothing that matters.
    suppressed: dict[str, int] = {}
    last_logged: dict[str, float] = {}

    def diagnose(code: str, count: int = 1) -> None:
        try:
            message = _MESSAGES.get(code, "Capture diagnostic")
            pending = suppressed.pop(code, 0) + count

            now = monotonic()
            previous = last_logged.get(code)
            if (
                coalesce_seconds > 0
                and previous is not None
                and now - previous < coalesce_seconds
            ):
                suppressed[code] = pending
                return

            last_logged[code] = now
            logger.warning(
                "arcjet %s: %s (%d event(s))",
                code,
                message,
                pending,
                extra={"event": "capture_diagnostic", "code": code, "count": pending},
            )
        except Exception:
            # Including a logging handler that raises.
            pass

    return diagnose
