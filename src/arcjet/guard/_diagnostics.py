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

import logging
import time
from typing import Callable, Protocol

from arcjet._logging import logger as _default_logger

# ``AJ1000``-``AJ1999`` is the server-side registry and travels on the wire.
# ``AJ3000``+ is SDK-local, reported only here, and allocated append-only across
# every Arcjet SDK: a code means the same thing in all of them, so a new meaning
# takes a new number. ``AJ3005`` is retired — it briefly meant "no client is
# registered" in JavaScript and was withdrawn before release.

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

CLIENT_ALREADY_REGISTERED = "AJ3004"
"""A second client tried to register; the first one was kept."""

CLIENT_FLAVOR_MISMATCH = "AJ3007"
"""The registered client is sync/async the other way round from the call."""

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
    # Registration codes. Neither concerns an individual event.
    CLIENT_ALREADY_REGISTERED: (
        "An Arcjet client is already registered; the existing one was kept"
    ),
    CLIENT_FLAVOR_MISMATCH: (
        "The registered Arcjet client is the other of sync/async from this "
        "call; the call failed open"
    ),
}

_COALESCE_SECONDS = 60.0
"""How long a code stays quiet after being logged, while counts accumulate.

Capture is called on a request path, so a persistent problem — a full queue
under sustained load, an unreachable API — would otherwise emit one log line per
event and turn a best-effort telemetry drop into a logging incident.
"""


class Diagnose(Protocol):
    """Reports one local diagnostic.  Never raises.

    Deliberately call-only: the delivery drivers report drops and nothing more,
    so a bare function or a recording test double satisfies this. Draining is a
    separate capability — see :class:`CoalescingDiagnose`.
    """

    def __call__(self, code: str, count: int = 1) -> None: ...


class CoalescingDiagnose(Diagnose, Protocol):
    """A :class:`Diagnose` that holds counts back and can be asked to release."""

    def drain(self) -> None:
        """Emit any counts held back by coalescing.  Never raises."""


def create_diagnose(
    *,
    logger: logging.Logger | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    coalesce_seconds: float = _COALESCE_SECONDS,
) -> CoalescingDiagnose:
    """Build a coalescing diagnostics reporter.

    Each code is logged at most once per *coalesce_seconds*.  Counts arriving
    while a code is quiet accumulate and are reported by whichever comes first:
    the next line for that code, or :meth:`drain`, which ``flush()`` calls.

    That pairing matters. Coalescing alone under-reports a burst that stops:
    a thousand drops inside one window would log ``1`` and hold the rest for a
    successor that never comes. ``flush()`` draining the remainder is what makes
    the total honest for the shape the capture ADR recommends — capture during a
    request, flush at the end of it.

    A burst that ends with neither a later drop nor a ``flush()`` still
    under-reports. That is the residual cost of bounding log volume, and it is
    why the reported figure is a count of events, not a guarantee of the total.

    Args:
        logger: Where to report.  Defaults to the ``arcjet`` logger.
        monotonic: Clock used for the coalescing window.  Injectable so tests
            do not have to sleep.
        coalesce_seconds: Quiet period per code.  ``0`` logs every diagnostic.

    Returns:
        A callable taking ``(code, count)``, with a ``drain()`` attribute.
        Neither raises: a diagnostics sink is observational and must not break
        application control flow or the background delivery worker.
    """
    # Not lock-guarded. Concurrent reports can race to emit an extra line or
    # briefly double-count, which costs a duplicate log entry; taking a lock on
    # every dropped event would put contention on the request path to protect
    # nothing that matters.
    suppressed: dict[str, int] = {}
    last_logged: dict[str, float] = {}

    sink = logger if logger is not None else _default_logger

    def emit(code: str, count: int) -> None:
        sink.warning(
            "arcjet %s: %s (%d event(s))",
            code,
            _MESSAGES.get(code, "Capture diagnostic"),
            count,
            extra={"event": "capture_diagnostic", "code": code, "count": count},
        )

    def diagnose(code: str, count: int = 1) -> None:
        try:
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
            emit(code, pending)
        except Exception:
            # Including a logging handler that raises.
            pass

    def drain() -> None:
        """Report every count still held back, ignoring the quiet period."""
        try:
            while suppressed:
                code, count = suppressed.popitem()
                if count:
                    last_logged[code] = monotonic()
                    emit(code, count)
        except Exception:
            pass

    diagnose.drain = drain  # type: ignore[attr-defined]  # matches the Diagnose protocol
    return diagnose  # type: ignore[return-value]  # drain attached above
