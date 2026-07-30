"""Normalization for ``capture()`` calls.

``capture()`` records something an application did, for visibility only.  It
never affects a decision and never raises, so everything here is written to
degrade rather than fail: a bad optional field costs you that field, a bad
``action`` costs you the event, and neither costs you the call.

Problems are reported through :mod:`arcjet.guard._diagnostics` (locally, via the
``arcjet`` logger) and in the event's own ``local_warnings`` (to the server, so
they are visible alongside the stored event).
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Mapping

from arcjet._metadata import (
    LocalWarning,
    encode_metadata,
    enforce_metadata_budget,
)

from ._convert import local_warnings_to_proto
from ._diagnostics import CAPTURE_INPUT_INVALID, Diagnose
from .proto.decide.v2 import decide_pb2 as pb

CAPTURE_SOURCE_SDK = "sdk"
"""``source`` for an event from an explicit ``capture()`` call.

The producer decides this, not the caller, which is why it is not an argument.
A future span-conversion path sets ``"otlp"`` instead.  The server never
substitutes a default — it stores an absent ``source`` as NULL, meaning
unknown — so sending nothing would leave the origin unknown rather than merely
unstated.
"""

CAPTURE_OPTION_DROPPED_CODE = "AJ1001"
"""Warning code for a capture field that was dropped during normalization.

Shared with arcjet-js, which reports the same condition under the same code, so
a support answer about ``AJ1001`` holds for either SDK.  Note this is an
``AJ1xxx`` validation code, not one of the ``AJ30xx`` capture-delivery codes:
the field was rejected before delivery was involved.
"""


def _option_dropped(name: str) -> LocalWarning:
    # Message text matches arcjet-js so the two SDKs render this identically.
    return LocalWarning(
        code=CAPTURE_OPTION_DROPPED_CODE,
        message=f"capture.{name} was invalid and was dropped by the SDK",
    )


def normalize_capture_event(
    *,
    action: object,
    correlation_id: object = None,
    decision_id: object = None,
    occurred_at: object = None,
    metadata: object = None,
    diagnose: Diagnose,
) -> pb.CaptureEvent | None:
    """Build a wire ``CaptureEvent``, or ``None`` if the event must be dropped.

    Arguments are typed ``object`` on purpose.  Python has no runtime type
    enforcement, so a caller who ignores the type hints — or passes a value
    through from user input — reaches this function with anything at all.  Each
    field is validated independently so one bad optional value drops only
    itself.

    Only an unusable ``action`` drops the whole event, because an event that
    does not say what happened records nothing.

    Args:
        action: What the application did, e.g. ``"refund.issued"``.  Required;
            must be a non-empty string.
        correlation_id: Optional identifier tying this event to other
            ``guard()``/``capture()`` calls in the same workflow.
        decision_id: Optional id of a decision this event relates to.
        occurred_at: Optional :class:`~datetime.datetime` of when it happened.
            Defaults to now.  A naive datetime is interpreted as local time,
            matching :meth:`datetime.datetime.timestamp`.
        metadata: Optional nested-JSON metadata.
        diagnose: Local diagnostics sink.

    Returns:
        The proto event, or ``None`` when it could not be built.
    """
    try:
        if not isinstance(action, str) or not action:
            diagnose(CAPTURE_INPUT_INVALID)
            return None

        warnings: list[LocalWarning] = []

        correlation = _optional_str(correlation_id, "correlation_id", warnings)
        decision = _optional_str(decision_id, "decision_id", warnings)
        occurred_at_unix_ms = _occurred_at_unix_ms(occurred_at, warnings)

        encoded: dict[str, str] = {}
        if isinstance(metadata, Mapping):
            encoded, metadata_warnings = encode_metadata(
                metadata,  # type: ignore[arg-type]  # narrowed to Mapping above
                message_prefix="capture: ",
            )
            warnings.extend(metadata_warnings)
        elif metadata is not None:
            warnings.append(_option_dropped("metadata"))

        warnings.extend(enforce_metadata_budget([encoded]))

        for warning in warnings:
            diagnose(warning.code)

        return pb.CaptureEvent(
            occurred_at_unix_ms=occurred_at_unix_ms,
            correlation_id=correlation,
            decision_id=decision,
            action=action,
            metadata_json=encoded,
            local_warnings=local_warnings_to_proto(warnings),
            source=CAPTURE_SOURCE_SDK,
        )
    except Exception:
        # Normalization touches user-supplied objects, whose __iter__,
        # __getitem__, or __str__ is user code that can raise anything.
        diagnose(CAPTURE_INPUT_INVALID)
        return None


def _optional_str(value: object, name: str, warnings: list[LocalWarning]) -> str:
    """Keep a string field, or drop it with a warning.

    Absent is not the same as wrong: ``None`` means the caller did not set the
    field, so it produces no warning.  Anything else that is not a string was
    meant to be a value and failed, so it is reported.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    warnings.append(_option_dropped(name))
    return ""


def _occurred_at_unix_ms(value: object, warnings: list[LocalWarning]) -> int:
    """Resolve ``occurred_at`` to unsigned milliseconds since the epoch.

    Pre-epoch timestamps are rejected because the wire field is unsigned: a
    negative millisecond value cannot be represented and would wrap to an
    enormous timestamp.  Dropping the field and warning beats sending a wrong
    one.
    """
    if value is None:
        return int(time.time() * 1000)

    if not isinstance(value, datetime):
        warnings.append(_option_dropped("occurred_at"))
        return int(time.time() * 1000)

    try:
        # A naive datetime has no offset, so `timestamp()` reads it as local
        # time. That matches the stdlib and is what a caller who built one with
        # `datetime.now()` means.
        seconds = value.timestamp()
    except (OverflowError, OSError, ValueError):
        # Out of range for the platform's time functions.
        warnings.append(_option_dropped("occurred_at"))
        return int(time.time() * 1000)

    millis = int(seconds * 1000)
    if millis < 0:
        warnings.append(_option_dropped("occurred_at"))
        return int(time.time() * 1000)
    return millis


def build_capture_request(
    events: list[pb.CaptureEvent], *, user_agent: str
) -> pb.CaptureRequest:
    """Wrap one batch of events in a ``CaptureRequest``."""
    return pb.CaptureRequest(
        user_agent=user_agent,
        sent_at_unix_ms=int(time.time() * 1000),
        events=events,
    )
