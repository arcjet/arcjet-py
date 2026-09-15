"""Seconds until a rate-limited call may be retried.

One rule, shared by every vendor module. It lived in four byte-identical
copies, which is four places for the answer the SDK promises to drift apart.
"""

from __future__ import annotations

import math
import time
from typing import Optional

from ._types import Decision

__all__ = ["MAX_RETRY_AFTER_SECONDS", "retry_after_seconds"]

MAX_RETRY_AFTER_SECONDS = 24 * 60 * 60
"""Upper bound on a retry hint.

A reset near the uint32 ceiling would otherwise yield a nonsensical wait here,
and a negative one on a 32-bit consumer.
"""


def retry_after_seconds(decision: Decision) -> Optional[int]:
    """Seconds until a rate-limited call may be retried, or ``None``.

    Only meaningful for a ``RATE_LIMIT`` denial; the reason check stays with
    the caller. Among the results, only rules that denied are considered, and
    the latest reset among them is reported — that is when the call would
    actually be permitted, whereas the earliest invites a retry that the longer
    rule denies again.
    """
    latest: Optional[int] = None

    for result in decision.results:
        if getattr(result, "conclusion", None) != "DENY":
            continue
        if getattr(result, "reason", None) != "RATE_LIMIT":
            continue

        reset = getattr(result, "reset_at_unix_seconds", None)
        if not isinstance(reset, int):
            continue
        # Zero is proto3's default for an omitted field, not a reset in 1970.
        # Treating it as real would tell the model to retry immediately.
        if reset <= 0:
            continue

        if latest is None or reset > latest:
            latest = reset

    if latest is None:
        return None

    return min(max(0, math.ceil(latest - time.time())), MAX_RETRY_AFTER_SECONDS)
