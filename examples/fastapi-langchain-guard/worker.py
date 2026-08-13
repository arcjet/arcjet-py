"""The far side of a background boundary.

Context does not cross a bare thread, a process, or a task broker, so this
worker is handed the correlation ID as ordinary data and reopens the sequence
from it. Everything it guards or captures then lands on the Sequence the
originating request started, instead of one of its own.

In production a broker — Celery, RQ, Dramatiq — calls this. It is a plain
synchronous function so the example runs without one.

It holds its own client rather than relying on the one ``main.py`` registered,
and that is the point worth copying: a worker runs blocking code, so it needs
the sync client. The registered client here is the async ``ArcjetGuard``, and a
synchronous checkpoint cannot await it — it would fail closed on every call
without ever reaching policy. A real Celery worker is a separate process that
would not share the registration at all.
"""

import logging
import os
from typing import Any, Mapping

from arcjet.guard import (
    ArcjetDeniedError,
    ArcjetUnavailableError,
    arcjet_sequence,
    capture_action,
    guard_action_sync,
    launch_arcjet_sync,
    security_metadata,
)

logger = logging.getLogger(__name__)

# One client per worker process, as a broker would have.
_client = launch_arcjet_sync(key=os.environ["ARCJET_KEY"])


def send_receipt(payload: Mapping[str, Any]) -> None:
    """Guard one outbound effect on the originating request's Sequence.

    Nothing is inherited here. Without the ``arcjet_sequence`` below, this
    worker's decision and capture would carry no correlation ID at all and the
    trace would split in half.
    """
    with arcjet_sequence(correlation_id=payload["correlation_id"]):
        try:
            # guard_action_sync wraps the effect rather than returning a
            # decision: it raises if policy denies, so the callable simply does
            # not run.
            guard_action_sync(
                lambda: _deliver(payload),
                action="receipt.sent",
                guard=_client,
                # No rules configured locally, which is still a real call: the
                # server selects remote policy by `action`.
                metadata=security_metadata(
                    user=str(payload["session_id"]),
                    destination="email",
                    reversibility="irreversible",
                ),
            )
        except ArcjetDeniedError:
            logger.warning("arcjet denied the receipt; not sending")
        except ArcjetUnavailableError:
            # The default is fail-closed, so an unevaluated policy stops the
            # send rather than letting an irreversible effect through unchecked.
            logger.error("arcjet policy unavailable; not sending")
        else:
            # Something the application did, recorded on the same Sequence.
            capture_action(action="receipt.recorded")
        finally:
            # A worker process exits between jobs, and capture queues rather
            # than blocking, so anything unflushed is lost.
            _client.flush()


def _deliver(payload: Mapping[str, Any]) -> None:
    """Stand in for the real outbound effect."""
    logger.info("delivering receipt for session %s", payload["session_id"])
