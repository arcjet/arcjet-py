"""Bounded, send-once delivery for capture events.

Capture is best-effort telemetry on a request path, which fixes the shape of
this code:

* **Bounded.**  The queue has a ceiling and drops when full.  Making the caller
  wait is not an option — ``capture()`` runs inside someone else's application,
  so blocking for space would turn our telemetry into their latency.
* **Batched.**  An event waits briefly for company, so a burst of calls costs one
  request instead of one each.
* **Send-once.**  A failed batch is dropped, never retried.  Retries pile work
  onto a backend that is already struggling, and a stale visibility event is
  worth less than the capacity a retry would consume.
* **Never process-holding.**  The sync worker is a daemon thread, so a queued
  event cannot keep an application alive at exit.  Call :meth:`flush` when you
  need delivery before shutting down.

Every drop is reported through :mod:`arcjet.guard._diagnostics`; nothing is
discarded silently.

There are two drivers because arcjet-py has two clients.  The sync client gets a
worker thread and the async client an ``asyncio`` task, so each uses its own
transport and neither pays for the other's machinery.
"""

from __future__ import annotations

import asyncio
import queue
import threading
import time
from collections import deque
from typing import Awaitable, Deque, Protocol

from ._diagnostics import (
    CAPTURE_FLUSH_EXPIRED,
    CAPTURE_QUEUE_FULL,
    CAPTURE_SEND_FAILED,
    Diagnose,
)
from .proto.decide.v2 import decide_pb2 as pb

DEFAULT_QUEUE_SIZE = 1000
"""Most events held in memory, queued and in flight together."""

DEFAULT_BATCH_SIZE = 50
"""Most events in one Capture request."""

DEFAULT_BATCH_DELAY_MS = 100
"""Longest an event waits for a batch to fill before being sent on its own."""

DEFAULT_FLUSH_TIMEOUT_MS = 1000
"""Default :meth:`flush` deadline."""

_IDLE_WAIT_SECONDS = 0.5
"""How long a worker sits idle before it stops.

The worker exits when nothing arrives so an application that captures rarely is
not left holding a thread or a loop task.  The next event starts a new one.
"""


class _SendSync(Protocol):
    def __call__(self, events: list[pb.CaptureEvent]) -> None: ...


class _SendAsync(Protocol):
    def __call__(self, events: list[pb.CaptureEvent]) -> Awaitable[None]: ...


def _positive_int(value: object, fallback: int) -> int:
    """Accept a positive int, else fall back.  ``bool`` is not an int here."""
    if isinstance(value, bool) or not isinstance(value, int):
        return fallback
    return value if value > 0 else fallback


def _nonnegative_int(value: object, fallback: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return fallback
    return value if value >= 0 else fallback


class SyncCaptureDelivery:
    """Bounded batched delivery on a daemon worker thread.

    Args:
        send: Sends one batch exactly once.  May raise, in which case the batch
            is dropped and reported.
        diagnose: Local diagnostics sink.
        queue_size: Ceiling on queued plus in-flight events.
        batch_size: Most events per request.
        batch_delay_ms: How long a partial batch waits before being sent.
    """

    def __init__(
        self,
        *,
        send: _SendSync,
        diagnose: Diagnose,
        queue_size: int = DEFAULT_QUEUE_SIZE,
        batch_size: int = DEFAULT_BATCH_SIZE,
        batch_delay_ms: int = DEFAULT_BATCH_DELAY_MS,
    ) -> None:
        self._send = send
        self._diagnose = diagnose
        self._batch_size = _positive_int(batch_size, DEFAULT_BATCH_SIZE)
        delay_ms = _nonnegative_int(batch_delay_ms, DEFAULT_BATCH_DELAY_MS)
        self._batch_delay = delay_ms / 1000

        self._queue_size = _positive_int(queue_size, DEFAULT_QUEUE_SIZE)
        # The queue handles the batching timers via get(timeout=...). Admission
        # is decided against `_outstanding` below, not against maxsize, so the
        # ceiling covers in-flight events too.
        self._queue: queue.Queue[pb.CaptureEvent] = queue.Queue(
            maxsize=self._queue_size
        )
        # Outstanding = accepted but not yet sent or dropped, so queued plus
        # in flight. This is what the ceiling applies to: a batch already on the
        # wire still occupies memory, and a slow backend must show up as drops
        # rather than unbounded growth.
        self._outstanding = 0
        self._idle = threading.Condition()
        # Set while a flush() is waiting, so a partial batch is sent at once
        # instead of sitting out its full delay.
        self._flush_now = threading.Event()
        self._worker_lock = threading.Lock()
        self._worker: threading.Thread | None = None

    def capture(self, event: pb.CaptureEvent) -> None:
        """Enqueue one event without blocking the caller."""
        with self._idle:
            if self._outstanding >= self._queue_size:
                self._diagnose(CAPTURE_QUEUE_FULL, 1)
                return
            # Reserved before the put so two concurrent callers cannot both pass
            # the check and overshoot the ceiling.
            self._outstanding += 1
        # The put happens outside the condition, deliberately: reserve → put →
        # send. For a brief window `_outstanding` counts an event that is not yet
        # in the queue, which is the safe direction to be wrong — flush() waits
        # for `_outstanding == 0`, so it conservatively waits for an event that is
        # still on its way in. Reversing the order, or holding the lock across
        # the put, would either undercount for flush() or put lock traffic on the
        # caller's request path.
        try:
            self._queue.put_nowait(event)
        except queue.Full:  # pragma: no cover - _outstanding bounds this first
            self._finish(1)
            self._diagnose(CAPTURE_QUEUE_FULL, 1)
            return
        self._ensure_worker()

    def flush(self, timeout_ms: int | None = None) -> None:
        """Drain queued and in-flight events, dropping whatever does not fit.

        Args:
            timeout_ms: Deadline in milliseconds.  On expiry the queued
                remainder is dropped and reported as ``AJ3003``.

        A request already on the wire is not cancelled on expiry — the sync
        transport exposes no cancellation handle — so this clears the queue and
        leaves that request to finish or time out on its own.
        """
        deadline = _nonnegative_int(timeout_ms, DEFAULT_FLUSH_TIMEOUT_MS) / 1000
        with self._idle:
            if self._outstanding == 0:
                return
        self._ensure_worker()
        self._flush_now.set()
        try:
            with self._idle:
                drained = self._idle.wait_for(
                    lambda: self._outstanding == 0, timeout=deadline
                )
            if drained:
                return
            self._drop_queued()
        finally:
            self._flush_now.clear()

    def _drop_queued(self) -> None:
        """Discard everything still queued and report it once."""
        dropped = 0
        while True:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                break
            dropped += 1
        if dropped:
            self._finish(dropped)
            self._diagnose(CAPTURE_FLUSH_EXPIRED, dropped)

    def _finish(self, count: int) -> None:
        """Mark *count* events as no longer outstanding and wake any flush."""
        with self._idle:
            self._outstanding -= count
            if self._outstanding <= 0:
                self._outstanding = 0
                self._idle.notify_all()

    def _ensure_worker(self) -> None:
        with self._worker_lock:
            if self._worker is not None and self._worker.is_alive():
                return
            # A daemon thread cannot keep the interpreter alive at exit, which
            # is what stops a queued best-effort event from delaying shutdown.
            self._worker = threading.Thread(
                target=self._run, name="arcjet-capture", daemon=True
            )
            self._worker.start()

    def _drain_available(self, limit: int) -> list[pb.CaptureEvent]:
        """Take up to *limit* events that are already queued, without waiting."""
        taken: list[pb.CaptureEvent] = []
        while len(taken) < limit:
            try:
                taken.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return taken

    def _collect(self) -> list[pb.CaptureEvent]:
        """Block for one event, then fill the batch until size or delay.

        Returns an empty list if nothing arrived while idling, which ends the
        worker.

        "Do not wait" and "do not batch" are different things, and conflating
        them is a mistake worth naming: when a flush is pending, or when
        batching is disabled, this still sweeps up everything already queued. It
        just does not wait for more. Sending one request per event on the flush
        path would break batching precisely on the shutdown path where a backlog
        is most likely.
        """
        try:
            first = self._queue.get(timeout=_IDLE_WAIT_SECONDS)
        except queue.Empty:
            return []

        batch = [first]
        if self._batch_delay <= 0 or self._flush_now.is_set():
            batch.extend(self._drain_available(self._batch_size - len(batch)))
            return batch

        deadline = time.monotonic() + self._batch_delay
        while len(batch) < self._batch_size:
            if self._flush_now.is_set():
                # A flush is waiting: stop waiting, but still take the backlog.
                batch.extend(self._drain_available(self._batch_size - len(batch)))
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                batch.append(self._queue.get(timeout=remaining))
            except queue.Empty:
                break
        return batch

    def _run(self) -> None:
        while True:
            batch = self._collect()
            if not batch:
                return
            try:
                self._send(batch)
            except Exception:
                # Send-once: a failed batch is dropped, never retried.
                self._diagnose(CAPTURE_SEND_FAILED, len(batch))
            finally:
                self._finish(len(batch))


class AsyncCaptureDelivery:
    """Bounded batched delivery on an ``asyncio`` task.

    The worker task is created on the first :meth:`capture` call rather than in
    the constructor, because a client is usually built at import time when no
    event loop is running yet.

    Args:
        send: Sends one batch exactly once.  May raise, in which case the batch
            is dropped and reported.
        diagnose: Local diagnostics sink.
        queue_size: Ceiling on queued plus in-flight events.
        batch_size: Most events per request.
        batch_delay_ms: How long a partial batch waits before being sent.
    """

    def __init__(
        self,
        *,
        send: _SendAsync,
        diagnose: Diagnose,
        queue_size: int = DEFAULT_QUEUE_SIZE,
        batch_size: int = DEFAULT_BATCH_SIZE,
        batch_delay_ms: int = DEFAULT_BATCH_DELAY_MS,
    ) -> None:
        self._send = send
        self._diagnose = diagnose
        self._queue_size = _positive_int(queue_size, DEFAULT_QUEUE_SIZE)
        self._batch_size = _positive_int(batch_size, DEFAULT_BATCH_SIZE)
        delay_ms = _nonnegative_int(batch_delay_ms, DEFAULT_BATCH_DELAY_MS)
        self._batch_delay = delay_ms / 1000

        # A plain deque rather than asyncio.Queue: the queue would bind to one
        # event loop, and a client outlives any single loop (a per-test loop, or
        # successive asyncio.run calls).
        self._queue: Deque[pb.CaptureEvent] = deque()
        self._in_flight = 0
        self._loop: asyncio.AbstractEventLoop | None = None
        self._worker: asyncio.Task[None] | None = None
        self._wake: asyncio.Event | None = None
        self._idle: asyncio.Event | None = None
        self._flush_now = False

    def capture(self, event: pb.CaptureEvent) -> None:
        """Enqueue one event without blocking or awaiting."""
        if len(self._queue) + self._in_flight >= self._queue_size:
            self._diagnose(CAPTURE_QUEUE_FULL, 1)
            return
        self._queue.append(event)
        self._ensure_worker()
        if self._idle is not None:
            self._idle.clear()
        if self._wake is not None:
            self._wake.set()

    async def flush(self, timeout_ms: int | None = None) -> None:
        """Drain queued and in-flight events, dropping whatever does not fit.

        Args:
            timeout_ms: Deadline in milliseconds.  On expiry the queued
                remainder is dropped and reported as ``AJ3003``.
        """
        deadline = _nonnegative_int(timeout_ms, DEFAULT_FLUSH_TIMEOUT_MS) / 1000
        if not self._queue and self._in_flight == 0:
            return

        self._ensure_worker()
        idle = self._idle
        if idle is None:
            # No loop was running, so nothing can drain. Reachable only if the
            # caller has no running loop, which cannot happen inside `await`.
            return

        self._flush_now = True
        if self._wake is not None:
            self._wake.set()
        try:
            await asyncio.wait_for(idle.wait(), timeout=deadline)
        except (asyncio.TimeoutError, TimeoutError):
            dropped = len(self._queue)
            self._queue.clear()
            if dropped:
                self._diagnose(CAPTURE_FLUSH_EXPIRED, dropped)
        finally:
            self._flush_now = False

    def _ensure_worker(self) -> None:
        """Start the worker task, or leave events queued until a loop exists."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No running loop. Events stay queued until a capture() or flush()
            # happens inside one; dropping here would lose events that a later
            # flush() could still deliver.
            return

        alive = self._worker is not None and not self._worker.done()
        if alive and self._loop is loop:
            return

        # asyncio primitives belong to the loop that created them, so a new loop
        # needs a fresh Event pair and task.
        #
        # This rebinds rather than cancelling the previous task, which is safe
        # for the supported case — loops used one after another, as successive
        # asyncio.run() calls or a per-test loop, where the old loop is closed
        # and its task is already gone. It is NOT safe to drive one client from
        # two loops running concurrently in different threads: two workers would
        # pop from the same deque with `_in_flight` split between them, so
        # flush() could return early. Cancelling the old task cannot fix that
        # from here either, because cancelling a task belonging to another
        # running loop is itself not thread-safe.
        #
        # A client is documented as belonging to one loop at a time. Sharing one
        # across concurrent loops is unsupported; build a client per loop.
        self._loop = loop
        self._wake = asyncio.Event()
        self._idle = asyncio.Event()
        self._worker = loop.create_task(self._run())

    def _mark_idle_if_done(self) -> None:
        if not self._queue and self._in_flight == 0 and self._idle is not None:
            self._idle.set()

    async def _run(self) -> None:
        wake = self._wake
        if wake is None:  # pragma: no cover - set by _ensure_worker
            return
        while True:
            if not self._queue:
                self._mark_idle_if_done()
                wake.clear()
                try:
                    await asyncio.wait_for(wake.wait(), timeout=_IDLE_WAIT_SECONDS)
                except (asyncio.TimeoutError, TimeoutError):
                    # Expected: nothing arrived within the idle window. The
                    # timeout is the signal to re-check the queue and stop, not
                    # an error, so there is nothing to handle or report.
                    pass
                if not self._queue:
                    # Nothing arrived while idling. Ending the task frees the
                    # loop; the next capture() starts a new one.
                    return

            if (
                len(self._queue) < self._batch_size
                and self._batch_delay > 0
                and not self._flush_now
            ):
                await asyncio.sleep(self._batch_delay)

            batch: list[pb.CaptureEvent] = []
            while self._queue and len(batch) < self._batch_size:
                batch.append(self._queue.popleft())
            if not batch:
                continue

            self._in_flight += len(batch)
            try:
                await self._send(batch)
            except (asyncio.CancelledError, GeneratorExit):
                # The loop is going away. This is not a send failure, so it is
                # not reported as one.
                self._in_flight -= len(batch)
                raise
            except Exception:
                # Send-once: a failed batch is dropped, never retried.
                self._diagnose(CAPTURE_SEND_FAILED, len(batch))
                self._in_flight -= len(batch)
            else:
                self._in_flight -= len(batch)
            self._mark_idle_if_done()
