"""Unit tests for bounded, batched capture delivery.

Delivery is concurrent, so these tests avoid sleeping to observe a result.  They
synchronize on ``threading.Event`` / ``asyncio.Event`` and on ``flush()``, and
every test that blocks a send releases it in a ``finally`` so a failure cannot
hang the suite.

``batch_delay_ms=0`` is used wherever batching itself is not under test, so a
send happens as soon as the worker picks the event up.
"""

from __future__ import annotations

import asyncio
import threading
import time

from arcjet.guard._delivery import AsyncCaptureDelivery, SyncCaptureDelivery
from arcjet.guard._diagnostics import (
    CAPTURE_FLUSH_EXPIRED,
    CAPTURE_QUEUE_FULL,
    CAPTURE_SEND_FAILED,
)
from arcjet.guard.proto.decide.v2 import decide_pb2 as pb

# Long enough that a correct implementation never reaches it, short enough that
# a deadlock fails the test instead of hanging the suite.
TIMEOUT = 5.0
TIMEOUT_MS = 5000


def event(action: str = "refund.issued") -> pb.CaptureEvent:
    return pb.CaptureEvent(action=action, source="sdk")


class Diagnostics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.codes: list[tuple[str, int]] = []

    def __call__(self, code: str, count: int = 1) -> None:
        with self._lock:
            self.codes.append((code, count))

    def total(self, code: str) -> int:
        with self._lock:
            return sum(n for c, n in self.codes if c == code)


class TestSyncDelivery:
    def test_sends_a_captured_event(self) -> None:
        sent: list[list[pb.CaptureEvent]] = []
        diag = Diagnostics()
        delivery = SyncCaptureDelivery(
            send=lambda events: sent.append(events),
            diagnose=diag,
            batch_delay_ms=0,
        )

        delivery.capture(event())
        delivery.flush(TIMEOUT_MS)

        assert [e.action for batch in sent for e in batch] == ["refund.issued"]
        assert diag.codes == []

    def test_batches_several_events_into_one_request(self) -> None:
        """A burst costs one request, not one per event."""
        sent: list[list[pb.CaptureEvent]] = []
        release = threading.Event()

        def send(events: list[pb.CaptureEvent]) -> None:
            sent.append(events)
            release.set()

        delivery = SyncCaptureDelivery(
            send=send, diagnose=Diagnostics(), batch_size=10, batch_delay_ms=50
        )

        for i in range(5):
            delivery.capture(event(f"a.{i}"))
        delivery.flush(TIMEOUT_MS)

        assert release.wait(TIMEOUT)
        # The exact split depends on worker timing; what matters is that all
        # five arrived and they did not each become their own request.
        assert sum(len(b) for b in sent) == 5
        assert len(sent) < 5

    def test_flush_still_batches_the_backlog(self) -> None:
        """A pending flush must not turn a backlog into one request per event.

        Regression test. Live against the API, a five-event burst followed by
        `flush()` produced five separate requests: the worker saw the flush flag
        and sent only the event it already held, abandoning the queue. In-process
        sends are instant, so the looser "fewer requests than events" assertion
        above passed anyway — this test blocks the first send to build a real
        backlog, which is what made the bug visible in production.
        """
        sent: list[int] = []
        blocked = threading.Event()
        in_send = threading.Event()

        def send(events: list[pb.CaptureEvent]) -> None:
            sent.append(len(events))
            if not in_send.is_set():
                in_send.set()
                blocked.wait(TIMEOUT)

        delivery = SyncCaptureDelivery(
            send=send, diagnose=Diagnostics(), batch_size=10, batch_delay_ms=50
        )

        try:
            delivery.capture(event("first"))
            # The worker is now inside send(), holding nothing else.
            assert in_send.wait(TIMEOUT)
            for i in range(5):
                delivery.capture(event(f"backlog.{i}"))
        finally:
            blocked.set()

        delivery.flush(TIMEOUT_MS)

        assert sum(sent) == 6, f"all six events should be sent, got {sent}"
        assert sent == [1, 5], (
            f"the five queued events should go as one batch, got {sent}"
        )

    def test_drops_when_the_queue_is_full(self) -> None:
        """The ceiling covers in-flight events, so a stuck send applies it."""
        blocked = threading.Event()
        in_send = threading.Event()
        diag = Diagnostics()

        def send(events: list[pb.CaptureEvent]) -> None:
            in_send.set()
            blocked.wait(TIMEOUT)

        delivery = SyncCaptureDelivery(
            send=send,
            diagnose=diag,
            queue_size=2,
            batch_size=1,
            batch_delay_ms=0,
        )

        try:
            delivery.capture(event("first"))
            # Wait until it is genuinely on the wire, so `outstanding` is 1 and
            # the queue is empty — otherwise the counts race.
            assert in_send.wait(TIMEOUT)

            delivery.capture(event("second"))  # queued: outstanding == 2
            delivery.capture(event("third"))  # over the ceiling: dropped
            delivery.capture(event("fourth"))  # also dropped

            assert diag.total(CAPTURE_QUEUE_FULL) == 2
        finally:
            blocked.set()

    def test_a_failed_send_is_not_retried(self) -> None:
        attempts: list[int] = []
        diag = Diagnostics()

        def send(events: list[pb.CaptureEvent]) -> None:
            attempts.append(len(events))
            raise ConnectionError("network down")

        delivery = SyncCaptureDelivery(
            send=send, diagnose=diag, batch_size=1, batch_delay_ms=0
        )

        delivery.capture(event())
        delivery.flush(TIMEOUT_MS)

        assert attempts == [1], "a failed batch must not be retried"
        assert diag.total(CAPTURE_SEND_FAILED) == 1

    def test_a_failed_send_does_not_stop_the_worker(self) -> None:
        results: list[str] = []
        diag = Diagnostics()

        def send(events: list[pb.CaptureEvent]) -> None:
            action = events[0].action
            results.append(action)
            if action == "bad":
                raise ConnectionError("network down")

        delivery = SyncCaptureDelivery(
            send=send, diagnose=diag, batch_size=1, batch_delay_ms=0
        )

        delivery.capture(event("bad"))
        delivery.flush(TIMEOUT_MS)
        delivery.capture(event("good"))
        delivery.flush(TIMEOUT_MS)

        assert results == ["bad", "good"]
        assert diag.total(CAPTURE_SEND_FAILED) == 1

    def test_flush_with_nothing_queued_returns(self) -> None:
        delivery = SyncCaptureDelivery(send=lambda events: None, diagnose=Diagnostics())

        delivery.flush(TIMEOUT_MS)  # must not block or raise

    def test_flush_deadline_drops_the_remainder(self) -> None:
        blocked = threading.Event()
        in_send = threading.Event()
        diag = Diagnostics()

        def send(events: list[pb.CaptureEvent]) -> None:
            in_send.set()
            blocked.wait(TIMEOUT)

        delivery = SyncCaptureDelivery(
            send=send, diagnose=diag, batch_size=1, batch_delay_ms=0
        )

        try:
            delivery.capture(event("in-flight"))
            assert in_send.wait(TIMEOUT)
            delivery.capture(event("queued"))

            delivery.flush(50)  # cannot drain: the send is stuck

            # Two: the queued event, dropped, plus the in-flight one, abandoned.
            # The in-flight event used to be omitted from this total entirely.
            assert diag.total(CAPTURE_FLUSH_EXPIRED) == 2
        finally:
            blocked.set()

    def test_flush_does_not_drop_events_captured_after_it_started(self) -> None:
        """One caller's flush deadline must not discard another's telemetry.

        The capture ADR recommends calling flush() at the end of a handler, so in
        a concurrent server several flushes overlap with ongoing captures. Both
        drivers previously drained the whole queue on expiry, so request A's
        deadline deleted request B's queued events.
        """
        sent: list[str] = []
        blocked = threading.Event()
        in_send = threading.Event()
        diag = Diagnostics()

        def send(events: list[pb.CaptureEvent]) -> None:
            sent.extend(e.action for e in events)
            if not in_send.is_set():
                in_send.set()
                blocked.wait(TIMEOUT)

        delivery = SyncCaptureDelivery(
            send=send, diagnose=diag, batch_size=1, batch_delay_ms=0
        )
        try:
            delivery.capture(event("early"))
            assert in_send.wait(TIMEOUT)

            # Capture only after flush() has snapshotted the queue. A sleep
            # here races: if the late puts land first, they are this flush's
            # remainder and `_abandon` drops them.
            flushed = threading.Event()

            def run_flush() -> None:
                try:
                    delivery.flush(100)  # cannot drain: the first send is stuck
                finally:
                    flushed.set()

            threading.Thread(target=run_flush, daemon=True).start()
            assert delivery._flush_now.wait(TIMEOUT)
            delivery.capture(event("late-1"))
            delivery.capture(event("late-2"))
            assert flushed.wait(TIMEOUT)

            assert delivery._queue.qsize() == 2, "late events must still be queued"
        finally:
            blocked.set()

        delivery.flush(TIMEOUT_MS)
        assert sorted(sent) == ["early", "late-1", "late-2"]

    def test_flush_expiry_counts_in_flight_events(self) -> None:
        """An abandoned in-flight send must still be reported.

        It is deliberately not cancelled — the sync transport has no handle — but
        leaving it out of the AJ3003 total would under-report the loss.
        """
        blocked = threading.Event()
        in_send = threading.Event()
        diag = Diagnostics()

        def send(events: list[pb.CaptureEvent]) -> None:
            in_send.set()
            blocked.wait(TIMEOUT)

        delivery = SyncCaptureDelivery(
            send=send, diagnose=diag, batch_size=2, batch_delay_ms=0
        )
        try:
            delivery.capture(event("in-flight"))
            assert in_send.wait(TIMEOUT)
            delivery.capture(event("queued"))

            delivery.flush(50)

            # One dropped from the queue, one abandoned on the wire.
            assert diag.total(CAPTURE_FLUSH_EXPIRED) == 2
        finally:
            blocked.set()

    def test_worker_thread_is_a_daemon(self) -> None:
        """A queued event must not keep the interpreter alive at exit."""
        started = threading.Event()
        delivery = SyncCaptureDelivery(
            send=lambda events: started.set(),
            diagnose=Diagnostics(),
            batch_delay_ms=0,
        )

        delivery.capture(event())
        assert started.wait(TIMEOUT)

        workers = [t for t in threading.enumerate() if t.name == "arcjet-capture"]
        assert workers, "expected a worker thread"
        assert all(t.daemon for t in workers)

    def test_worker_releases_its_slot_when_it_exits(self) -> None:
        """The exiting worker must clear the slot, not just die.

        `Thread.is_alive()` stays True until the thread function returns, so
        `_ensure_worker` gating on it alone left a window where an event enqueued
        just after the idle timeout got no worker at all — queued, unsent, and
        undiagnosed. The fix makes the exit decision atomic with releasing the
        slot, so the observable invariant is that a dead worker is never left
        recorded as the current one.

        Asserted on the invariant rather than by racing it: the window is real
        but too narrow to hit reliably, and forcing it open by holding
        `_worker_lock` deadlocks, since `capture()` takes that same lock.
        """
        sent: list[str] = []
        diag = Diagnostics()
        delivery = SyncCaptureDelivery(
            send=lambda events: sent.extend(e.action for e in events),
            diagnose=diag,
            batch_delay_ms=0,
        )

        delivery.capture(event("first"))
        delivery.flush(TIMEOUT_MS)
        assert sent == ["first"]

        # Wait out the idle window so the worker exits on its own.
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            if delivery._worker is None:
                break
            time.sleep(0.05)

        assert delivery._worker is None, (
            "the exiting worker left itself recorded as current; a capture() "
            "arriving now would find is_alive() True and start no replacement"
        )

        # And the next capture is picked up by a fresh worker.
        delivery.capture(event("second"))
        delivery.flush(TIMEOUT_MS)
        assert sent == ["first", "second"]
        assert diag.total(CAPTURE_FLUSH_EXPIRED) == 0

    def test_no_worker_thread_before_first_capture(self) -> None:
        before = len([t for t in threading.enumerate() if t.name == "arcjet-capture"])
        SyncCaptureDelivery(send=lambda events: None, diagnose=Diagnostics())
        after = len([t for t in threading.enumerate() if t.name == "arcjet-capture"])

        assert after == before

    def test_invalid_tuning_falls_back_to_defaults(self) -> None:
        sent: list[list[pb.CaptureEvent]] = []
        delivery = SyncCaptureDelivery(
            send=lambda events: sent.append(events),
            diagnose=Diagnostics(),
            queue_size=0,
            batch_size=-5,
            batch_delay_ms=None,  # type: ignore[arg-type]
        )

        delivery.capture(event())
        delivery.flush(TIMEOUT_MS)

        assert sum(len(b) for b in sent) == 1


class TestAsyncDelivery:
    """Async driver tests.

    arcjet-py has no pytest-asyncio, so each test is a sync function that drives
    a coroutine with ``asyncio.run``, matching ``TestArcjetGuardAsync`` in
    ``tests/integration/guard/test_client.py``.
    """

    def test_sends_a_captured_event(self) -> None:
        sent: list[list[pb.CaptureEvent]] = []
        diag = Diagnostics()

        async def send(events: list[pb.CaptureEvent]) -> None:
            sent.append(events)

        async def scenario() -> None:
            delivery = AsyncCaptureDelivery(send=send, diagnose=diag, batch_delay_ms=0)
            delivery.capture(event())
            await delivery.flush(TIMEOUT_MS)

        asyncio.run(scenario())

        assert [e.action for batch in sent for e in batch] == ["refund.issued"]
        assert diag.codes == []

    def test_batches_several_events_into_one_request(self) -> None:
        sent: list[list[pb.CaptureEvent]] = []

        async def send(events: list[pb.CaptureEvent]) -> None:
            sent.append(events)

        async def scenario() -> None:
            delivery = AsyncCaptureDelivery(
                send=send, diagnose=Diagnostics(), batch_size=10, batch_delay_ms=10
            )
            for i in range(5):
                delivery.capture(event(f"a.{i}"))
            await delivery.flush(TIMEOUT_MS)

        asyncio.run(scenario())

        assert sum(len(b) for b in sent) == 5
        assert len(sent) == 1, "one flush of five events should be one request"

    def test_drops_when_the_queue_is_full(self) -> None:
        diag = Diagnostics()

        async def scenario() -> None:
            blocked = asyncio.Event()
            in_send = asyncio.Event()

            async def send(events: list[pb.CaptureEvent]) -> None:
                in_send.set()
                await blocked.wait()

            delivery = AsyncCaptureDelivery(
                send=send,
                diagnose=diag,
                queue_size=2,
                batch_size=1,
                batch_delay_ms=0,
            )
            try:
                delivery.capture(event("first"))
                await asyncio.wait_for(in_send.wait(), TIMEOUT)

                delivery.capture(event("second"))
                delivery.capture(event("third"))
                delivery.capture(event("fourth"))
            finally:
                blocked.set()

        asyncio.run(scenario())

        assert diag.total(CAPTURE_QUEUE_FULL) == 2

    def test_a_failed_send_is_not_retried(self) -> None:
        attempts: list[int] = []
        diag = Diagnostics()

        async def send(events: list[pb.CaptureEvent]) -> None:
            attempts.append(len(events))
            raise ConnectionError("network down")

        async def scenario() -> None:
            delivery = AsyncCaptureDelivery(
                send=send, diagnose=diag, batch_size=1, batch_delay_ms=0
            )
            delivery.capture(event())
            await delivery.flush(TIMEOUT_MS)

        asyncio.run(scenario())

        assert attempts == [1], "a failed batch must not be retried"
        assert diag.total(CAPTURE_SEND_FAILED) == 1

    def test_flush_with_nothing_queued_returns(self) -> None:
        async def send(events: list[pb.CaptureEvent]) -> None:
            return None

        async def scenario() -> None:
            delivery = AsyncCaptureDelivery(send=send, diagnose=Diagnostics())
            await delivery.flush(TIMEOUT_MS)

        asyncio.run(scenario())

    def test_flush_deadline_drops_the_remainder(self) -> None:
        diag = Diagnostics()

        async def scenario() -> None:
            blocked = asyncio.Event()
            in_send = asyncio.Event()

            async def send(events: list[pb.CaptureEvent]) -> None:
                in_send.set()
                await blocked.wait()

            delivery = AsyncCaptureDelivery(
                send=send, diagnose=diag, batch_size=1, batch_delay_ms=0
            )
            try:
                delivery.capture(event("in-flight"))
                await asyncio.wait_for(in_send.wait(), TIMEOUT)
                delivery.capture(event("queued"))

                await delivery.flush(50)
            finally:
                blocked.set()

        asyncio.run(scenario())

        # Two: the queued event, dropped, plus the in-flight one, abandoned.
        assert diag.total(CAPTURE_FLUSH_EXPIRED) == 2

    def test_flush_does_not_drop_events_captured_after_it_started(self) -> None:
        """Async counterpart of the sync test with the same name.

        Both drivers had the bug and both were fixed; only the sync one was
        covered, so this driver's fix was unverified.
        """
        sent: list[str] = []
        diag = Diagnostics()

        async def scenario() -> None:
            blocked = asyncio.Event()
            in_send = asyncio.Event()

            async def send(events: list[pb.CaptureEvent]) -> None:
                sent.extend(e.action for e in events)
                if not in_send.is_set():
                    in_send.set()
                    await blocked.wait()

            delivery = AsyncCaptureDelivery(
                send=send, diagnose=diag, batch_size=1, batch_delay_ms=0
            )
            try:
                delivery.capture(event("early"))
                await asyncio.wait_for(in_send.wait(), TIMEOUT)

                # Same race as the sync test: capture after `_flush_now` so
                # the snapshot cannot include these events.
                flush_task = asyncio.create_task(delivery.flush(100))
                deadline = time.monotonic() + TIMEOUT
                while not delivery._flush_now:
                    assert time.monotonic() < deadline, "flush never started"
                    await asyncio.sleep(0)
                delivery.capture(event("late-1"))
                delivery.capture(event("late-2"))
                await flush_task

                assert len(delivery._queue) == 2, "late events must still be queued"
            finally:
                blocked.set()
            await delivery.flush(TIMEOUT_MS)

        asyncio.run(scenario())

        assert sorted(sent) == ["early", "late-1", "late-2"]

    def test_flush_expiry_counts_in_flight_events(self) -> None:
        """Async counterpart: an abandoned in-flight send is still reported."""
        diag = Diagnostics()

        async def scenario() -> None:
            blocked = asyncio.Event()
            in_send = asyncio.Event()

            async def send(events: list[pb.CaptureEvent]) -> None:
                in_send.set()
                await blocked.wait()

            delivery = AsyncCaptureDelivery(
                send=send, diagnose=diag, batch_size=1, batch_delay_ms=0
            )
            try:
                delivery.capture(event("in-flight"))
                await asyncio.wait_for(in_send.wait(), TIMEOUT)
                delivery.capture(event("queued"))

                await delivery.flush(50)
            finally:
                blocked.set()

        asyncio.run(scenario())

        # One dropped from the queue, one abandoned on the wire.
        assert diag.total(CAPTURE_FLUSH_EXPIRED) == 2

    def test_survives_a_new_event_loop(self) -> None:
        """A client outlives any one loop, so the worker must rebind."""
        sent: list[str] = []

        async def send(events: list[pb.CaptureEvent]) -> None:
            sent.extend(e.action for e in events)

        delivery = AsyncCaptureDelivery(
            send=send, diagnose=Diagnostics(), batch_delay_ms=0
        )

        async def use(action: str) -> None:
            delivery.capture(event(action))
            await delivery.flush(TIMEOUT_MS)

        # Two separate asyncio.run calls are two distinct event loops, which is
        # what a per-test loop or a second entrypoint looks like.
        asyncio.run(use("first-loop"))
        asyncio.run(use("second-loop"))

        assert sent == ["first-loop", "second-loop"]

    def test_capture_without_a_running_loop_keeps_the_event(self) -> None:
        """Queued outside a loop, delivered by a later flush inside one."""
        sent: list[str] = []

        async def send(events: list[pb.CaptureEvent]) -> None:
            sent.extend(e.action for e in events)

        delivery = AsyncCaptureDelivery(
            send=send, diagnose=Diagnostics(), batch_delay_ms=0
        )

        # No loop is running here, so no worker can start yet.
        delivery.capture(event("queued-early"))
        assert sent == []

        async def later() -> None:
            await delivery.flush(TIMEOUT_MS)

        asyncio.run(later())

        assert sent == ["queued-early"]
