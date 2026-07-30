"""Integration tests for ``capture()`` on the guard clients.

These drive the whole path a user's call takes — ``capture()`` → normalization →
delivery → transport — with a fake transport standing in for the network, so the
wire request is inspected rather than mocked away.
"""

from __future__ import annotations

import asyncio
import threading
import time
from datetime import datetime, timezone
from typing import Any

import pytest

import arcjet.guard._client as guard_client
from arcjet.guard import ArcjetGuard, ArcjetGuardSync
from arcjet.guard.proto.decide.v2 import decide_pb2 as pb

TIMEOUT_MS = 5000


class FakeCaptureAsyncClient:
    """Async transport that records Capture requests."""

    def __init__(self, fail: bool = False) -> None:
        self.requests: list[pb.CaptureRequest] = []
        self.headers: list[dict[str, str] | None] = []
        self.timeouts: list[int | None] = []
        self._fail = fail

    async def capture(
        self,
        request: pb.CaptureRequest,
        *,
        headers: dict[str, str] | None = None,
        timeout_ms: int | None = None,
    ) -> pb.CaptureResponse:
        self.requests.append(request)
        self.headers.append(headers)
        self.timeouts.append(timeout_ms)
        if self._fail:
            raise ConnectionError("network down")
        return pb.CaptureResponse()

    @property
    def events(self) -> list[pb.CaptureEvent]:
        return [e for r in self.requests for e in r.events]


class FakeCaptureSyncClient:
    """Sync transport that records Capture requests."""

    def __init__(self, fail: bool = False) -> None:
        self._lock = threading.Lock()
        self.requests: list[pb.CaptureRequest] = []
        self.headers: list[dict[str, str] | None] = []
        self.timeouts: list[int | None] = []
        self._fail = fail

    def capture(
        self,
        request: pb.CaptureRequest,
        *,
        headers: dict[str, str] | None = None,
        timeout_ms: int | None = None,
    ) -> pb.CaptureResponse:
        with self._lock:
            self.requests.append(request)
            self.headers.append(headers)
            self.timeouts.append(timeout_ms)
        if self._fail:
            raise ConnectionError("network down")
        return pb.CaptureResponse()

    @property
    def events(self) -> list[pb.CaptureEvent]:
        with self._lock:
            return [e for r in self.requests for e in r.events]


def _make_guard(client: Any) -> ArcjetGuard:
    return ArcjetGuard(
        _key="test_key_123",
        _client=client,
        _timeout_ms=1000,
        _user_agent="arcjet-py/test",
    )


def _make_guard_sync(client: Any) -> ArcjetGuardSync:
    return ArcjetGuardSync(
        _key="test_key_123",
        _client=client,
        _timeout_ms=1000,
        _user_agent="arcjet-py/test",
    )


class TestCaptureSync:
    def test_captures_an_event(self) -> None:
        client = FakeCaptureSyncClient()
        guard = _make_guard_sync(client)

        guard.capture(action="refund.issued")
        guard.flush(TIMEOUT_MS)

        assert [e.action for e in client.events] == ["refund.issued"]

    def test_sends_auth_and_user_agent(self) -> None:
        client = FakeCaptureSyncClient()
        guard = _make_guard_sync(client)

        guard.capture(action="refund.issued")
        guard.flush(TIMEOUT_MS)

        assert client.headers[0] == {"Authorization": "Bearer test_key_123"}
        assert client.requests[0].user_agent == "arcjet-py/test"
        # Capture reuses the client's configured timeout rather than its own.
        assert client.timeouts[0] == 1000

    def test_sets_source_to_sdk(self) -> None:
        client = FakeCaptureSyncClient()
        guard = _make_guard_sync(client)

        guard.capture(action="refund.issued")
        guard.flush(TIMEOUT_MS)

        assert client.events[0].source == "sdk"

    def test_forwards_all_fields(self) -> None:
        client = FakeCaptureSyncClient()
        guard = _make_guard_sync(client)
        occurred = datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)

        guard.capture(
            action="refund.issued",
            correlation_id="workflow_123",
            decision_id="gdec_abc",
            occurred_at=occurred,
            metadata={"invoice": {"id": "inv_1"}},
        )
        guard.flush(TIMEOUT_MS)

        event = client.events[0]
        assert event.correlation_id == "workflow_123"
        assert event.decision_id == "gdec_abc"
        assert event.occurred_at_unix_ms == int(occurred.timestamp() * 1000)
        assert dict(event.metadata_json) == {"invoice": '{"id":"inv_1"}'}

    def test_invalid_event_never_reaches_the_transport(self) -> None:
        client = FakeCaptureSyncClient()
        guard = _make_guard_sync(client)

        guard.capture(action="")  # no action: dropped during normalization
        guard.flush(TIMEOUT_MS)

        assert client.requests == []

    def test_capture_does_not_raise_on_transport_failure(self) -> None:
        client = FakeCaptureSyncClient(fail=True)
        guard = _make_guard_sync(client)

        guard.capture(action="refund.issued")
        guard.flush(TIMEOUT_MS)  # must not raise

        assert len(client.requests) == 1, "failed sends are not retried"

    def test_flush_without_capture_does_nothing(self) -> None:
        client = FakeCaptureSyncClient()
        guard = _make_guard_sync(client)

        guard.flush(TIMEOUT_MS)

        assert client.requests == []

    def test_batches_a_burst(self) -> None:
        client = FakeCaptureSyncClient()
        guard = _make_guard_sync(client)

        for i in range(5):
            guard.capture(action=f"thing.{i}")
        guard.flush(TIMEOUT_MS)

        assert len(client.events) == 5
        assert len(client.requests) < 5, "a burst should not be one request each"

    def test_concurrent_first_capture_builds_one_delivery(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two threads racing the first capture() must not each build a delivery.

        Without double-checked locking in `_ensure_delivery`, both threads see
        `_delivery is None`, each construct a `SyncCaptureDelivery` and start a
        worker thread, and one is overwritten — orphaning its thread along with
        any events already queued on it. Those events are then invisible to
        `flush()`, which only knows about the surviving delivery.

        The construction window is widened artificially. Written the obvious way
        — threads on a barrier, then assert one delivery — this test passed 20/20
        against the *unlocked* code: construction is fast enough that the GIL
        hands it over before a second thread can enter. Sleeping inside the
        constructor is what makes the race deterministic instead of hoping the
        scheduler cooperates.
        """
        client = FakeCaptureSyncClient()
        guard = _make_guard_sync(client)

        built = []
        built_lock = threading.Lock()
        real_delivery = guard_client.SyncCaptureDelivery

        def slow_delivery(**kwargs: Any) -> Any:
            with built_lock:
                built.append(1)
            # Hold the window open so every waiting thread would also enter an
            # unlocked check-then-construct.
            time.sleep(0.05)
            return real_delivery(**kwargs)

        monkeypatch.setattr(guard_client, "SyncCaptureDelivery", slow_delivery)

        threads = 8
        start = threading.Barrier(threads)

        def worker(index: int) -> None:
            start.wait(TIMEOUT_MS / 1000)
            guard.capture(action=f"race.{index}")

        workers = [threading.Thread(target=worker, args=(i,)) for i in range(threads)]
        for t in workers:
            t.start()
        for t in workers:
            t.join(TIMEOUT_MS / 1000)

        assert len(built) == 1, (
            f"{len(built)} deliveries were constructed; each extra one orphans a "
            "worker thread and any events queued on it"
        )

        guard.flush(TIMEOUT_MS)

        # No event was orphaned on a discarded delivery.
        assert sorted(e.action for e in client.events) == sorted(
            f"race.{i}" for i in range(threads)
        )

    def test_flush_drains_coalesced_diagnostics(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """flush() must release counts the diagnostics channel held back.

        Coalescing means a burst of drops reports only its first event until
        something releases the rest. flush() is that something — without this
        wiring the fix in `_diagnostics` would never be reached in practice.
        """
        drained: list[bool] = []

        class Spy:
            def __call__(self, code: str, count: int = 1) -> None:
                pass

            def drain(self) -> None:
                drained.append(True)

        monkeypatch.setattr(guard_client, "_diagnose", Spy())

        client = FakeCaptureSyncClient()
        guard = _make_guard_sync(client)
        guard.capture(action="drain.me")
        guard.flush(TIMEOUT_MS)

        assert drained == [True], "flush() should drain held-back diagnostics"

    def test_flush_without_capture_does_not_drain(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Nothing was captured, so there is no delivery and nothing to drain."""
        drained: list[bool] = []

        class Spy:
            def __call__(self, code: str, count: int = 1) -> None:
                pass

            def drain(self) -> None:
                drained.append(True)

        monkeypatch.setattr(guard_client, "_diagnose", Spy())

        guard = _make_guard_sync(FakeCaptureSyncClient())
        guard.flush(TIMEOUT_MS)

        assert drained == []

    def test_guard_still_works_alongside_capture(self) -> None:
        """Capture must not disturb the decision path."""
        client = FakeCaptureSyncClient()
        guard = _make_guard_sync(client)

        guard.capture(action="refund.issued")
        guard.flush(TIMEOUT_MS)

        # An empty rule list short-circuits before the transport, which is
        # enough to show guard() is unaffected by the capture machinery. It
        # fails open, so the conclusion is ALLOW with the error on the result.
        decision = guard.guard([], label="test")
        assert decision.conclusion == "ALLOW"


class TestCaptureAsync:
    """Async client tests, driven with ``asyncio.run`` (no pytest-asyncio)."""

    def test_captures_an_event(self) -> None:
        client = FakeCaptureAsyncClient()
        guard = _make_guard(client)

        async def scenario() -> None:
            guard.capture(action="refund.issued")
            await guard.flush(TIMEOUT_MS)

        asyncio.run(scenario())

        assert [e.action for e in client.events] == ["refund.issued"]

    def test_sends_auth_and_user_agent(self) -> None:
        client = FakeCaptureAsyncClient()
        guard = _make_guard(client)

        async def scenario() -> None:
            guard.capture(action="refund.issued")
            await guard.flush(TIMEOUT_MS)

        asyncio.run(scenario())

        assert client.headers[0] == {"Authorization": "Bearer test_key_123"}
        assert client.requests[0].user_agent == "arcjet-py/test"
        assert client.timeouts[0] == 1000

    def test_sets_source_to_sdk(self) -> None:
        client = FakeCaptureAsyncClient()
        guard = _make_guard(client)

        async def scenario() -> None:
            guard.capture(action="refund.issued")
            await guard.flush(TIMEOUT_MS)

        asyncio.run(scenario())

        assert client.events[0].source == "sdk"

    def test_capture_returns_without_awaiting(self) -> None:
        """capture() is fire-and-forget: it is not a coroutine."""
        client = FakeCaptureAsyncClient()
        guard = _make_guard(client)

        async def scenario() -> None:
            result = guard.capture(action="refund.issued")
            assert result is None
            await guard.flush(TIMEOUT_MS)

        asyncio.run(scenario())

        assert len(client.events) == 1

    def test_invalid_event_never_reaches_the_transport(self) -> None:
        client = FakeCaptureAsyncClient()
        guard = _make_guard(client)

        async def scenario() -> None:
            guard.capture(action=None)  # type: ignore[arg-type]
            await guard.flush(TIMEOUT_MS)

        asyncio.run(scenario())

        assert client.requests == []

    def test_capture_does_not_raise_on_transport_failure(self) -> None:
        client = FakeCaptureAsyncClient(fail=True)
        guard = _make_guard(client)

        async def scenario() -> None:
            guard.capture(action="refund.issued")
            await guard.flush(TIMEOUT_MS)

        asyncio.run(scenario())

        assert len(client.requests) == 1, "failed sends are not retried"

    def test_batches_a_burst_into_one_request(self) -> None:
        client = FakeCaptureAsyncClient()
        guard = _make_guard(client)

        async def scenario() -> None:
            for i in range(5):
                guard.capture(action=f"thing.{i}")
            await guard.flush(TIMEOUT_MS)

        asyncio.run(scenario())

        assert len(client.events) == 5
        assert len(client.requests) == 1

    def test_flush_without_capture_does_nothing(self) -> None:
        client = FakeCaptureAsyncClient()
        guard = _make_guard(client)

        async def scenario() -> None:
            await guard.flush(TIMEOUT_MS)

        asyncio.run(scenario())

        assert client.requests == []
