"""Integration tests for ``experimental_capture`` on the guard clients.

``experimental_capture`` is fire-and-forget and returns ``None``, so these
tests inject fake transports that signal an event when the Capture RPC
arrives, rather than awaiting the call itself.
"""

from __future__ import annotations

import asyncio
import threading
from datetime import datetime, timezone

from arcjet.guard import ArcjetGuard, ArcjetGuardSync
from arcjet.guard.proto.decide.v2 import decide_pb2 as pb

_OCCURRED_AT = datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc)


class FakeAsyncCaptureClient:
    """Fake async transport recording the Capture request it receives."""

    def __init__(self, error: Exception | None = None) -> None:
        self.last_request: pb.CaptureRequest | None = None
        self.last_headers: dict[str, str] | None = None
        self.received = asyncio.Event()
        self._error = error

    async def guard(self, request, *, headers=None, timeout_ms=None):
        raise AssertionError("guard() must not be called by capture tests")

    async def capture(
        self,
        request: pb.CaptureRequest,
        *,
        headers: dict[str, str] | None = None,
        timeout_ms: int | None = None,
    ) -> pb.CaptureResponse:
        self.last_request = request
        self.last_headers = dict(headers) if headers else None
        self.received.set()
        if self._error is not None:
            raise self._error
        return pb.CaptureResponse()


class FakeSyncCaptureClient:
    """Fake sync transport recording the Capture request it receives."""

    def __init__(self, error: Exception | None = None) -> None:
        self.last_request: pb.CaptureRequest | None = None
        self.last_headers: dict[str, str] | None = None
        self.received = threading.Event()
        self._error = error

    def guard(self, request, *, headers=None, timeout_ms=None):
        raise AssertionError("guard() must not be called by capture tests")

    def capture(
        self,
        request: pb.CaptureRequest,
        *,
        headers: dict[str, str] | None = None,
        timeout_ms: int | None = None,
    ) -> pb.CaptureResponse:
        self.last_request = request
        self.last_headers = dict(headers) if headers else None
        self.received.set()
        if self._error is not None:
            raise self._error
        return pb.CaptureResponse()


def _make_async_client(fake: FakeAsyncCaptureClient) -> ArcjetGuard:
    return ArcjetGuard(
        _key="ajkey_test",
        _client=fake,
        _timeout_ms=1000,
        _user_agent="arcjet-py-test/0.0.0",
    )


def _make_sync_client(fake: FakeSyncCaptureClient) -> ArcjetGuardSync:
    return ArcjetGuardSync(
        _key="ajkey_test",
        _client=fake,
        _timeout_ms=1000,
        _user_agent="arcjet-py-test/0.0.0",
    )


def test_async_capture_sends_event_with_auth() -> None:
    fake = FakeAsyncCaptureClient()
    client = _make_async_client(fake)

    async def scenario() -> None:
        client.experimental_capture(
            "refund.issued",
            correlation_id="wf_abcdef",
            decision_id="gdec_abc",
            occurred_at=_OCCURRED_AT,
            metadata={"invoice": "inv_123"},
        )
        await asyncio.wait_for(fake.received.wait(), timeout=5)

    asyncio.run(scenario())
    request = fake.last_request
    assert request is not None
    assert len(request.events) == 1
    event = request.events[0]
    assert event.action == "refund.issued"
    assert event.correlation_id == "wf_abcdef"
    assert event.decision_id == "gdec_abc"
    assert event.occurred_at_unix_ms == int(_OCCURRED_AT.timestamp() * 1000)
    assert dict(event.metadata) == {"invoice": "inv_123"}
    assert request.sent_at_unix_ms > 0
    assert request.user_agent == "arcjet-py-test/0.0.0"
    assert fake.last_headers == {"Authorization": "Bearer ajkey_test"}


def test_async_capture_occurred_at_defaults_to_sent_at() -> None:
    fake = FakeAsyncCaptureClient()
    client = _make_async_client(fake)

    async def scenario() -> None:
        client.experimental_capture("refund.issued")
        await asyncio.wait_for(fake.received.wait(), timeout=5)

    asyncio.run(scenario())
    request = fake.last_request
    assert request is not None
    assert request.events[0].occurred_at_unix_ms == request.sent_at_unix_ms


def test_async_capture_swallows_transport_errors() -> None:
    fake = FakeAsyncCaptureClient(error=RuntimeError("boom"))
    client = _make_async_client(fake)

    async def scenario() -> None:
        client.experimental_capture("refund.issued")
        await asyncio.wait_for(fake.received.wait(), timeout=5)
        # Let the done callback run: the error must be swallowed (logged at
        # debug), never raised, and the task set must be emptied.
        await asyncio.sleep(0)

    asyncio.run(scenario())
    assert client._pending_captures == set()


def test_async_capture_without_running_loop_does_not_raise() -> None:
    fake = FakeAsyncCaptureClient()
    client = _make_async_client(fake)

    # No running event loop: the event is dropped, never raised.
    client.experimental_capture("refund.issued")

    assert fake.last_request is None


def test_sync_capture_sends_event_with_auth() -> None:
    fake = FakeSyncCaptureClient()
    client = _make_sync_client(fake)

    client.experimental_capture(
        "refund.issued",
        correlation_id="wf_abcdef",
        decision_id="gdec_abc",
        occurred_at=_OCCURRED_AT,
        metadata={"invoice": "inv_123"},
    )

    assert fake.received.wait(timeout=5)
    request = fake.last_request
    assert request is not None
    event = request.events[0]
    assert event.action == "refund.issued"
    assert event.correlation_id == "wf_abcdef"
    assert event.decision_id == "gdec_abc"
    assert event.occurred_at_unix_ms == int(_OCCURRED_AT.timestamp() * 1000)
    assert dict(event.metadata) == {"invoice": "inv_123"}
    assert request.sent_at_unix_ms > 0
    assert fake.last_headers == {"Authorization": "Bearer ajkey_test"}


def test_sync_capture_occurred_at_defaults_to_sent_at() -> None:
    fake = FakeSyncCaptureClient()
    client = _make_sync_client(fake)

    client.experimental_capture("refund.issued")

    assert fake.received.wait(timeout=5)
    request = fake.last_request
    assert request is not None
    assert request.events[0].occurred_at_unix_ms == request.sent_at_unix_ms


def test_sync_capture_swallows_transport_errors() -> None:
    fake = FakeSyncCaptureClient(error=RuntimeError("boom"))
    client = _make_sync_client(fake)

    client.experimental_capture("refund.issued")

    assert fake.received.wait(timeout=5)
