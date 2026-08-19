"""An in-memory Arcjet guard client for application tests.

Registers a client that records what was called and talks to nothing.  It exists
so a test can assert that application code captured the event it was supposed to,
without a key, a network, or a running server.

This is deliberately not a mock server.  It records calls and answers guards
uniformly; it does not let a test stub per-rule verdicts.  Simulating real
decisions is a much larger job and is not what this is for.

Public module, unlike its ``_``-prefixed siblings, but kept separate so
``import arcjet.guard`` never loads it.

Example:
    ::

        from arcjet.guard.testing import register_test_client
        from myapp.billing import refund

        async def test_refund_captures_an_event():
            with register_test_client() as arcjet:
                await refund("inv_1")

                assert arcjet.captures[0].action == "refund.issued"

    As a fixture, which is usually where this belongs::

        @pytest.fixture
        def arcjet():
            with register_test_client() as client:
                yield client
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import TracebackType
from typing import Any, Mapping, Optional, Sequence

from arcjet._metadata import Metadata

from ._capture import normalize_capture_event
from ._client import _make_error_decision, _shared_with_copies
from ._policy_input import PolicyInputMap
from ._registry import register_arcjet_for_testing, unregister_arcjet_if
from ._rules import RuleWithInput
from ._types import ArcjetWarning, Decision

__all__ = [
    "ArcjetTestClient",
    "RecordedCapture",
    "RecordedGuard",
    "register_test_client",
]


def _ignore(code: str, count: int = 1) -> None:
    """Drop diagnostics instead of logging them.

    A test that captures something invalid asserts on the recorded event's
    ``warnings``, which say the same thing in the place the test is already
    looking.  Logging as well would put warnings in the output of every test
    that exercises a drop deliberately.
    """


@dataclass(frozen=True, slots=True)
class RecordedCapture:
    """A capture event recorded by an :class:`ArcjetTestClient`."""

    action: str
    """What the application said it did."""
    occurred_at: datetime
    """The call's timestamp, or when it was recorded."""
    metadata: Metadata
    """Metadata as it would have been sent, decoded back from the wire."""
    warnings: tuple[ArcjetWarning, ...]
    """Anything the SDK dropped or rewrote while encoding this event."""
    correlation_id: Optional[str] = None
    """Present only when the call supplied one."""
    decision_id: Optional[str] = None
    """Present only when the call supplied one."""


@dataclass(frozen=True, slots=True)
class RecordedGuard:
    """A guard call recorded by an :class:`ArcjetTestClient`."""

    label: str
    rules: tuple[RuleWithInput, ...]
    metadata: Optional[Metadata] = None
    correlation_id: Optional[str] = None
    actor: Optional[str] = None
    """Who the call said was acting.  Present only when the call supplied one."""
    inputs: Optional[PolicyInputMap] = None
    """Inputs offered for remote policy evaluation.

    The caller's own mapping, not a copy — unlike ``rules``, which is
    snapshotted into a tuple.  Mutating the mapping after the call changes what
    this record reports.  Held by reference so a caller can assert that a
    checkpoint passed its inputs through without altering them.
    """


@dataclass(slots=True)
class ArcjetTestClient:
    """An in-memory client that records calls instead of sending them.

    Satisfies both :class:`~arcjet.guard.ArcjetGuard` and
    :class:`~arcjet.guard.ArcjetGuardSync` structurally by offering ``guard``,
    ``guard_sync``, ``capture``, ``flush`` and ``flush_sync``, so either free
    call reaches it.  That is the one place the sync/async split is bridged: a
    real client can only be one or the other, but a recorder has no I/O to make
    the distinction meaningful.
    """

    captures: list[RecordedCapture] = field(default_factory=list)
    """Captured events, in call order."""
    guards: list[RecordedGuard] = field(default_factory=list)
    """Guard calls, in call order."""

    # Named to match the real clients, so `_registry._diagnose` finds it and
    # stays quiet rather than falling back to a logger.
    _diagnose: Any = field(default=_ignore, repr=False)

    # Shared with a copy for the same reason a real client is, though not the
    # same cause: a recorder has nothing uncopyable in it, so a deep copy would
    # succeed and quietly fork the recording — the calls would land on the copy
    # while the test asserts against this one. Whatever holds a client, holding
    # a copy of it has to mean holding the client.
    __deepcopy__ = _shared_with_copies

    def unregister(self) -> None:
        """Unregister this client.

        Compare-and-clear, so a stale handle cannot unregister a client that
        replaced this one.  Safe to call twice, so it also works from a teardown
        that runs after a failing test.  ``with`` calls this on the way out.
        """
        unregister_arcjet_if(self)  # type: ignore[arg-type]  # structural double

    def __enter__(self) -> ArcjetTestClient:
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        # Unregisters and nothing else. There is no transport and no delivery
        # queue, so there is nothing to drain — which is why this is a plain
        # context manager rather than an async one that would imply otherwise.
        self.unregister()

    def capture(
        self,
        *,
        action: str,
        correlation_id: Optional[str] = None,
        decision_id: Optional[str] = None,
        occurred_at: Optional[datetime] = None,
        metadata: Optional[Metadata] = None,
    ) -> None:
        """Record a capture, normalized exactly as the real client would.

        Going through :func:`normalize_capture_event` is what makes a test
        honest: a ``capture()`` the real client would drop is not recorded here
        either, and the warnings it would have attached are on the record.
        """
        event = normalize_capture_event(
            action=action,
            correlation_id=correlation_id,
            decision_id=decision_id,
            occurred_at=occurred_at,
            metadata=metadata,
            diagnose=_ignore,
        )
        if event is None:
            return

        self.captures.append(
            RecordedCapture(
                action=event.action,
                correlation_id=event.correlation_id or None,
                decision_id=event.decision_id or None,
                occurred_at=datetime.fromtimestamp(
                    event.occurred_at_unix_ms / 1000, tz=timezone.utc
                ),
                metadata=_decode_metadata(event.metadata_json),
                warnings=tuple(
                    ArcjetWarning(code=w.code, message=w.message)
                    for w in event.local_warnings
                ),
            )
        )

    async def guard(
        self,
        rules: Sequence[RuleWithInput] = (),
        *,
        label: str,
        metadata: Optional[Metadata] = None,
        correlation_id: Optional[str] = None,
        actor: Optional[str] = None,
        inputs: Optional[PolicyInputMap] = None,
    ) -> Decision:
        """Record the guard call and answer fail-open.

        A fail-open ALLOW rather than a plain one, because no rule was
        evaluated and a plain ALLOW would claim otherwise.  Note this means the
        decision reports an error, so helpers that fail closed on an errored
        decision will deny against this client.
        """
        return self._record_guard(rules, label, metadata, correlation_id, actor, inputs)

    def guard_sync(
        self,
        rules: Sequence[RuleWithInput] = (),
        *,
        label: str,
        metadata: Optional[Metadata] = None,
        correlation_id: Optional[str] = None,
        actor: Optional[str] = None,
        inputs: Optional[PolicyInputMap] = None,
    ) -> Decision:
        """The blocking counterpart of :meth:`guard`."""
        return self._record_guard(rules, label, metadata, correlation_id, actor, inputs)

    def _record_guard(
        self,
        rules: Sequence[RuleWithInput],
        label: str,
        metadata: Optional[Metadata],
        correlation_id: Optional[str],
        actor: Optional[str],
        inputs: Optional[PolicyInputMap],
    ) -> Decision:
        self.guards.append(
            RecordedGuard(
                label=label,
                rules=tuple(rules),
                metadata=metadata,
                correlation_id=correlation_id,
                actor=actor,
                inputs=inputs,
            )
        )
        return _make_error_decision(
            "guard() was called on the Arcjet test client; no rules ran"
        )

    async def flush(self, timeout_ms: Optional[int] = None) -> None:
        """Resolve immediately — there is no queue to drain."""

    def flush_sync(self, timeout_ms: Optional[int] = None) -> None:
        """Return immediately — there is no queue to drain."""


def register_test_client() -> ArcjetTestClient:
    """Register an in-memory client that records guard and capture calls.

    The one place launching and registering are a single act — a test that
    wanted them apart would use ``launch_arcjet()`` directly.

    Raises:
        RuntimeError: If a client is already registered.  In an application a
            second registration warns and carries on, because it should be
            survivable; in a test it means an earlier test leaked one, and every
            assertion here would silently read the wrong recorder.

    Returns:
        The client, which is also a context manager, so ``with`` unregisters it.
    """
    client = ArcjetTestClient()
    # Checked and set under one lock rather than here, so two concurrent calls
    # cannot both succeed while only one of them is actually registered.
    register_arcjet_for_testing(client)  # type: ignore[arg-type]  # structural double
    return client


def _decode_metadata(metadata_json: Mapping[str, str]) -> Metadata:
    """Decode the wire form back to what a test would assert against.

    Takes a ``Mapping`` rather than a ``dict`` because the wire event carries a
    protobuf map container, not a plain dict.
    """
    decoded: dict[str, Any] = {}
    for key, value in metadata_json.items():
        try:
            decoded[key] = json.loads(value)
        except ValueError:
            # Unreachable via `capture()`, which encodes these itself. Kept so a
            # malformed record degrades to a visible raw string in an assertion
            # rather than an exception from the recorder.
            decoded[key] = value
    return decoded
