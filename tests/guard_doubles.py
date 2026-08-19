"""Shared test doubles and fixtures for the Arcjet guard surfaces.

Imported flat (``from guard_doubles import ...``) because ``tests/`` is on
sys.path for the suite, the same way ``helpers`` and ``fixtures`` already are.
"""

from __future__ import annotations

import pytest

from arcjet.guard._context import _correlation_id, _sequence_metadata


@pytest.fixture
def reset_sequence_context():
    """Guarantee a test starts and ends outside any sequence.

    ``arcjet_sequence`` restores on exit, so a well-behaved test cannot leak.
    A test that sets the ContextVar directly can — and a leaked correlation ID
    surfaces as an unrelated test failing somewhere else entirely.
    """
    id_token = _correlation_id.set(None)
    metadata_token = _sequence_metadata.set(None)
    try:
        yield
    finally:
        _sequence_metadata.reset(metadata_token)
        _correlation_id.reset(id_token)


from typing import Any, Optional, Sequence

from arcjet._metadata import Metadata
from arcjet.guard._rules import RuleWithInput
from arcjet.guard._types import Decision, Reason


class StubGuardClient:
    """A minimal in-memory guard client recording all calls.

    Configured to return a specific decision or raise an exception on guard
    calls. Both sync and async paths are exposed, so the checkpoint engine
    can test flavor routing.
    """

    def __init__(
        self,
        decision: Optional[Decision] = None,
        exception: Optional[Exception] = None,
    ):
        self.decision = decision
        self.exception = exception
        self.guards: list[dict[str, Any]] = []
        self.captures: list[dict[str, Any]] = []

    async def guard(
        self,
        rules: Sequence[RuleWithInput] = (),
        *,
        label: str,
        metadata: Optional[Metadata] = None,
        correlation_id: Optional[str] = None,
        actor: Optional[str] = None,
        inputs: Optional[dict[str, Any]] = None,
    ) -> Decision:
        if self.exception is not None:
            raise self.exception

        self.guards.append(
            dict(
                rules=rules,
                label=label,
                metadata=metadata,
                correlation_id=correlation_id,
                actor=actor,
                inputs=inputs,
            )
        )

        if self.decision is None:
            raise AssertionError("StubGuardClient not configured with a decision")
        return self.decision

    def guard_sync(
        self,
        rules: Sequence[RuleWithInput] = (),
        *,
        label: str,
        metadata: Optional[Metadata] = None,
        correlation_id: Optional[str] = None,
        actor: Optional[str] = None,
        inputs: Optional[dict[str, Any]] = None,
    ) -> Decision:
        if self.exception is not None:
            raise self.exception

        self.guards.append(
            dict(
                rules=rules,
                label=label,
                metadata=metadata,
                correlation_id=correlation_id,
                actor=actor,
                inputs=inputs,
            )
        )

        if self.decision is None:
            raise AssertionError("StubGuardClient not configured with a decision")
        return self.decision

    def capture(
        self,
        *,
        action: str,
        correlation_id: Optional[str] = None,
        decision_id: Optional[str] = None,
        metadata: Optional[Metadata] = None,
        **kwargs: Any,
    ) -> None:
        self.captures.append(
            dict(
                action=action,
                correlation_id=correlation_id,
                decision_id=decision_id,
                metadata=metadata,
                **kwargs,
            )
        )


def make_allow_decision(
    id: str = "gdec_test_allow",
    reason: Reason = "UNKNOWN",
    results: tuple[Any, ...] = (),
) -> Decision:
    """Create a clean ALLOW decision (not failed open)."""
    return Decision(
        conclusion="ALLOW",
        id=id,
        reason=reason,
        results=results,
    )


def make_deny_decision(
    id: str = "gdec_test_deny",
    reason: Reason = "RATE_LIMIT",
    results: tuple[Any, ...] = (),
) -> Decision:
    """Create a DENY decision."""
    return Decision(
        conclusion="DENY",
        id=id,
        reason=reason,
        results=results,
    )


class AsyncOnlyStubGuardClient:
    """A guard client with only async guard (no guard_sync)."""

    def __init__(
        self,
        decision: Optional[Decision] = None,
        exception: Optional[Exception] = None,
    ):
        self.decision = decision
        self.exception = exception
        self.guards: list[dict[str, Any]] = []

    async def guard(
        self,
        rules: Sequence[RuleWithInput] = (),
        *,
        label: str,
        metadata: Optional[Metadata] = None,
        correlation_id: Optional[str] = None,
        actor: Optional[str] = None,
        inputs: Optional[dict[str, Any]] = None,
    ) -> Decision:
        if self.exception is not None:
            raise self.exception

        self.guards.append(
            dict(
                rules=rules,
                label=label,
                metadata=metadata,
                correlation_id=correlation_id,
                actor=actor,
                inputs=inputs,
            )
        )

        if self.decision is None:
            raise AssertionError(
                "AsyncOnlyStubGuardClient not configured with a decision"
            )
        return self.decision


class SyncOnlyStubGuardClient:
    """A guard client with only a sync guard method (no async guard).

    The guard method is synchronous, matching ArcjetGuardSync.
    """

    def __init__(
        self,
        decision: Optional[Decision] = None,
        exception: Optional[Exception] = None,
    ):
        self.decision = decision
        self.exception = exception
        self.guards: list[dict[str, Any]] = []

    def guard(
        self,
        rules: Sequence[RuleWithInput] = (),
        *,
        label: str,
        metadata: Optional[Metadata] = None,
        correlation_id: Optional[str] = None,
        actor: Optional[str] = None,
        inputs: Optional[dict[str, Any]] = None,
    ) -> Decision:
        """Synchronous guard method, matching ArcjetGuardSync."""
        if self.exception is not None:
            raise self.exception

        self.guards.append(
            dict(
                rules=rules,
                label=label,
                metadata=metadata,
                correlation_id=correlation_id,
                actor=actor,
                inputs=inputs,
            )
        )

        if self.decision is None:
            raise AssertionError(
                "SyncOnlyStubGuardClient not configured with a decision"
            )
        return self.decision
