"""Unit tests for the in-memory test client.

Also the worked example of the pattern the docs recommend: a ``with`` block, or
a fixture wrapping one.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from arcjet.guard._registry import (
    capture,
    flush,
    flush_sync,
    guard,
    guard_sync,
    register_arcjet,
    registered_client,
    unregister_arcjet,
)
from arcjet.guard.testing import ArcjetTestClient, register_test_client


@pytest.fixture(autouse=True)
def _clear_registration():
    unregister_arcjet()
    try:
        yield
    finally:
        unregister_arcjet()


class TestRegisterTestClient:
    def test_registers_itself_so_free_calls_reach_it(self) -> None:
        with register_test_client() as arcjet:
            assert registered_client() is arcjet

    def test_the_with_block_unregisters_on_the_way_out(self) -> None:
        with register_test_client():
            pass

        assert registered_client() is None

    def test_it_unregisters_even_when_the_body_raises(self) -> None:
        with pytest.raises(ValueError):
            with register_test_client():
                raise ValueError("boom")

        # The whole reason to prefer `with` over a manual call.
        assert registered_client() is None

    def test_raises_when_a_client_is_already_registered(self) -> None:
        with register_test_client():
            # A leak from an earlier test would otherwise have this test assert
            # against the previous test's recorder.
            with pytest.raises(RuntimeError, match="already registered"):
                register_test_client()

    def test_unregister_is_safe_to_call_twice(self) -> None:
        arcjet = register_test_client()
        arcjet.unregister()
        arcjet.unregister()

        assert registered_client() is None

    def test_unregister_does_not_clear_somebody_elses_client(self) -> None:
        arcjet = register_test_client()
        arcjet.unregister()

        class _Other:
            async def guard(self, rules, **kwargs): ...
            def capture(self, **kwargs): ...
            async def flush(self, timeout_ms=None): ...

        other = _Other()
        register_arcjet(other)  # type: ignore[arg-type]
        arcjet.unregister()

        assert registered_client() is other


class TestRecordingCaptures:
    def test_records_a_capture_made_through_the_free_function(self) -> None:
        with register_test_client() as arcjet:
            capture(action="refund.issued", metadata={"invoice": "inv_1"})

            assert len(arcjet.captures) == 1
            assert arcjet.captures[0].action == "refund.issued"
            assert arcjet.captures[0].metadata == {"invoice": "inv_1"}

    def test_records_captures_in_call_order(self) -> None:
        with register_test_client() as arcjet:
            capture(action="first")
            capture(action="second")

            assert [c.action for c in arcjet.captures] == ["first", "second"]

    def test_preserves_nested_metadata_through_the_wire_encoding(self) -> None:
        with register_test_client() as arcjet:
            capture(
                action="order.placed", metadata={"items": [1, 2], "user": {"id": "u1"}}
            )

            assert arcjet.captures[0].metadata == {
                "items": [1, 2],
                "user": {"id": "u1"},
            }

    def test_keeps_ids_only_when_supplied(self) -> None:
        with register_test_client() as arcjet:
            capture(action="with", correlation_id="corr_1", decision_id="dec_1")
            capture(action="without")

            assert arcjet.captures[0].correlation_id == "corr_1"
            assert arcjet.captures[0].decision_id == "dec_1"
            assert arcjet.captures[1].correlation_id is None
            assert arcjet.captures[1].decision_id is None

    def test_records_occurred_at_when_supplied(self) -> None:
        occurred_at = datetime(2026, 8, 4, 12, 0, 0, tzinfo=timezone.utc)

        with register_test_client() as arcjet:
            capture(action="backfilled", occurred_at=occurred_at)

            assert arcjet.captures[0].occurred_at == occurred_at

    def test_drops_an_invalid_event_exactly_as_the_real_client_would(self) -> None:
        with register_test_client() as arcjet:
            # An empty action is rejected by the same validation the real client
            # runs. Recording the raw input instead would let this test pass
            # while the real client silently dropped the event in production.
            capture(action="")

            assert arcjet.captures == []

    def test_surfaces_encoding_warnings_on_the_recorded_event(self) -> None:
        with register_test_client() as arcjet:
            capture(action="lossy", metadata={"ok": "kept", "bad": {1, 2, 3}})  # type: ignore[dict-item]

            recorded = arcjet.captures[0]
            assert recorded.action == "lossy"
            assert recorded.metadata == {"ok": "kept"}
            assert recorded.warnings, "the dropped key should be reported"


class TestRecordingGuards:
    def test_records_an_async_guard_and_answers_fail_open(self) -> None:
        with register_test_client() as arcjet:
            decision = asyncio.run(guard([], label="tools.weather"))

            assert [g.label for g in arcjet.guards] == ["tools.weather"]
            # Fail-open rather than a plain ALLOW: no rule ran, and a plain
            # ALLOW would claim policy was evaluated.
            assert decision.conclusion == "ALLOW"
            assert decision.has_failed_open()

    def test_records_a_sync_guard_too(self) -> None:
        with register_test_client() as arcjet:
            decision = guard_sync([], label="tools.weather")

            assert [g.label for g in arcjet.guards] == ["tools.weather"]
            assert decision.has_failed_open()

    def test_records_the_metadata_and_correlation_id(self) -> None:
        with register_test_client() as arcjet:
            guard_sync([], label="x", metadata={"a": 1}, correlation_id="corr_1")

            assert arcjet.guards[0].metadata == {"a": 1}
            assert arcjet.guards[0].correlation_id == "corr_1"

    def test_both_flush_flavors_return(self) -> None:
        with register_test_client():
            asyncio.run(flush())
            flush_sync()


class TestFixturePattern:
    """The shape the docs recommend, exercised so it cannot rot."""

    @pytest.fixture
    def arcjet(self):
        with register_test_client() as client:
            yield client

    def test_a_fixture_wrapping_the_context_manager_works(
        self, arcjet: ArcjetTestClient
    ) -> None:
        capture(action="from.fixture")

        assert arcjet.captures[0].action == "from.fixture"
