"""Tests for the checkpoint engine and guard_action surfaces.

Comprehensive coverage of the four outcomes, flavor routing, capture behavior,
and ambient context handling.
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
from typing import Any

import pytest
from guard_doubles import (
    AsyncOnlyStubGuardClient,
    StubGuardClient,
    SyncOnlyStubGuardClient,
    make_allow_decision,
    make_deny_decision,
)

from arcjet.guard import (
    ArcjetDeniedError,
    ArcjetUnavailableError,
    arcjet_sequence,
    capture_action,
    guard_action,
    guard_action_sync,
)
from arcjet.guard._checkpoint import (
    ResolvedInputs,
    run_checkpoint,
    run_checkpoint_sync,
)
from arcjet.guard._types import RuleResultError


class TestAllowOutcomeSync:
    """A clean ALLOW runs the callable and returns its value unchanged."""

    def test_allow_runs_callable(self, reset_sequence_context):
        client = StubGuardClient(decision=make_allow_decision())
        sentinel = object()
        call_count = 0

        def fn():
            nonlocal call_count
            call_count += 1
            return sentinel

        result = run_checkpoint_sync(
            fn,
            action="thing.done",
            guard=client,
        )

        assert call_count == 1
        assert result is sentinel
        assert len(client.captures) == 1
        assert client.captures[0]["metadata"]["outcome"] == "success"

    def test_allow_with_metadata_merging(self, reset_sequence_context):
        """Passed metadata is present in the success capture."""
        client = StubGuardClient(decision=make_allow_decision())

        result = run_checkpoint_sync(
            lambda: "value",
            action="thing.done",
            guard=client,
            metadata={"request": "id"},
        )

        assert result == "value"
        assert client.captures[0]["metadata"]["request"] == "id"
        assert client.captures[0]["metadata"]["outcome"] == "success"


class TestAllowOutcomeAsync:
    """A clean ALLOW runs the awaitable and returns its value unchanged."""

    def test_allow_runs_callable(self, reset_sequence_context):
        async def test():
            client = StubGuardClient(decision=make_allow_decision())
            sentinel = object()
            call_count = 0

            async def fn():
                nonlocal call_count
                call_count += 1
                return sentinel

            result = await run_checkpoint(
                fn,
                action="thing.done",
                guard=client,
            )

            assert call_count == 1
            assert result is sentinel
            assert len(client.captures) == 1
            assert client.captures[0]["metadata"]["outcome"] == "success"

        asyncio.run(test())


class TestDenyOutcomeSync:
    """A DENY raises ArcjetDeniedError, callable never runs."""

    def test_deny_raises(self, reset_sequence_context):
        decision = make_deny_decision()
        client = StubGuardClient(decision=decision)
        call_count = 0

        def fn():
            nonlocal call_count
            call_count += 1
            return "value"

        with pytest.raises(ArcjetDeniedError) as exc_info:
            run_checkpoint_sync(
                fn,
                action="thing.done",
                guard=client,
            )

        assert call_count == 0
        error = exc_info.value
        assert error.action == "thing.done"
        assert error.decision is decision
        assert len(client.captures) == 1
        assert client.captures[0]["metadata"]["outcome"] == "denied"

    def test_deny_always_blocks_on_guard_error_allow(self, reset_sequence_context):
        """DENY blocks even with on_guard_error='allow'."""
        decision = make_deny_decision()
        client = StubGuardClient(decision=decision)
        call_count = 0

        def fn():
            nonlocal call_count
            call_count += 1
            return "value"

        with pytest.raises(ArcjetDeniedError):
            run_checkpoint_sync(
                fn,
                action="thing.done",
                guard=client,
                on_guard_error="allow",
            )

        assert call_count == 0
        assert len(client.captures) == 1
        assert client.captures[0]["metadata"]["outcome"] == "denied"


class TestDenyOutcomeAsync:
    """A DENY raises ArcjetDeniedError and the awaitable never runs."""

    def test_deny_raises(self, reset_sequence_context):
        async def test():
            decision = make_deny_decision()
            client = StubGuardClient(decision=decision)
            call_count = 0

            async def fn():
                nonlocal call_count
                call_count += 1
                return "value"

            with pytest.raises(ArcjetDeniedError) as exc_info:
                await run_checkpoint(
                    fn,
                    action="thing.done",
                    guard=client,
                )

            assert call_count == 0
            assert exc_info.value.decision is decision
            assert exc_info.value.action == "thing.done"

        asyncio.run(test())

    def test_deny_always_blocks_on_guard_error_allow(self, reset_sequence_context):
        """DENY blocks even with on_guard_error='allow'."""

        async def test():
            decision = make_deny_decision()
            client = StubGuardClient(decision=decision)
            call_count = 0

            async def fn():
                nonlocal call_count
                call_count += 1
                return "value"

            with pytest.raises(ArcjetDeniedError):
                await run_checkpoint(
                    fn,
                    action="thing.done",
                    guard=client,
                    on_guard_error="allow",
                )

            assert call_count == 0
            assert len(client.captures) == 1
            assert client.captures[0]["metadata"]["outcome"] == "denied"

        asyncio.run(test())


class TestGuardRaisesSync:
    """Guard call raising under on_guard_error='deny' raises unavailability."""

    def test_guard_raise_default_deny(self, reset_sequence_context):
        exc = ValueError("network error")
        client = StubGuardClient(exception=exc)
        call_count = 0

        def fn():
            nonlocal call_count
            call_count += 1
            return "value"

        with pytest.raises(ArcjetUnavailableError) as exc_info:
            run_checkpoint_sync(
                fn,
                action="thing.done",
                guard=client,
            )

        assert call_count == 0
        error = exc_info.value
        assert error.action == "thing.done"
        assert error.__cause__ is exc
        assert len(client.captures) == 1
        assert client.captures[0]["metadata"]["outcome"] == "unavailable"

    def test_guard_raise_allow_proceeds(self, reset_sequence_context):
        """Guard raising with on_guard_error='allow' runs the callable."""
        exc = ValueError("network error")
        client = StubGuardClient(exception=exc)
        call_count = 0

        def fn():
            nonlocal call_count
            call_count += 1
            return "value"

        result = run_checkpoint_sync(
            fn,
            action="thing.done",
            guard=client,
            on_guard_error="allow",
        )

        assert call_count == 1
        assert result == "value"
        # Capture the success, not unavailable
        # Not `unavailable`, which would mean the action was blocked, and
        # not `success`, which would claim policy judged it.
        assert client.captures[0]["metadata"]["outcome"] == "degraded"


class TestGuardRaisesAsync:
    """A raising guard call under the deny default raises unavailability."""

    def test_guard_raise_default_deny(self, reset_sequence_context):
        async def test():
            exc = ValueError("network error")
            client = StubGuardClient(exception=exc)
            call_count = 0

            async def fn():
                nonlocal call_count
                call_count += 1
                return "value"

            with pytest.raises(ArcjetUnavailableError) as exc_info:
                await run_checkpoint(
                    fn,
                    action="thing.done",
                    guard=client,
                )

            assert call_count == 0
            error = exc_info.value
            assert error.action == "thing.done"
            assert error.__cause__ is exc
            assert len(client.captures) == 1
            assert client.captures[0]["metadata"]["outcome"] == "unavailable"

        asyncio.run(test())


class TestFailedOpenSync:
    """A decision with has_failed_open() true raises unavailability."""

    def test_failed_open_raises_default(self, reset_sequence_context):
        # Build a failed-open decision: ALLOW with an error result
        error_result = RuleResultError(code="ERR_UNKNOWN", message="something broke")
        decision = make_allow_decision(results=(error_result,))

        # Verify the fixture is actually failed open
        assert decision.has_failed_open() is True

        client = StubGuardClient(decision=decision)
        call_count = 0

        def fn():
            nonlocal call_count
            call_count += 1
            return "value"

        with pytest.raises(ArcjetUnavailableError):
            run_checkpoint_sync(
                fn,
                action="thing.done",
                guard=client,
            )

        assert call_count == 0
        assert client.captures[0]["metadata"]["outcome"] == "unavailable"

    def test_failed_open_allow_proceeds(self, reset_sequence_context):
        """Failed open with on_guard_error='allow' runs the callable."""
        error_result = RuleResultError(code="ERR_UNKNOWN", message="something broke")
        decision = make_allow_decision(results=(error_result,))

        client = StubGuardClient(decision=decision)
        call_count = 0

        def fn():
            nonlocal call_count
            call_count += 1
            return "value"

        result = run_checkpoint_sync(
            fn,
            action="thing.done",
            guard=client,
            on_guard_error="allow",
        )

        assert call_count == 1
        assert result == "value"
        # The action ran only because on_guard_error is 'allow', and the
        # decision failed open, so policy judged none of it.
        assert client.captures[0]["metadata"]["outcome"] == "degraded"


class TestErrorOutcomeSync:
    """When the callable raises, emit error and re-raise unchanged."""

    def test_callable_error_emits_error(self, reset_sequence_context):
        client = StubGuardClient(decision=make_allow_decision())
        sentinel_exc = ValueError("boom")
        call_count = 0

        def fn():
            nonlocal call_count
            call_count += 1
            raise sentinel_exc

        with pytest.raises(ValueError) as exc_info:
            run_checkpoint_sync(
                fn,
                action="thing.done",
                guard=client,
            )

        assert call_count == 1
        assert exc_info.value is sentinel_exc
        assert len(client.captures) == 1
        assert client.captures[0]["metadata"]["outcome"] == "error"

    def test_deny_short_circuits_before_callable(self, reset_sequence_context):
        """A DENY raises before the callable, so only the denied capture is emitted."""
        decision = make_deny_decision()
        client = StubGuardClient(decision=decision)

        def fn():
            raise ValueError("boom")

        with pytest.raises(ArcjetDeniedError):
            run_checkpoint_sync(
                fn,
                action="thing.done",
                guard=client,
            )

        # Only the denied capture, not the error capture
        assert len(client.captures) == 1
        assert client.captures[0]["metadata"]["outcome"] == "denied"


class TestErrorOutcomeAsync:
    """When the awaitable raises, emit error and re-raise it unchanged."""

    def test_callable_error_emits_error(self, reset_sequence_context):
        async def test():
            client = StubGuardClient(decision=make_allow_decision())
            sentinel_exc = ValueError("boom")

            async def fn():
                raise sentinel_exc

            with pytest.raises(ValueError) as exc_info:
                await run_checkpoint(
                    fn,
                    action="thing.done",
                    guard=client,
                )

            assert exc_info.value is sentinel_exc
            assert client.captures[0]["metadata"]["outcome"] == "error"

        asyncio.run(test())


class TestCaptureMetadataSync:
    """Success capture includes metadata and decision_id."""

    def test_capture_includes_decision_id(self, reset_sequence_context):
        decision = make_allow_decision(id="gdec_abc123")
        client = StubGuardClient(decision=decision)

        run_checkpoint_sync(
            lambda: None,
            action="thing.done",
            guard=client,
        )

        assert client.captures[0]["decision_id"] == "gdec_abc123"

    def test_capture_empty_decision_id_becomes_none(self, reset_sequence_context):
        """Empty decision id should be suppressed as None."""
        decision = make_allow_decision(id="")
        client = StubGuardClient(decision=decision)

        run_checkpoint_sync(
            lambda: None,
            action="thing.done",
            guard=client,
        )

        assert client.captures[0]["decision_id"] is None

    def test_capture_includes_correlation_id(self, reset_sequence_context):
        decision = make_allow_decision()
        client = StubGuardClient(decision=decision)

        run_checkpoint_sync(
            lambda: None,
            action="thing.done",
            guard=client,
            correlation_id="corr-123",
        )

        assert client.captures[0]["correlation_id"] == "corr-123"

    def test_capture_with_sequence_context(self, reset_sequence_context):
        """Inside arcjet_sequence, capture inherits the correlation ID."""
        decision = make_allow_decision()
        client = StubGuardClient(decision=decision)

        with arcjet_sequence(correlation_id="seq-456"):
            run_checkpoint_sync(
                lambda: None,
                action="thing.done",
                guard=client,
            )

        assert client.captures[0]["correlation_id"] == "seq-456"

    def test_outcome_not_overridable(self, reset_sequence_context):
        """Outcome in metadata is applied last and cannot be overridden."""
        decision = make_allow_decision()
        client = StubGuardClient(decision=decision)

        run_checkpoint_sync(
            lambda: None,
            action="thing.done",
            guard=client,
            metadata={"outcome": "fake_value"},
        )

        # The engine's outcome wins
        assert client.captures[0]["metadata"]["outcome"] == "success"


class TestDeniedCaptureSync:
    """A denied checkpoint emits outcome='denied'."""

    def test_denied_capture(self, reset_sequence_context):
        decision = make_deny_decision()
        client = StubGuardClient(decision=decision)

        with pytest.raises(ArcjetDeniedError):
            run_checkpoint_sync(
                lambda: None,
                action="thing.done",
                guard=client,
            )

        assert len(client.captures) == 1
        assert client.captures[0]["metadata"]["outcome"] == "denied"


class TestUnavailableCaptureSync:
    """Unevaluated policy emits outcome='unavailable'."""

    def test_guard_raise_unavailable_capture(self, reset_sequence_context):
        exc = ValueError("network error")
        client = StubGuardClient(exception=exc)

        with pytest.raises(ArcjetUnavailableError):
            run_checkpoint_sync(
                lambda: None,
                action="thing.done",
                guard=client,
            )

        assert client.captures[0]["metadata"]["outcome"] == "unavailable"
        # No decision when guard raised
        assert client.captures[0]["decision_id"] is None

    def test_failed_open_unavailable_capture(self, reset_sequence_context):
        error_result = RuleResultError(code="ERR_UNKNOWN", message="something broke")
        decision = make_allow_decision(results=(error_result,))

        client = StubGuardClient(decision=decision)

        with pytest.raises(ArcjetUnavailableError):
            run_checkpoint_sync(
                lambda: None,
                action="thing.done",
                guard=client,
            )

        assert client.captures[0]["metadata"]["outcome"] == "unavailable"
        # Failed open still has a decision
        assert client.captures[0]["decision_id"] is not None


class TestOutsideSequenceSync:
    """Checkpoints still evaluate outside any sequence."""

    def test_checkpoint_outside_sequence(self, reset_sequence_context):
        decision = make_allow_decision()
        client = StubGuardClient(decision=decision)

        run_checkpoint_sync(
            lambda: None,
            action="thing.done",
            guard=client,
        )

        # No correlation_id from sequence
        assert client.captures[0]["correlation_id"] is None


class TestGuardActionSync:
    """guard_action_sync guards an arbitrary callable."""

    def test_guard_action_sync_allow(self, reset_sequence_context):
        client = StubGuardClient(decision=make_allow_decision())

        result = guard_action_sync(
            lambda: "value",
            action="thing.done",
            guard=client,  # type: ignore[arg-type]
        )

        assert result == "value"
        assert len(client.captures) == 1

    def test_guard_action_sync_deny(self, reset_sequence_context):
        client = StubGuardClient(decision=make_deny_decision())

        with pytest.raises(ArcjetDeniedError):
            guard_action_sync(
                lambda: "value",
                action="thing.done",
                guard=client,  # type: ignore[arg-type]
            )


class TestGuardActionAsync:
    """guard_action guards an arbitrary callable."""

    def test_guard_action_allow(self, reset_sequence_context):
        async def async_fn():
            return "value"

        async def test():
            client = StubGuardClient(decision=make_allow_decision())

            result = await guard_action(
                async_fn,
                action="thing.done",
                guard=client,  # type: ignore[arg-type]
            )

            assert result == "value"
            assert len(client.captures) == 1

        asyncio.run(test())


class TestRegisteredClientSync:
    """guard=None uses registered client."""

    def test_registered_client_with_stub(self, reset_sequence_context):
        """With a registered stub client, guard=None reaches it."""
        client = StubGuardClient(decision=make_allow_decision())

        from arcjet.guard._registry import (
            register_arcjet_for_testing,
            unregister_arcjet_if,
        )

        register_arcjet_for_testing(client)  # type: ignore[arg-type]
        try:
            result = guard_action_sync(
                lambda: "value",
                action="thing.done",
                guard=None,
            )
            assert result == "value"
            assert len(client.guards) == 1
        finally:
            unregister_arcjet_if(client)  # type: ignore[arg-type]

    def test_no_registered_client_deny_default(self, reset_sequence_context):
        """With nothing registered, fails open, then on_guard_error='deny' raises."""
        with pytest.raises(ArcjetUnavailableError):
            guard_action_sync(
                lambda: "value",
                action="thing.done",
                guard=None,
            )

    def test_no_registered_client_allow_mode(self, reset_sequence_context):
        """With nothing registered, on_guard_error='allow' runs it."""
        result = guard_action_sync(
            lambda: "value",
            action="thing.done",
            guard=None,
            on_guard_error="allow",
        )

        assert result == "value"


class TestCaptureFailureSync:
    """Capture failures must not fail the action."""

    def test_capture_failure_on_success(self, reset_sequence_context):
        """If capture raises, success still returns the value."""
        client = StubGuardClient(decision=make_allow_decision())

        def failing_capture(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("capture broken")

        client.capture = failing_capture  # type: ignore[method-assign]
        sentinel = object()

        result = run_checkpoint_sync(
            lambda: sentinel,
            action="thing.done",
            guard=client,
        )

        assert result is sentinel

    def test_capture_failure_on_deny(self, reset_sequence_context):
        """If capture raises on deny, the deny error is still raised."""
        client = StubGuardClient(decision=make_deny_decision())

        def failing_capture(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("capture broken")

        client.capture = failing_capture  # type: ignore[method-assign]

        with pytest.raises(ArcjetDeniedError):
            run_checkpoint_sync(
                lambda: "value",
                action="thing.done",
                guard=client,
            )


class TestEmptyRulesSync:
    """Empty rules still contact Guard."""

    def test_empty_rules_calls_guard(self, reset_sequence_context):
        client = StubGuardClient(decision=make_allow_decision())

        run_checkpoint_sync(
            lambda: None,
            action="thing.done",
            guard=client,
            rules=(),
        )

        assert len(client.guards) == 1
        assert client.guards[0]["rules"] == ()


class TestWrongFlavorSync:
    """Passing an async client to sync raises TypeError -> unavailability."""

    def test_async_client_to_sync_raises_unavailability(self, reset_sequence_context):
        """An async-only client has no guard_sync, raising TypeError."""
        client = AsyncOnlyStubGuardClient(decision=make_allow_decision())

        with pytest.raises(ArcjetUnavailableError):
            run_checkpoint_sync(
                lambda: None,
                action="thing.done",
                guard=client,
            )

    @pytest.mark.filterwarnings("error::RuntimeWarning")
    def test_wrong_flavor_no_coroutine_warning(self, reset_sequence_context):
        """Passing an async client to sync raises unavailability."""
        client = AsyncOnlyStubGuardClient(decision=make_allow_decision())

        with pytest.raises(ArcjetUnavailableError):
            run_checkpoint_sync(
                lambda: None,
                action="thing.done",
                guard=client,
            )


class TestWrongFlavorAsync:
    """Passing a sync client to async raises TypeError -> unavailability."""

    def test_sync_client_to_async_raises_unavailability(self, reset_sequence_context):
        async def test():
            client = SyncOnlyStubGuardClient(decision=make_allow_decision())

            with pytest.raises(ArcjetUnavailableError):
                await run_checkpoint(
                    async_fn,
                    action="thing.done",
                    guard=client,
                )

            # The blocking method is rejected on sight, so it is never invoked.
            # Awaiting its return value would raise too, but only after the
            # call had already happened.
            assert client.guards == []

        async def async_fn():
            return None

        asyncio.run(test())


class TestInputsPassThroughSync:
    """inputs pass through the engine unchanged."""

    def test_inputs_identity_preserved(self, reset_sequence_context):
        """The inputs mapping is passed to guard as-is."""
        from arcjet.guard import local_input

        decision = make_allow_decision()
        client = StubGuardClient(decision=decision)
        inputs = {"message": local_input.string("hello")}

        result_value = object()

        run_checkpoint_sync(
            lambda: result_value,
            action="thing.done",
            guard=client,
            inputs=inputs,
        )

        # The exact same mapping object was passed to the guard
        assert client.guards[0]["inputs"] is inputs

    def test_return_value_identity_preserved(self, reset_sequence_context):
        """The callable's return value is returned unchanged."""
        decision = make_allow_decision()
        client = StubGuardClient(decision=decision)
        sentinel = object()

        result = run_checkpoint_sync(
            lambda: sentinel,
            action="thing.done",
            guard=client,
        )

        assert result is sentinel


class TestInputsPassThroughAsync:
    """Inputs pass through the async engine unchanged."""

    def test_inputs_identity_preserved(self, reset_sequence_context):
        from arcjet.guard import local_input

        async def async_fn():
            return None

        async def test():
            decision = make_allow_decision()
            client = StubGuardClient(decision=decision)
            inputs = {"message": local_input.string("hello")}

            await run_checkpoint(
                async_fn,
                action="thing.done",
                guard=client,
                inputs=inputs,
            )

            assert client.guards[0]["inputs"] is inputs

        asyncio.run(test())


class TestNoLangChainSync:
    """guard_action_sync works without LangChain imported."""

    def test_no_langchain_import(self):
        """In a subprocess with LangChain blocked, guard_action_sync works."""
        code = """
import sys

class BlockLangChain:
    def find_module(self, fullname, path=None):
        if fullname.startswith("langchain"):
            raise ImportError(f"LangChain is blocked")
        return None

    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith("langchain"):
            raise ImportError(f"LangChain is blocked")
        return None

sys.meta_path.insert(0, BlockLangChain())

# Now import arcjet.guard
from arcjet.guard import guard_action_sync

# And use it
result = guard_action_sync(
    lambda: "success",
    action="test",
    guard=None,
    on_guard_error="allow",
)

assert result == "success"
assert not [m for m in sys.modules if m.startswith("langchain")]
print("ok")
"""
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "ok" in result.stdout


class TestPrepareSync:
    """Prepare callable is invoked inside the try block."""

    def test_prepare_raises_becomes_unavailable(self, reset_sequence_context):
        client = StubGuardClient(decision=make_allow_decision())
        exc = ValueError("prepare failed")

        def prepare():
            raise exc

        with pytest.raises(ArcjetUnavailableError) as exc_info:
            run_checkpoint_sync(
                lambda: None,
                action="thing.done",
                guard=client,
                prepare=prepare,
            )

        assert exc_info.value.__cause__ is exc

    def test_prepared_actor_and_inputs_reach_guard(self, reset_sequence_context):
        """What prepare() returns is what gets evaluated."""
        from arcjet.guard import local_input

        client = StubGuardClient(decision=make_allow_decision())
        inputs = {"message": local_input.string("hello")}

        def prepare():
            return ResolvedInputs(actor="u_1", inputs=inputs)

        run_checkpoint_sync(
            lambda: "value",
            action="thing.done",
            guard=client,
            prepare=prepare,
            actor="ignored",
            inputs={"ignored": local_input.string("no")},
        )

        assert len(client.guards) == 1
        assert client.guards[0]["actor"] == "u_1"
        assert client.guards[0]["inputs"] is inputs


class TestGuardCallArgumentsSync:
    """What the engine sends to guard(), not just what it captures."""

    def test_guard_receives_label_correlation_metadata_and_actor(
        self, reset_sequence_context
    ):
        client = StubGuardClient(decision=make_allow_decision())

        with arcjet_sequence(correlation_id="corr-1"):
            run_checkpoint_sync(
                lambda: "value",
                action="checkout.refund",
                guard=client,
                actor="u_1",
                metadata={"tier": "pro"},
            )

        assert len(client.guards) == 1
        recorded = client.guards[0]
        assert recorded["label"] == "checkout.refund"
        assert recorded["correlation_id"] == "corr-1"
        assert recorded["metadata"] == {"tier": "pro"}
        assert recorded["actor"] == "u_1"


class TestMetadataSync:
    """Metadata from arcjet_sequence is inherited."""

    def test_sequence_metadata_inherited(self, reset_sequence_context):
        decision = make_allow_decision()
        client = StubGuardClient(decision=decision)

        with arcjet_sequence(
            correlation_id="seq-123",
            metadata={"user_id": "u_1"},
        ):
            run_checkpoint_sync(
                lambda: None,
                action="thing.done",
                guard=client,
            )

        # Sequence metadata is in the capture
        assert client.captures[0]["metadata"]["user_id"] == "u_1"
        assert client.captures[0]["metadata"]["outcome"] == "success"


class TestCaptureActionSync:
    """capture_action guards an action with sequence context."""

    def test_capture_action_outside_sequence(self, reset_sequence_context):
        """capture_action works outside a sequence."""

        # Should not raise even with no sequence
        capture_action(action="item.created")

    def test_capture_action_inside_sequence_inherits_correlation_id(
        self, reset_sequence_context
    ):
        """Omitted correlation_id is inherited from sequence."""

        client = StubGuardClient()
        client.captures = []

        def capture_impl(
            action: str,
            correlation_id: Any = None,
            decision_id: Any = None,
            occurred_at: Any = None,
            metadata: Any = None,
        ) -> None:
            client.captures.append(
                dict(
                    action=action,
                    correlation_id=correlation_id,
                    decision_id=decision_id,
                    metadata=metadata,
                )
            )

        client.capture = capture_impl  # type: ignore[assignment]

        # Simulate registration
        from arcjet.guard import _registry as reg

        old_registered = reg._registered
        try:
            reg._registered = client  # type: ignore[assignment]

            with arcjet_sequence(correlation_id="seq-456"):
                capture_action(action="item.created")

            assert len(client.captures) == 1
            assert client.captures[0]["correlation_id"] == "seq-456"
        finally:
            reg._registered = old_registered

    def test_capture_action_explicit_correlation_id_wins(self, reset_sequence_context):
        """Explicit correlation_id overrides sequence."""
        from arcjet.guard import _registry as reg

        client = StubGuardClient()
        client.captures = []

        def capture_impl(
            action: str,
            correlation_id: Any = None,
            decision_id: Any = None,
            occurred_at: Any = None,
            metadata: Any = None,
        ) -> None:
            client.captures.append(
                dict(
                    action=action,
                    correlation_id=correlation_id,
                    decision_id=decision_id,
                    metadata=metadata,
                )
            )

        client.capture = capture_impl  # type: ignore[assignment]

        old_registered = reg._registered
        try:
            reg._registered = client  # type: ignore[assignment]

            with arcjet_sequence(correlation_id="seq-456"):
                capture_action(action="item.created", correlation_id="explicit-789")

            assert len(client.captures) == 1
            assert client.captures[0]["correlation_id"] == "explicit-789"
        finally:
            reg._registered = old_registered

    def test_capture_action_metadata_merges_with_sequence(self, reset_sequence_context):
        """Omitted metadata merges with sequence metadata."""
        from arcjet.guard import _registry as reg

        client = StubGuardClient()
        client.captures = []

        def capture_impl(
            action: str,
            correlation_id: Any = None,
            decision_id: Any = None,
            occurred_at: Any = None,
            metadata: Any = None,
        ) -> None:
            client.captures.append(
                dict(
                    action=action,
                    correlation_id=correlation_id,
                    decision_id=decision_id,
                    metadata=metadata,
                )
            )

        client.capture = capture_impl  # type: ignore[assignment]

        old_registered = reg._registered
        try:
            reg._registered = client  # type: ignore[assignment]

            with arcjet_sequence(correlation_id="seq-789", metadata={"tenant": "acme"}):
                capture_action(action="item.created")

            assert len(client.captures) == 1
            assert client.captures[0]["metadata"]["tenant"] == "acme"
        finally:
            reg._registered = old_registered

    def test_capture_action_metadata_collision_explicit_wins(
        self, reset_sequence_context
    ):
        """When both have same key, explicit value wins."""
        from arcjet.guard import _registry as reg

        client = StubGuardClient()
        client.captures = []

        def capture_impl(
            action: str,
            correlation_id: Any = None,
            decision_id: Any = None,
            occurred_at: Any = None,
            metadata: Any = None,
        ) -> None:
            client.captures.append(
                dict(
                    action=action,
                    correlation_id=correlation_id,
                    decision_id=decision_id,
                    metadata=metadata,
                )
            )

        client.capture = capture_impl  # type: ignore[assignment]

        old_registered = reg._registered
        try:
            reg._registered = client  # type: ignore[assignment]

            with arcjet_sequence(
                correlation_id="seq-789",
                metadata={"tenant": "acme", "key": "ambient"},
            ):
                capture_action(action="item.created", metadata={"key": "explicit"})

            assert len(client.captures) == 1
            assert client.captures[0]["metadata"]["tenant"] == "acme"
            assert client.captures[0]["metadata"]["key"] == "explicit"
        finally:
            reg._registered = old_registered

    def test_capture_action_decision_id_passed_through(self, reset_sequence_context):
        """decision_id is passed through unchanged."""
        from arcjet.guard import _registry as reg

        client = StubGuardClient()
        client.captures = []

        def capture_impl(
            action: str,
            correlation_id: Any = None,
            decision_id: Any = None,
            occurred_at: Any = None,
            metadata: Any = None,
        ) -> None:
            client.captures.append(
                dict(
                    action=action,
                    correlation_id=correlation_id,
                    decision_id=decision_id,
                    metadata=metadata,
                )
            )

        client.capture = capture_impl  # type: ignore[assignment]

        old_registered = reg._registered
        try:
            reg._registered = client  # type: ignore[assignment]

            capture_action(action="item.created", decision_id="dec_123")

            assert len(client.captures) == 1
            assert client.captures[0]["decision_id"] == "dec_123"
        finally:
            reg._registered = old_registered


class TestCaptureActionAsync:
    """capture_action async tests mirror sync behavior."""

    def test_capture_action_async_inside_sequence_inherits_correlation_id(
        self, reset_sequence_context
    ):
        """Async: omitted correlation_id is inherited from sequence."""
        from arcjet.guard import _registry as reg

        async def test():
            client = StubGuardClient()
            client.captures = []

            def capture_impl(
                action: str,
                correlation_id: Any = None,
                decision_id: Any = None,
                occurred_at: Any = None,
                metadata: Any = None,
            ) -> None:
                client.captures.append(
                    dict(
                        action=action,
                        correlation_id=correlation_id,
                        decision_id=decision_id,
                        metadata=metadata,
                    )
                )

            client.capture = capture_impl  # type: ignore[assignment]

            old_registered = reg._registered
            try:
                reg._registered = client  # type: ignore[assignment]

                with arcjet_sequence(correlation_id="seq-456"):
                    capture_action(action="item.created")

                assert len(client.captures) == 1
                assert client.captures[0]["correlation_id"] == "seq-456"
            finally:
                reg._registered = old_registered

        asyncio.run(test())

    def test_capture_action_async_metadata_collision_explicit_wins(
        self, reset_sequence_context
    ):
        """Async: explicit metadata wins on collision."""
        from arcjet.guard import _registry as reg

        async def test():
            client = StubGuardClient()
            client.captures = []

            def capture_impl(
                action: str,
                correlation_id: Any = None,
                decision_id: Any = None,
                occurred_at: Any = None,
                metadata: Any = None,
            ) -> None:
                client.captures.append(
                    dict(
                        action=action,
                        correlation_id=correlation_id,
                        decision_id=decision_id,
                        metadata=metadata,
                    )
                )

            client.capture = capture_impl  # type: ignore[assignment]

            old_registered = reg._registered
            try:
                reg._registered = client  # type: ignore[assignment]

                with arcjet_sequence(
                    correlation_id="seq-789",
                    metadata={"tenant": "acme", "key": "ambient"},
                ):
                    capture_action(action="item.created", metadata={"key": "explicit"})

                assert len(client.captures) == 1
                assert client.captures[0]["metadata"]["tenant"] == "acme"
                assert client.captures[0]["metadata"]["key"] == "explicit"
            finally:
                reg._registered = old_registered

        asyncio.run(test())


class TestPolicyInputIntegration:
    """Policy input rules (prompt injection, sensitive info) in checkpoint."""

    def test_prompt_injection_rule_in_checkpoint(self, reset_sequence_context):
        """DetectPromptInjection rule arrives in recorded guard call."""
        from arcjet.guard._rules import DetectPromptInjection

        client = StubGuardClient(decision=make_allow_decision())
        rule = DetectPromptInjection()("test message")

        def fn():
            return "ok"

        run_checkpoint_sync(
            fn,
            action="thing.done",
            guard=client,
            rules=[rule],
        )

        # Rule is recorded unchanged
        assert len(client.guards) == 1
        assert len(client.guards[0]["rules"]) == 1
        assert client.guards[0]["rules"][0] is rule

    def test_sensitive_info_rule_in_checkpoint(self, reset_sequence_context):
        """LocalDetectSensitiveInfo rule arrives unchanged."""
        from arcjet.guard._rules import LocalDetectSensitiveInfo

        client = StubGuardClient(decision=make_allow_decision())
        rule = LocalDetectSensitiveInfo()("test value")

        def fn():
            return "ok"

        run_checkpoint_sync(
            fn,
            action="thing.done",
            guard=client,
            rules=[rule],
        )

        # Rule is recorded unchanged
        assert len(client.guards) == 1
        assert len(client.guards[0]["rules"]) == 1
        assert client.guards[0]["rules"][0] is rule


class TestContentMutationSync:
    """Argument and return value mutation are forbidden."""

    def test_no_mutation_on_allow_path(self, reset_sequence_context):
        """ALLOW path does not mutate argument object."""
        client = StubGuardClient(decision=make_allow_decision())

        class MutableArg:
            def __init__(self):
                self.value = "original"

        mutable = MutableArg()
        inputs = {"arg": mutable}

        def fn():
            return "success"

        run_checkpoint_sync(
            fn,
            action="thing.done",
            guard=client,
            inputs=inputs,  # type: ignore[arg-type]
        )

        assert mutable.value == "original"
        assert client.guards[0]["inputs"] is inputs
        assert client.guards[0]["inputs"]["arg"] is mutable

    def test_no_mutation_on_deny_path(self, reset_sequence_context):
        """DENY path does not mutate argument object."""
        client = StubGuardClient(decision=make_deny_decision())

        class MutableArg:
            def __init__(self):
                self.value = "original"

        mutable = MutableArg()
        inputs = {"arg": mutable}

        def fn():
            return "success"

        with pytest.raises(ArcjetDeniedError):
            run_checkpoint_sync(
                fn,
                action="thing.done",
                guard=client,
                inputs=inputs,  # type: ignore[arg-type]
            )

        assert mutable.value == "original"
        # The same mapping reached the client; nothing was rewritten on the way.
        assert client.guards[0]["inputs"] is inputs


class TestSensitiveInfoDenial:
    """Sensitive info detection denies rather than redacts."""

    def test_sensitive_info_deny_raises_before_callable(self, reset_sequence_context):
        """DENY from sensitive info raises before callable runs."""
        from arcjet.guard import local_input
        from arcjet.guard._rules import LocalDetectSensitiveInfo

        client = StubGuardClient(decision=make_deny_decision())
        rule = LocalDetectSensitiveInfo()("sensitive_value_here")
        inputs = {"message": local_input.string("card 4111111111111111")}
        call_count = 0

        def fn():
            nonlocal call_count
            call_count += 1
            return "never_reaches_here"

        with pytest.raises(ArcjetDeniedError):
            run_checkpoint_sync(
                fn,
                action="thing.done",
                guard=client,
                rules=[rule],
                inputs=inputs,
            )

        assert call_count == 0
        # Denied, not redacted: the mapping arrives as the caller built it.
        assert client.guards[0]["inputs"] is inputs
        assert client.guards[0]["rules"] == [rule]


class TestMetadataPreferenceSync:
    """When both tiers set same key, explicit wins."""

    def test_metadata_explicit_wins_over_sequence(self, reset_sequence_context):
        """Explicit metadata overrides sequence on key collision."""
        decision = make_allow_decision()
        client = StubGuardClient(decision=decision)

        with arcjet_sequence(
            correlation_id="seq-123",
            metadata={"key": "ambient", "other": "value"},
        ):
            run_checkpoint_sync(
                lambda: None,
                action="thing.done",
                guard=client,
                metadata={"key": "explicit", "extra": "data"},
            )

        # Sequence metadata applied first, then explicit
        capture_metadata = client.captures[0]["metadata"]
        assert capture_metadata["key"] == "explicit"  # Explicit wins
        assert capture_metadata["other"] == "value"  # Ambient preserved
        assert capture_metadata["extra"] == "data"  # Explicit added
        assert capture_metadata["outcome"] == "success"


class TestCorrelationIdPreferenceSync:
    """Explicit correlation_id always wins over sequence."""

    def test_correlation_id_explicit_wins_over_sequence(self, reset_sequence_context):
        """Explicit correlation_id overrides sequence."""
        decision = make_allow_decision()
        client = StubGuardClient(decision=decision)

        with arcjet_sequence(correlation_id="seq-123"):
            run_checkpoint_sync(
                lambda: None,
                action="thing.done",
                guard=client,
                correlation_id="explicit-456",
            )

        assert client.captures[0]["correlation_id"] == "explicit-456"


class TestMetadataPreferenceAsync:
    """Async: explicit metadata overrides sequence."""

    def test_metadata_explicit_wins_over_sequence_async(self, reset_sequence_context):
        """Async: explicit metadata overrides sequence on key collision."""

        async def test():
            decision = make_allow_decision()
            client = StubGuardClient(decision=decision)

            async def fn():
                return "success"

            with arcjet_sequence(
                correlation_id="seq-123",
                metadata={"key": "ambient", "other": "value"},
            ):
                await run_checkpoint(
                    fn,
                    action="thing.done",
                    guard=client,
                    metadata={"key": "explicit", "extra": "data"},
                )

            capture_metadata = client.captures[0]["metadata"]
            assert capture_metadata["key"] == "explicit"
            assert capture_metadata["other"] == "value"
            assert capture_metadata["extra"] == "data"
            assert capture_metadata["outcome"] == "success"

        asyncio.run(test())


class TestCorrelationIdPreferenceAsync:
    """Async: explicit correlation_id wins over sequence."""

    def test_correlation_id_explicit_wins_over_sequence_async(
        self, reset_sequence_context
    ):
        """Async: explicit correlation_id overrides sequence."""

        async def test():
            decision = make_allow_decision()
            client = StubGuardClient(decision=decision)

            async def fn():
                return "success"

            with arcjet_sequence(correlation_id="seq-123"):
                await run_checkpoint(
                    fn,
                    action="thing.done",
                    guard=client,
                    correlation_id="explicit-456",
                )

            assert client.captures[0]["correlation_id"] == "explicit-456"

        asyncio.run(test())


class TestEmptyRulesAsync:
    """Async: empty rules path is covered."""

    def test_empty_rules_async(self, reset_sequence_context):
        """Async: empty rules still evaluates policy and succeeds."""

        async def test():
            decision = make_allow_decision()
            client = StubGuardClient(decision=decision)

            async def fn():
                return "success"

            result = await run_checkpoint(
                fn,
                action="thing.done",
                guard=client,
                rules=[],
            )

            assert result == "success"
            assert len(client.captures) == 1
            assert len(client.guards) == 1
            assert client.guards[0]["rules"] == []

        asyncio.run(test())


class TestGuardCallArgumentsAsync:
    """What the async engine sends to guard(), not just what it captures."""

    def test_guard_receives_label_correlation_metadata_and_actor(
        self, reset_sequence_context
    ):
        async def test():
            client = StubGuardClient(decision=make_allow_decision())

            async def fn():
                return "value"

            with arcjet_sequence(correlation_id="corr-1"):
                await run_checkpoint(
                    fn,
                    action="checkout.refund",
                    guard=client,
                    actor="u_1",
                    metadata={"tier": "pro"},
                )

            assert len(client.guards) == 1
            recorded = client.guards[0]
            assert recorded["label"] == "checkout.refund"
            assert recorded["correlation_id"] == "corr-1"
            assert recorded["metadata"] == {"tier": "pro"}
            assert recorded["actor"] == "u_1"

        asyncio.run(test())

    def test_prepared_actor_and_inputs_reach_guard(self, reset_sequence_context):
        """What an awaited prepare() returns is what gets evaluated."""

        async def test():
            from arcjet.guard import local_input

            client = StubGuardClient(decision=make_allow_decision())
            inputs = {"message": local_input.string("hello")}

            async def fn():
                return "value"

            async def prepare():
                return ResolvedInputs(actor="u_1", inputs=inputs)

            await run_checkpoint(
                fn,
                action="thing.done",
                guard=client,
                prepare=prepare,
                actor="ignored",
                inputs={"ignored": local_input.string("no")},
            )

            assert len(client.guards) == 1
            assert client.guards[0]["actor"] == "u_1"
            assert client.guards[0]["inputs"] is inputs

        asyncio.run(test())


class TestPrepareRaisingAsync:
    """Async: prepare() raising path is covered."""

    def test_prepare_raise_async(self, reset_sequence_context):
        """Async: prepare() raising becomes unavailable."""

        async def test():
            client = StubGuardClient(decision=make_allow_decision())
            call_count = 0

            async def fn():
                nonlocal call_count
                call_count += 1
                return "success"

            async def prepare():
                raise ValueError("prepare failed")

            with pytest.raises(ArcjetUnavailableError):
                await run_checkpoint(
                    fn,
                    action="thing.done",
                    guard=client,
                    prepare=prepare,
                )

            assert call_count == 0

        asyncio.run(test())


class TestFailedOpenAsync:
    """Async: failed-open decision handling."""

    def test_failed_open_deny_default_async(self, reset_sequence_context):
        """Async: failed-open denies by default."""

        async def test():
            error_result = RuleResultError(
                code="ERR_UNKNOWN", message="something broke"
            )
            decision = make_allow_decision(results=(error_result,))
            # Verify the fixture is actually failed open
            assert decision.has_failed_open() is True

            client = StubGuardClient(decision=decision)

            async def fn():
                return "success"

            with pytest.raises(ArcjetUnavailableError):
                await run_checkpoint(
                    fn,
                    action="thing.done",
                    guard=client,
                )

            assert len(client.captures) == 1
            assert client.captures[0]["metadata"]["outcome"] == "unavailable"

        asyncio.run(test())

    def test_failed_open_allow_proceeds_async(self, reset_sequence_context):
        """Async: failed-open allows with on_guard_error='allow'."""

        async def test():
            error_result = RuleResultError(
                code="ERR_UNKNOWN", message="something broke"
            )
            decision = make_allow_decision(results=(error_result,))
            # Verify the fixture is actually failed open
            assert decision.has_failed_open() is True

            client = StubGuardClient(decision=decision)
            call_count = 0

            async def fn():
                nonlocal call_count
                call_count += 1
                return "success"

            result = await run_checkpoint(
                fn,
                action="thing.done",
                guard=client,
                on_guard_error="allow",
            )

            assert result == "success"
            assert call_count == 1
            assert len(client.captures) >= 1
            # The action ran only because on_guard_error is 'allow', and the
            # decision failed open, so policy judged none of it.
            assert client.captures[0]["metadata"]["outcome"] == "degraded"

        asyncio.run(test())


class TestDenyCallableErrorAsync:
    """Async: deny with callable error path covered."""

    def test_deny_when_callable_would_error_async(self, reset_sequence_context):
        """Async: deny raises even if callable would error."""

        async def test():
            decision = make_deny_decision()
            client = StubGuardClient(decision=decision)
            call_count = 0

            async def fn():
                nonlocal call_count
                call_count += 1
                raise ValueError("error in callable")

            with pytest.raises(ArcjetDeniedError):
                await run_checkpoint(
                    fn,
                    action="thing.done",
                    guard=client,
                )

            assert call_count == 0
            assert len(client.captures) == 1
            assert client.captures[0]["metadata"]["outcome"] == "denied"

        asyncio.run(test())


class TestSequenceMetadataAsync:
    """Async: sequence metadata inheritance."""

    def test_sequence_metadata_inherited_async(self, reset_sequence_context):
        """Async: sequence metadata is inherited."""

        async def test():
            decision = make_allow_decision()
            client = StubGuardClient(decision=decision)

            async def fn():
                return "success"

            with arcjet_sequence(
                correlation_id="seq-123",
                metadata={"user_id": "u_1"},
            ):
                await run_checkpoint(
                    fn,
                    action="thing.done",
                    guard=client,
                )

            assert client.captures[0]["metadata"]["user_id"] == "u_1"
            assert client.captures[0]["metadata"]["outcome"] == "success"

        asyncio.run(test())


class TestRegisteredClientAsync:
    """Async: guard=None resolves to registered client."""

    def test_guard_none_registered_client_async(self, reset_sequence_context):
        """Async: guard=None uses registered client."""

        async def test():
            from arcjet.guard import register_arcjet, unregister_arcjet

            decision = make_allow_decision()
            client = StubGuardClient(decision=decision)

            async def fn():
                return "success"

            register_arcjet(client)  # type: ignore[arg-type]
            try:
                result = await run_checkpoint(
                    fn,
                    action="thing.done",
                    guard=None,
                )
            finally:
                unregister_arcjet()

            # Should have called the registered client
            assert len(client.guards) == 1
            assert result == "success"

        asyncio.run(test())


class TestGuardRaiseAllowProceedsAsync:
    """Async: guard raising with on_guard_error='allow' runs callable."""

    def test_guard_raise_allow_proceeds_async(self, reset_sequence_context):
        """Async: guard raising with on_guard_error='allow' runs callable."""

        async def test():
            exc = ValueError("network error")
            client = StubGuardClient(exception=exc)
            call_count = 0

            async def fn():
                nonlocal call_count
                call_count += 1
                return "success"

            result = await run_checkpoint(
                fn,
                action="thing.done",
                guard=client,
                on_guard_error="allow",
            )

            assert call_count == 1
            assert result == "success"
            # Should capture success, not unavailable
            assert len(client.captures) == 1
            # Not `unavailable`, which would mean the action was blocked, and
            # not `success`, which would claim policy judged it.
            assert client.captures[0]["metadata"]["outcome"] == "degraded"

        asyncio.run(test())


class TestDegradedOutcome:
    """`success` claims policy judged the action, so a partial judgement is not one.

    Covers the conditions from the capture-outcome ADR that reach the capture
    with the action already run. The fail-closed halves of the same conditions
    are covered by the `unavailable` tests above.
    """

    def test_degraded_inputs_carry_a_decision_id(self, reset_sequence_context):
        """Policy judged the action in part: it ran, and a real decision exists."""
        client = StubGuardClient(decision=make_allow_decision(id="gdec_partial"))

        def prepare() -> ResolvedInputs:
            return ResolvedInputs(
                actor="user-1", degraded=RuntimeError("inputs unreadable")
            )

        result = run_checkpoint_sync(
            lambda: "value",
            action="thing.done",
            guard=client,
            prepare=prepare,
            on_guard_error="allow",
        )

        assert result == "value"
        capture = client.captures[0]
        assert capture["metadata"]["outcome"] == "degraded"
        # The half of the three-state reading that says "judged in part".
        assert capture["decision_id"] == "gdec_partial"

    def test_a_failed_open_decision_carries_no_decision_id(
        self, reset_sequence_context
    ):
        """Policy judged none of it, which the absent decision ID reports."""
        decision = make_allow_decision(
            id="", results=(RuleResultError(code="ERR_UNKNOWN", message="broke"),)
        )
        client = StubGuardClient(decision=decision)

        run_checkpoint_sync(
            lambda: "value",
            action="thing.done",
            guard=client,
            on_guard_error="allow",
        )

        capture = client.captures[0]
        assert capture["metadata"]["outcome"] == "degraded"
        assert not capture["decision_id"]

    def test_an_unreadable_decision_is_degraded(self, reset_sequence_context):
        """A client that answered with something that is not a decision.

        Policy was not evaluated, so the action ran only because
        `on_guard_error` is 'allow' — the record must say so.
        """
        client = StubGuardClient(decision=object())  # type: ignore[arg-type]

        result = run_checkpoint_sync(
            lambda: "value",
            action="thing.done",
            guard=client,
            on_guard_error="allow",
        )

        assert result == "value"
        assert client.captures[0]["metadata"]["outcome"] == "degraded"

    def test_a_clean_allow_is_still_success(self, reset_sequence_context):
        """The control: nothing degraded, so the claim of a judgement stands."""
        client = StubGuardClient(decision=make_allow_decision())

        run_checkpoint_sync(
            lambda: "value",
            action="thing.done",
            guard=client,
            on_guard_error="allow",
        )

        assert client.captures[0]["metadata"]["outcome"] == "success"

    def test_a_throwing_action_reports_error_over_degraded(
        self, reset_sequence_context
    ):
        """`outcome` holds one value, and the ADR gives `error` precedence.

        A count of `degraded` events therefore excludes the degraded actions
        that also threw, which is stated in the ADR rather than fixed here.
        """
        decision = make_allow_decision(
            id="", results=(RuleResultError(code="ERR_UNKNOWN", message="broke"),)
        )
        client = StubGuardClient(decision=decision)

        def fn() -> str:
            raise ValueError("the action itself failed")

        with pytest.raises(ValueError):
            run_checkpoint_sync(
                fn,
                action="thing.done",
                guard=client,
                on_guard_error="allow",
            )

        assert client.captures[0]["metadata"]["outcome"] == "error"

    def test_degraded_inputs_are_degraded_on_the_async_path(
        self, reset_sequence_context
    ):
        """Both flavours share the engine, so both report it the same way."""

        async def test() -> None:
            client = StubGuardClient(decision=make_allow_decision(id="gdec_partial"))

            async def prepare() -> ResolvedInputs:
                return ResolvedInputs(
                    actor="user-1", degraded=RuntimeError("inputs unreadable")
                )

            async def fn() -> str:
                return "value"

            result = await run_checkpoint(
                fn,
                action="thing.done",
                guard=client,
                prepare=prepare,
                on_guard_error="allow",
            )

            assert result == "value"
            capture = client.captures[0]
            assert capture["metadata"]["outcome"] == "degraded"
            assert capture["decision_id"] == "gdec_partial"

        asyncio.run(test())
