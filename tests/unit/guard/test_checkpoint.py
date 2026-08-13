"""Tests for the checkpoint engine and guard_action surfaces.

Comprehensive coverage of the four outcomes, flavor routing, capture behavior,
and ambient context handling.
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import warnings
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
    guard_action,
    guard_action_sync,
)
from arcjet.guard._checkpoint import run_checkpoint, run_checkpoint_sync
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
        assert client.captures[0]["metadata"]["outcome"] == "success"


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

            with pytest.raises(ArcjetUnavailableError):
                await run_checkpoint(
                    fn,
                    action="thing.done",
                    guard=client,
                )

            assert call_count == 0

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
        assert client.captures[0]["metadata"]["outcome"] == "success"


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

    def test_callable_error_with_deny_still_runs(self, reset_sequence_context):
        """Error outcome is after policy, so DENY was not checked."""
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

    def test_wrong_flavor_no_coroutine_warning(self, reset_sequence_context):
        """No 'coroutine was never awaited' warning."""
        client = AsyncOnlyStubGuardClient(decision=make_allow_decision())

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            try:
                run_checkpoint_sync(
                    lambda: None,
                    action="thing.done",
                    guard=client,
                )
            except ArcjetUnavailableError:
                pass

            # No RuntimeWarning about un-awaited coroutine
            runtime_warnings = [x for x in w if issubclass(x.category, RuntimeWarning)]
            assert len(runtime_warnings) == 0


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
                guard=client,  # type: ignore[arg-type]
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
