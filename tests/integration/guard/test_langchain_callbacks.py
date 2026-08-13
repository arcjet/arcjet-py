"""Tests for the LangChain capture handlers.

Verifies that ArcjetCaptureHandler and ArcjetAsyncCaptureHandler emit
captures correctly across the chain, model, and tool lifecycle, with
proper correlation tracking and error handling.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

import pytest
from langchain_core.outputs import Generation, LLMResult

from arcjet.guard import arcjet_sequence
from arcjet.guard.langchain.callbacks import (
    ArcjetAsyncCaptureHandler,
    ArcjetCaptureHandler,
)
from arcjet.guard.testing import register_test_client


class _Recorder:
    """A client double recording capture kwargs, applying no ambient defaults.

    Routing through a client rather than ``guard=None`` matters: the free
    ``capture()`` applies its own ambient fallback, which would mask a handler
    that stopped resolving the correlation ID itself.
    """

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def capture(self, **kwargs: Any) -> None:
        self.calls.append(kwargs)


class TestArcjetCaptureHandlerSyncLifecycle:
    """Test the synchronous handler lifecycle and correlation tracking."""

    def test_full_lifecycle_shares_correlation_id(self) -> None:
        """Full lifecycle: all hooks share the same correlation ID.

        One chain-shaped run emits one capture per hook, all carrying the
        run's correlation ID and the past-tense resource.verb action names.
        """
        with register_test_client() as client:
            handler = ArcjetCaptureHandler()
            run_id = uuid.uuid4()
            tool_run_id = uuid.uuid4()
            llm_run_id = uuid.uuid4()

            with arcjet_sequence(correlation_id="corr-1"):
                handler.on_chain_start({"name": "chain"}, {}, run_id=run_id)
                handler.on_tool_start(
                    {"name": "tool"},
                    "tool_input",
                    run_id=tool_run_id,
                )
                handler.on_tool_end("tool_output", run_id=tool_run_id)
                handler.on_llm_start(
                    {"name": "model"},
                    ["prompt1", "prompt2"],
                    run_id=llm_run_id,
                )
                handler.on_llm_end(
                    LLMResult(
                        generations=[[Generation(text="response")]],
                    ),
                    run_id=llm_run_id,
                )
                handler.on_chain_end({"output": "result"}, run_id=run_id)

            assert len(client.captures) == 6
            assert all(c.correlation_id == "corr-1" for c in client.captures)

            expected_actions = [
                "langchain.chain.started",
                "langchain.tool.started",
                "langchain.tool.completed",
                "langchain.model.started",
                "langchain.model.completed",
                "langchain.chain.completed",
            ]
            actual_actions = [c.action for c in client.captures]
            assert actual_actions == expected_actions

    def test_correlation_resolves_per_event_not_per_handler(self) -> None:
        """Correlation resolves at emit time, not construction time.

        Verifies the construction-time-binding bug: construct one handler
        outside any sequence, drive it inside arcjet_sequence("a"), then
        again inside arcjet_sequence("b"), and assert captures carry "a"
        and "b" respectively. This is the bug the implementation comment
        warns about.
        """
        with register_test_client() as client:
            handler = ArcjetCaptureHandler()
            run_id_a = uuid.uuid4()
            run_id_b = uuid.uuid4()

            with arcjet_sequence(correlation_id="a"):
                handler.on_chain_start({"name": "x"}, {}, run_id=run_id_a)

            with arcjet_sequence(correlation_id="b"):
                handler.on_chain_start({"name": "y"}, {}, run_id=run_id_b)

            assert len(client.captures) == 2
            assert client.captures[0].correlation_id == "a"
            assert client.captures[1].correlation_id == "b"

    def test_explicit_correlation_wins(self) -> None:
        """Explicit correlation_id takes precedence over ambient.

        A handler built with correlation_id="explicit" emits "explicit"
        even inside arcjet_sequence(correlation_id="ambient").
        """
        with register_test_client() as client:
            handler = ArcjetCaptureHandler(correlation_id="explicit")
            run_id = uuid.uuid4()

            with arcjet_sequence(correlation_id="ambient"):
                handler.on_chain_start({"name": "x"}, {}, run_id=run_id)

            assert len(client.captures) == 1
            assert client.captures[0].correlation_id == "explicit"

    def test_outside_any_sequence_captures_with_none_correlation(self) -> None:
        """Captures outside any sequence have correlation_id=None.

        Observation must not require a sequence. Correlation can be None
        when no sequence is active.
        """
        with register_test_client() as client:
            handler = ArcjetCaptureHandler()
            run_id = uuid.uuid4()

            handler.on_chain_start({"name": "x"}, {}, run_id=run_id)

            assert len(client.captures) == 1
            assert client.captures[0].correlation_id is None

    def test_error_hooks_emit_failed_actions(self) -> None:
        """Error hooks emit ...failed actions."""
        with register_test_client() as client:
            handler = ArcjetCaptureHandler()
            run_id = uuid.uuid4()
            error = ValueError("test error")

            with arcjet_sequence(correlation_id="corr-1"):
                handler.on_chain_error(error, run_id=run_id)

            assert len(client.captures) == 1
            assert client.captures[0].action == "langchain.chain.failed"
            assert client.captures[0].correlation_id == "corr-1"

    def test_llm_error_emits_failed_action(self) -> None:
        """on_llm_error emits model.failed action."""
        with register_test_client() as client:
            handler = ArcjetCaptureHandler()
            run_id = uuid.uuid4()
            error = ValueError("model error")

            with arcjet_sequence(correlation_id="corr-1"):
                handler.on_llm_error(error, run_id=run_id)

            assert len(client.captures) == 1
            assert client.captures[0].action == "langchain.model.failed"

    def test_tool_error_emits_failed_action(self) -> None:
        """on_tool_error emits tool.failed action."""
        with register_test_client() as client:
            handler = ArcjetCaptureHandler()
            run_id = uuid.uuid4()
            error = ValueError("tool error")

            with arcjet_sequence(correlation_id="corr-1"):
                handler.on_tool_error(error, run_id=run_id)

            assert len(client.captures) == 1
            assert client.captures[0].action == "langchain.tool.failed"


class TestArcjetCaptureHandlerCaptureFailure:
    """Test that capture failures never raise into LangChain.

    A capture failure inside the callback handler never
    raises into LangChain, even when capture itself fails.
    """

    def test_capture_failure_on_start_hook_returns_normally(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """on_chain_start with failing capture returns normally.

        When the guard's capture() raises, the handler catches it,
        logs a warning, and returns normally.
        """

        class FailingGuard:
            """A guard whose capture() raises."""

            def capture(self, **kwargs: Any) -> None:
                raise RuntimeError("capture failed")

        with caplog.at_level(logging.WARNING, logger="arcjet"):
            handler = ArcjetCaptureHandler(guard=FailingGuard())  # type: ignore
            run_id = uuid.uuid4()

            # This must not raise, despite capture() failing
            handler.on_chain_start({"name": "x"}, {}, run_id=run_id)

        assert any(
            "failed to capture" in record.message for record in caplog.records
        ), "Expected warning not logged"

    def test_capture_failure_on_end_hook_returns_normally(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """on_chain_end with failing capture returns normally."""

        class FailingGuard:
            """A guard whose capture() raises."""

            def capture(self, **kwargs: Any) -> None:
                raise RuntimeError("capture failed")

        with caplog.at_level(logging.WARNING, logger="arcjet"):
            handler = ArcjetCaptureHandler(guard=FailingGuard())  # type: ignore
            run_id = uuid.uuid4()

            # This must not raise, despite capture() failing
            handler.on_chain_end({"output": "result"}, run_id=run_id)

        assert any(
            "failed to capture" in record.message for record in caplog.records
        ), "Expected warning not logged"

    def test_capture_failure_on_error_hook_returns_normally(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """on_chain_error with failing capture returns normally."""

        class FailingGuard:
            """A guard whose capture() raises."""

            def capture(self, **kwargs: Any) -> None:
                raise RuntimeError("capture failed")

        with caplog.at_level(logging.WARNING, logger="arcjet"):
            handler = ArcjetCaptureHandler(guard=FailingGuard())  # type: ignore
            run_id = uuid.uuid4()
            error = ValueError("test error")

            # This must not raise, despite capture() failing
            handler.on_chain_error(error, run_id=run_id)

        assert any(
            "failed to capture" in record.message for record in caplog.records
        ), "Expected warning not logged"


class TestArcjetAsyncCaptureHandler:
    """Test the asynchronous handler."""

    def test_async_handler_correlation_resolves_per_event(self) -> None:
        """Async handler: correlation resolves at emit time, not construction.

        Drive ArcjetAsyncCaptureHandler from a plain def test_* calling
        asyncio.run(...), asserting the same correlation sharing as sync.
        """

        async def run_test() -> None:
            with register_test_client() as client:
                handler = ArcjetAsyncCaptureHandler()
                run_id_a = uuid.uuid4()
                run_id_b = uuid.uuid4()

                with arcjet_sequence(correlation_id="a"):
                    await handler.on_chain_start({"name": "x"}, {}, run_id=run_id_a)

                with arcjet_sequence(correlation_id="b"):
                    await handler.on_chain_start({"name": "y"}, {}, run_id=run_id_b)

                assert len(client.captures) == 2
                assert client.captures[0].correlation_id == "a"
                assert client.captures[1].correlation_id == "b"

        asyncio.run(run_test())

    def test_async_handler_full_lifecycle_shares_correlation(self) -> None:
        """Async handler full lifecycle shares correlation ID."""

        async def run_test() -> None:
            with register_test_client() as client:
                handler = ArcjetAsyncCaptureHandler()
                run_id = uuid.uuid4()
                tool_run_id = uuid.uuid4()
                llm_run_id = uuid.uuid4()

                with arcjet_sequence(correlation_id="corr-async"):
                    await handler.on_chain_start({"name": "chain"}, {}, run_id=run_id)
                    await handler.on_tool_start(
                        {"name": "tool"}, "tool_input", run_id=tool_run_id
                    )
                    await handler.on_tool_end("tool_output", run_id=tool_run_id)
                    await handler.on_llm_start(
                        {"name": "model"},
                        ["prompt1"],
                        run_id=llm_run_id,
                    )
                    await handler.on_llm_end(
                        LLMResult(
                            generations=[[Generation(text="response")]],
                        ),
                        run_id=llm_run_id,
                    )
                    await handler.on_chain_end({"output": "result"}, run_id=run_id)

                assert len(client.captures) == 6
                assert all(c.correlation_id == "corr-async" for c in client.captures)

        asyncio.run(run_test())

    def test_async_handler_error_returns_normally_on_capture_failure(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Async handler: capture failure returns normally."""

        async def run_test() -> None:
            class FailingGuard:
                """A guard whose capture() raises."""

                def capture(self, **kwargs: Any) -> None:
                    raise RuntimeError("capture failed")

            with caplog.at_level(logging.WARNING, logger="arcjet"):
                handler = ArcjetAsyncCaptureHandler(guard=FailingGuard())  # type: ignore
                run_id = uuid.uuid4()
                error = ValueError("test error")

                # Must not raise
                await handler.on_chain_error(error, run_id=run_id)

            assert any(
                "failed to capture" in record.message for record in caplog.records
            ), "Expected warning not logged"

        asyncio.run(run_test())


class TestNoContentLeaks:
    """Test that user content never leaks into metadata.

    Verifies that metadata contains only shapes and structural info
    (run IDs, counts, action names), never user content like inputs,
    prompts, outputs, or secrets.
    """

    def test_no_secret_in_tool_start_metadata(self) -> None:
        """on_tool_start with secret in inputs: secret absent from metadata.

        Drive on_tool_start with a recognizable secret string in the inputs
        and assert that string appears in no recorded capture's metadata.
        """
        secret = "xyzzy_secret_token_12345"
        with register_test_client() as client:
            handler = ArcjetCaptureHandler()
            run_id = uuid.uuid4()

            with arcjet_sequence(correlation_id="corr-1"):
                handler.on_tool_start(
                    {"name": "tool"},
                    input_str=secret,
                    run_id=run_id,
                    inputs={"key": secret},
                )

            assert len(client.captures) == 1
            capture = client.captures[0]
            metadata_str = str(capture.metadata)
            assert secret not in metadata_str

    def test_no_secret_in_llm_start_metadata(self) -> None:
        """on_llm_start with secret in prompts: secret absent from metadata."""
        secret = "xyzzy_secret_prompt_67890"
        with register_test_client() as client:
            handler = ArcjetCaptureHandler()
            run_id = uuid.uuid4()

            with arcjet_sequence(correlation_id="corr-1"):
                handler.on_llm_start(
                    {"name": "model"},
                    prompts=[secret, "other prompt"],
                    run_id=run_id,
                )

            assert len(client.captures) == 1
            capture = client.captures[0]
            metadata_str = str(capture.metadata)
            assert secret not in metadata_str

    def test_no_secret_in_tool_end_metadata(self) -> None:
        """on_tool_end with secret in output: secret absent from metadata."""
        secret = "xyzzy_secret_output_99999"
        with register_test_client() as client:
            handler = ArcjetCaptureHandler()
            run_id = uuid.uuid4()

            with arcjet_sequence(correlation_id="corr-1"):
                handler.on_tool_end(output=secret, run_id=run_id)

            assert len(client.captures) == 1
            capture = client.captures[0]
            metadata_str = str(capture.metadata)
            assert secret not in metadata_str


class TestMetadataInclusion:
    """Test that run_id and related metadata are included correctly."""

    def test_run_id_in_metadata_string_form(self) -> None:
        """run_id is included in metadata as a string."""
        with register_test_client() as client:
            handler = ArcjetCaptureHandler()
            run_id = uuid.uuid4()

            with arcjet_sequence(correlation_id="corr-1"):
                handler.on_chain_start({"name": "chain"}, {}, run_id=run_id)

            assert len(client.captures) == 1
            capture = client.captures[0]
            assert "run_id" in capture.metadata
            assert capture.metadata["run_id"] == str(run_id)

    def test_parent_run_id_in_metadata_when_present(self) -> None:
        """parent_run_id is included in metadata when provided."""
        with register_test_client() as client:
            handler = ArcjetCaptureHandler()
            run_id = uuid.uuid4()
            parent_run_id = uuid.uuid4()

            with arcjet_sequence(correlation_id="corr-1"):
                handler.on_chain_start(
                    {"name": "chain"},
                    {},
                    run_id=run_id,
                    parent_run_id=parent_run_id,
                )

            assert len(client.captures) == 1
            capture = client.captures[0]
            assert "parent_run_id" in capture.metadata
            assert capture.metadata["parent_run_id"] == str(parent_run_id)

    def test_parent_run_id_absent_when_not_provided(self) -> None:
        """parent_run_id is absent from metadata when not provided."""
        with register_test_client() as client:
            handler = ArcjetCaptureHandler()
            run_id = uuid.uuid4()

            with arcjet_sequence(correlation_id="corr-1"):
                handler.on_chain_start({"name": "chain"}, {}, run_id=run_id)

            assert len(client.captures) == 1
            capture = client.captures[0]
            assert "parent_run_id" not in capture.metadata

    def test_prompt_count_in_llm_start_metadata(self) -> None:
        """on_llm_start includes prompt_count in metadata."""
        with register_test_client() as client:
            handler = ArcjetCaptureHandler()
            run_id = uuid.uuid4()

            with arcjet_sequence(correlation_id="corr-1"):
                handler.on_llm_start(
                    {"name": "model"},
                    prompts=["p1", "p2", "p3"],
                    run_id=run_id,
                )

            assert len(client.captures) == 1
            capture = client.captures[0]
            assert capture.metadata["prompt_count"] == 3


class TestCustomPrefix:
    """Test that custom prefix is used in action names."""

    def test_custom_prefix_in_action_names(self) -> None:
        """Custom prefix builds correct action names."""
        with register_test_client() as client:
            handler = ArcjetCaptureHandler(prefix="custom")
            run_id = uuid.uuid4()

            with arcjet_sequence(correlation_id="corr-1"):
                handler.on_chain_start({"name": "x"}, {}, run_id=run_id)
                handler.on_chain_end({"output": "result"}, run_id=run_id)

            assert len(client.captures) == 2
            assert client.captures[0].action == "custom.chain.started"
            assert client.captures[1].action == "custom.chain.completed"


class TestCustomMetadata:
    """Test that custom metadata is merged into captures."""

    def test_custom_metadata_merged_into_capture(self) -> None:
        """Custom metadata passed to constructor is merged into all captures."""
        with register_test_client() as client:
            handler = ArcjetCaptureHandler(metadata={"custom_key": "custom_value"})
            run_id = uuid.uuid4()

            with arcjet_sequence(correlation_id="corr-1"):
                handler.on_chain_start({"name": "x"}, {}, run_id=run_id)

            assert len(client.captures) == 1
            capture = client.captures[0]
            assert capture.metadata["custom_key"] == "custom_value"
            assert "run_id" in capture.metadata

    def test_custom_metadata_on_async_handler(self) -> None:
        """Async handler also includes custom metadata."""

        async def run_test() -> None:
            with register_test_client() as client:
                handler = ArcjetAsyncCaptureHandler(
                    metadata={"async_key": "async_value"}
                )
                run_id = uuid.uuid4()

                with arcjet_sequence(correlation_id="corr-1"):
                    await handler.on_chain_start({"name": "x"}, {}, run_id=run_id)

                assert len(client.captures) == 1
                capture = client.captures[0]
                assert capture.metadata["async_key"] == "async_value"

        asyncio.run(run_test())


class TestEveryHookRecordsRunIds:
    """Every hook, on both handlers, reports the run it belongs to."""

    def test_sync_hooks_all_record_run_and_parent_ids(self) -> None:
        run_id = uuid.uuid4()
        parent_run_id = uuid.uuid4()
        result = LLMResult(generations=[[Generation(text="r")]])

        with register_test_client() as client:
            handler = ArcjetCaptureHandler()
            handler.on_chain_start({}, {}, run_id=run_id, parent_run_id=parent_run_id)
            handler.on_chain_end({}, run_id=run_id, parent_run_id=parent_run_id)
            handler.on_chain_error(
                ValueError("x"), run_id=run_id, parent_run_id=parent_run_id
            )
            handler.on_llm_start({}, ["p"], run_id=run_id, parent_run_id=parent_run_id)
            handler.on_llm_end(result, run_id=run_id, parent_run_id=parent_run_id)
            handler.on_llm_error(
                ValueError("x"), run_id=run_id, parent_run_id=parent_run_id
            )
            handler.on_tool_start({}, "i", run_id=run_id, parent_run_id=parent_run_id)
            handler.on_tool_end("o", run_id=run_id, parent_run_id=parent_run_id)
            handler.on_tool_error(
                ValueError("x"), run_id=run_id, parent_run_id=parent_run_id
            )

            assert [c.action for c in client.captures] == [
                "langchain.chain.started",
                "langchain.chain.completed",
                "langchain.chain.failed",
                "langchain.model.started",
                "langchain.model.completed",
                "langchain.model.failed",
                "langchain.tool.started",
                "langchain.tool.completed",
                "langchain.tool.failed",
            ]
            for capture in client.captures:
                assert capture.metadata is not None
                assert capture.metadata["run_id"] == str(run_id)
                assert capture.metadata["parent_run_id"] == str(parent_run_id)

    def test_async_hooks_all_record_run_and_parent_ids(self) -> None:
        run_id = uuid.uuid4()
        parent_run_id = uuid.uuid4()
        result = LLMResult(generations=[[Generation(text="r")]])

        async def drive(handler: ArcjetAsyncCaptureHandler) -> None:
            await handler.on_chain_start(
                {}, {}, run_id=run_id, parent_run_id=parent_run_id
            )
            await handler.on_chain_end({}, run_id=run_id, parent_run_id=parent_run_id)
            await handler.on_chain_error(
                ValueError("x"), run_id=run_id, parent_run_id=parent_run_id
            )
            await handler.on_llm_start(
                {}, ["p"], run_id=run_id, parent_run_id=parent_run_id
            )
            await handler.on_llm_end(result, run_id=run_id, parent_run_id=parent_run_id)
            await handler.on_llm_error(
                ValueError("x"), run_id=run_id, parent_run_id=parent_run_id
            )
            await handler.on_tool_start(
                {}, "i", run_id=run_id, parent_run_id=parent_run_id
            )
            await handler.on_tool_end("o", run_id=run_id, parent_run_id=parent_run_id)
            await handler.on_tool_error(
                ValueError("x"), run_id=run_id, parent_run_id=parent_run_id
            )

        with register_test_client() as client:
            asyncio.run(drive(ArcjetAsyncCaptureHandler()))

            assert [c.action for c in client.captures] == [
                "langchain.chain.started",
                "langchain.chain.completed",
                "langchain.chain.failed",
                "langchain.model.started",
                "langchain.model.completed",
                "langchain.model.failed",
                "langchain.tool.started",
                "langchain.tool.completed",
                "langchain.tool.failed",
            ]
            for capture in client.captures:
                assert capture.metadata is not None
                assert capture.metadata["run_id"] == str(run_id)
                assert capture.metadata["parent_run_id"] == str(parent_run_id)


class TestHandlerResolvesCorrelationItself:
    """The handler resolves the ambient ID, not just whatever capture() does.

    Driving these through an explicit client matters. With ``guard=None`` the
    free ``capture()`` applies its own ambient fallback, which would mask the
    handler dropping the resolution entirely; a client's ``capture()`` applies
    none, so only the handler can supply the ID.
    """

    def test_sync_handler_supplies_the_ambient_id_per_event(self) -> None:
        recorder = _Recorder()
        handler = ArcjetCaptureHandler(guard=recorder)  # type: ignore[arg-type]

        with arcjet_sequence(correlation_id="a"):
            handler.on_chain_start({}, {}, run_id=uuid.uuid4())
        with arcjet_sequence(correlation_id="b"):
            handler.on_chain_start({}, {}, run_id=uuid.uuid4())

        assert [c["correlation_id"] for c in recorder.calls] == ["a", "b"]

    def test_async_handler_supplies_the_ambient_id_per_event(self) -> None:
        recorder = _Recorder()
        handler = ArcjetAsyncCaptureHandler(guard=recorder)  # type: ignore[arg-type]

        async def drive(correlation_id: str) -> None:
            with arcjet_sequence(correlation_id=correlation_id):
                await handler.on_chain_start({}, {}, run_id=uuid.uuid4())

        asyncio.run(drive("a"))
        asyncio.run(drive("b"))

        assert [c["correlation_id"] for c in recorder.calls] == ["a", "b"]


class TestEmitDoesNotSwallowBaseException:
    """An interrupt during capture still reaches the interpreter."""

    class _Interrupting:
        def __init__(self, exc: BaseException) -> None:
            self._exc = exc

        def capture(self, **kwargs: Any) -> None:
            raise self._exc

    @pytest.mark.parametrize("exc_type", [KeyboardInterrupt, SystemExit])
    def test_sync_handler_propagates_base_exception(
        self, exc_type: type[BaseException]
    ) -> None:
        handler = ArcjetCaptureHandler(guard=self._Interrupting(exc_type()))  # type: ignore[arg-type]
        with pytest.raises(exc_type):
            handler.on_chain_start({}, {}, run_id=uuid.uuid4())

    @pytest.mark.parametrize("exc_type", [KeyboardInterrupt, SystemExit])
    def test_async_handler_propagates_base_exception(
        self, exc_type: type[BaseException]
    ) -> None:
        handler = ArcjetAsyncCaptureHandler(guard=self._Interrupting(exc_type()))  # type: ignore[arg-type]

        async def drive() -> None:
            await handler.on_chain_start({}, {}, run_id=uuid.uuid4())

        with pytest.raises(exc_type):
            asyncio.run(drive())

    def test_ordinary_exception_is_still_swallowed(self) -> None:
        """The narrowing must not turn into "propagate everything"."""

        class Failing:
            def capture(self, **kwargs: Any) -> None:
                raise RuntimeError("capture failed")

        handler = ArcjetCaptureHandler(guard=Failing())  # type: ignore[arg-type]
        handler.on_chain_start({}, {}, run_id=uuid.uuid4())


# Kills: on the ASYNC handler, inverting the correlation precedence so the
# ambient ID wins over the explicit one. The sync equivalent was covered;
# the async one was not.
class TestAsyncExplicitCorrelationWins:
    """An explicitly configured correlation ID beats the ambient sequence."""

    def test_async_explicit_correlation_beats_ambient(self) -> None:
        recorder = _Recorder()
        handler = ArcjetAsyncCaptureHandler(
            guard=recorder,  # type: ignore[arg-type]
            correlation_id="explicit",
        )

        async def drive() -> None:
            with arcjet_sequence(correlation_id="ambient"):
                await handler.on_chain_start({}, {}, run_id=uuid.uuid4())

        asyncio.run(drive())

        assert [c["correlation_id"] for c in recorder.calls] == ["explicit"]


# Kills: hardcoding the "langchain" prefix in any hook other than the two
# sync chain hooks, and every hook on the async handler.
class TestPrefixAppliesToEveryHook:
    """A custom prefix reaches all nine actions on both handlers."""

    EXPECTED = [
        "custom.chain.started",
        "custom.chain.completed",
        "custom.chain.failed",
        "custom.model.started",
        "custom.model.completed",
        "custom.model.failed",
        "custom.tool.started",
        "custom.tool.completed",
        "custom.tool.failed",
    ]

    def test_sync_prefix_on_all_nine_hooks(self) -> None:
        recorder = _Recorder()
        handler = ArcjetCaptureHandler(guard=recorder, prefix="custom")  # type: ignore[arg-type]
        run_id = uuid.uuid4()
        result = LLMResult(generations=[[Generation(text="r")]])

        handler.on_chain_start({}, {}, run_id=run_id)
        handler.on_chain_end({}, run_id=run_id)
        handler.on_chain_error(ValueError("x"), run_id=run_id)
        handler.on_llm_start({}, ["p"], run_id=run_id)
        handler.on_llm_end(result, run_id=run_id)
        handler.on_llm_error(ValueError("x"), run_id=run_id)
        handler.on_tool_start({}, "i", run_id=run_id)
        handler.on_tool_end("o", run_id=run_id)
        handler.on_tool_error(ValueError("x"), run_id=run_id)

        assert [c["action"] for c in recorder.calls] == self.EXPECTED

    def test_async_prefix_on_all_nine_hooks(self) -> None:
        recorder = _Recorder()
        handler = ArcjetAsyncCaptureHandler(guard=recorder, prefix="custom")  # type: ignore[arg-type]
        run_id = uuid.uuid4()
        result = LLMResult(generations=[[Generation(text="r")]])

        async def drive() -> None:
            await handler.on_chain_start({}, {}, run_id=run_id)
            await handler.on_chain_end({}, run_id=run_id)
            await handler.on_chain_error(ValueError("x"), run_id=run_id)
            await handler.on_llm_start({}, ["p"], run_id=run_id)
            await handler.on_llm_end(result, run_id=run_id)
            await handler.on_llm_error(ValueError("x"), run_id=run_id)
            await handler.on_tool_start({}, "i", run_id=run_id)
            await handler.on_tool_end("o", run_id=run_id)
            await handler.on_tool_error(ValueError("x"), run_id=run_id)

        asyncio.run(drive())

        assert [c["action"] for c in recorder.calls] == self.EXPECTED

    def test_async_prompt_count_is_the_real_count(self) -> None:
        """Kills hardcoding prompt_count on the async handler."""
        recorder = _Recorder()
        handler = ArcjetAsyncCaptureHandler(guard=recorder)  # type: ignore[arg-type]

        async def drive() -> None:
            await handler.on_llm_start({}, ["p1", "p2", "p3"], run_id=uuid.uuid4())

        asyncio.run(drive())

        assert recorder.calls[0]["metadata"]["prompt_count"] == 3


# Kills: any hook on either handler starting to copy a content-bearing
# argument into metadata. The existing cover checked three hooks and three
# arguments; this sweeps every hook and every content channel, including the
# **kwargs tail and LangChain's own run tags/metadata.
class TestNoContentLeaksFromAnyHook:
    """No content-bearing argument of any hook reaches capture metadata."""

    SECRET = "xyzzy-do-not-record-3f9a1c"

    def _content_kwargs(self) -> dict[str, Any]:
        """Arguments LangChain would pass that must never be recorded."""
        return {
            "tags": [self.SECRET],
            "metadata": {"lc_run_key": self.SECRET},
            "extra_unexpected_kwarg": self.SECRET,
        }

    def _drive_sync(self, handler: ArcjetCaptureHandler, run_id: uuid.UUID) -> None:
        s = self.SECRET
        k = self._content_kwargs()
        serialized = {"name": s, "kwargs": {"api_key": s}}
        handler.on_chain_start(serialized, {"question": s}, run_id=run_id, **k)
        handler.on_chain_end({"answer": s}, run_id=run_id, **k)
        handler.on_chain_error(ValueError(s), run_id=run_id, **k)
        handler.on_llm_start(serialized, [s, s], run_id=run_id, **k)
        handler.on_llm_end(
            LLMResult(generations=[[Generation(text=s)]]), run_id=run_id, **k
        )
        handler.on_llm_error(ValueError(s), run_id=run_id, **k)
        handler.on_tool_start(serialized, s, run_id=run_id, inputs={"arg": s}, **k)
        handler.on_tool_end(s, run_id=run_id, **k)
        handler.on_tool_error(ValueError(s), run_id=run_id, **k)

    async def _drive_async(
        self, handler: ArcjetAsyncCaptureHandler, run_id: uuid.UUID
    ) -> None:
        s = self.SECRET
        k = self._content_kwargs()
        serialized = {"name": s, "kwargs": {"api_key": s}}
        await handler.on_chain_start(serialized, {"question": s}, run_id=run_id, **k)
        await handler.on_chain_end({"answer": s}, run_id=run_id, **k)
        await handler.on_chain_error(ValueError(s), run_id=run_id, **k)
        await handler.on_llm_start(serialized, [s, s], run_id=run_id, **k)
        await handler.on_llm_end(
            LLMResult(generations=[[Generation(text=s)]]), run_id=run_id, **k
        )
        await handler.on_llm_error(ValueError(s), run_id=run_id, **k)
        await handler.on_tool_start(
            serialized, s, run_id=run_id, inputs={"arg": s}, **k
        )
        await handler.on_tool_end(s, run_id=run_id, **k)
        await handler.on_tool_error(ValueError(s), run_id=run_id, **k)

    def test_sync_hooks_record_no_content(self) -> None:
        recorder = _Recorder()
        handler = ArcjetCaptureHandler(guard=recorder)  # type: ignore[arg-type]
        run_id = uuid.uuid4()

        self._drive_sync(handler, run_id)

        assert len(recorder.calls) == 9
        for call in recorder.calls:
            assert self.SECRET not in repr(call["metadata"]), call["action"]
            assert set(call["metadata"]) <= {"run_id", "prompt_count"}, call["action"]

    def test_async_hooks_record_no_content(self) -> None:
        recorder = _Recorder()
        handler = ArcjetAsyncCaptureHandler(guard=recorder)  # type: ignore[arg-type]
        run_id = uuid.uuid4()

        asyncio.run(self._drive_async(handler, run_id))

        assert len(recorder.calls) == 9
        for call in recorder.calls:
            assert self.SECRET not in repr(call["metadata"]), call["action"]
            assert set(call["metadata"]) <= {"run_id", "prompt_count"}, call["action"]
