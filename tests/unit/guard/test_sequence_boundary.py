"""Unit tests for correlation ID resumption across worker boundaries.

Verifies that a correlation ID can be explicitly carried across process
boundaries and resumed in a new worker context, landing all decisions and
captures on the same Sequence.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from arcjet.guard import (
    arcjet_sequence,
    capture_action,
    current_correlation_id,
    guard_action_sync,
)
from arcjet.guard.testing import register_test_client


class TestSequenceBoundaryResume:
    """Correlation ID can be carried across a worker boundary and resumed."""

    def test_correlation_crosses_boundary_when_explicit(self) -> None:
        """A worker resuming an exported correlation_id lands on the originating Sequence."""
        with register_test_client() as arcjet:
            # Open the sequence and export the id
            payload: dict = {}
            with arcjet_sequence(correlation_id="req-1"):
                assert current_correlation_id() == "req-1"

                # Run a checkpoint in the main context
                result = guard_action_sync(
                    lambda: "main-result",
                    action="main.action",
                    on_guard_error="allow",
                )
                assert result == "main-result"

                # Export the correlation ID for the worker
                payload = {"correlation_id": current_correlation_id()}

            # Leave it: the resume must do real work, not read a leaked value
            assert current_correlation_id() is None

            # A bare submit inherits nothing, so the worker must reopen it
            def worker_task():
                with arcjet_sequence(correlation_id=payload["correlation_id"]):
                    # Run second checkpoint in worker
                    worker_result = guard_action_sync(
                        lambda: "worker-result",
                        action="worker.action",
                        on_guard_error="allow",
                    )
                    # Capture an action
                    capture_action(action="worker.captured")
                    return worker_result

            with ThreadPoolExecutor(max_workers=1) as executor:
                worker_result = executor.submit(worker_task).result()

            assert worker_result == "worker-result"

            # Verify: All guards and captures on both sides carry correlation_id == "req-1"
            assert len(arcjet.guards) == 2
            for guard in arcjet.guards:
                assert guard.correlation_id == "req-1", (
                    f"Guard {guard.label} has correlation_id={guard.correlation_id}, "
                    f"expected 'req-1'"
                )

            # guard_action_sync creates a capture for each action, plus explicit capture_action call
            assert len(arcjet.captures) == 3
            for capture in arcjet.captures:
                assert capture.correlation_id == "req-1", (
                    f"Capture {capture.action} has correlation_id={capture.correlation_id}, "
                    f"expected 'req-1'"
                )

    def test_bare_thread_does_not_inherit_the_enclosing_sequence(self) -> None:
        """Submitting from inside a sequence carries nothing into the thread.

        This is the control that makes the resume above meaningful. It runs the
        worker without reopening the sequence, but submits it while the sequence
        is still open — so if a bare thread did inherit the correlation ID, or if
        it were held somewhere shared between threads rather than per-context,
        this would see "req-1" instead of nothing.
        """
        with register_test_client() as arcjet:

            def worker_without_resume() -> str | None:
                return guard_action_sync(
                    current_correlation_id,
                    action="worker.action",
                    on_guard_error="allow",
                )

            with arcjet_sequence(correlation_id="req-1"):
                with ThreadPoolExecutor(max_workers=1) as executor:
                    seen_in_thread = executor.submit(worker_without_resume).result()

            assert seen_in_thread is None
            assert arcjet.guards[0].correlation_id is None

    def test_correlation_is_none_without_any_sequence(self) -> None:
        """With no sequence open anywhere, events simply carry no correlation ID.

        Observation does not require a sequence; a checkpoint outside one still
        evaluates policy and just joins no Sequence.
        """
        with register_test_client() as arcjet:
            # Worker function that does NOT reopen the sequence
            def worker_without_sequence():
                result = guard_action_sync(
                    lambda: "worker-result",
                    action="worker.action",
                    on_guard_error="allow",
                )
                capture_action(action="worker.captured")
                return result

            # Run the worker in a separate thread
            with ThreadPoolExecutor(max_workers=1) as executor:
                worker_result = executor.submit(worker_without_sequence).result()

            assert worker_result == "worker-result"

            # Verify: The guard and captures have correlation_id=None
            assert len(arcjet.guards) == 1
            assert arcjet.guards[0].correlation_id is None

            # guard_action_sync creates a capture for the action, plus explicit capture_action call
            assert len(arcjet.captures) == 2
            for capture in arcjet.captures:
                assert capture.correlation_id is None, (
                    f"Capture {capture.action} has correlation_id={capture.correlation_id}, "
                    f"expected None"
                )
