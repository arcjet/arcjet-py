"""Tests for ambient correlation context in arcjet.guard._context.

Verifies langchain-helper.AC3 (correlation ID management) and AC6 (context
propagation across async boundaries).
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context

import pytest

from arcjet.guard import (
    arcjet_sequence,
    current_correlation_id,
    current_sequence_metadata,
)


class TestAC31ExplicitID:
    """AC3.1: Inside arcjet_sequence, yielded ID and current_correlation_id() match."""

    def test_yields_and_reads_back_explicit_id(self):
        """Explicit ID is yielded and returned by current_correlation_id()."""
        assert current_correlation_id() is None
        with arcjet_sequence(correlation_id="corr-1") as cid:
            assert cid == "corr-1"
            assert current_correlation_id() == "corr-1"
        assert current_correlation_id() is None

    def test_generates_id_when_none_given(self):
        """Auto-generated ID is yielded and returned by current_correlation_id()."""
        assert current_correlation_id() is None
        with arcjet_sequence() as cid:
            assert isinstance(cid, str)
            assert len(cid) == 26  # Crockford base32 encoded UUIDv7
            assert cid.isalnum() and cid.islower()
            assert current_correlation_id() == cid
        assert current_correlation_id() is None


class TestAC32Nesting:
    """AC3.2: Nested blocks restore outer ID on exit, including when body raises."""

    def test_nested_sequence_restores_outer_id(self):
        """Nested sequence restores outer ID after exiting."""
        with arcjet_sequence(correlation_id="outer") as outer_cid:
            assert current_correlation_id() == "outer"
            with arcjet_sequence(correlation_id="inner") as inner_cid:
                assert inner_cid == "inner"
                assert current_correlation_id() == "inner"
            assert current_correlation_id() == "outer"
        assert current_correlation_id() is None

    def test_nested_restores_even_when_body_raises(self):
        """Nested sequence restores outer ID even when inner body raises."""
        with arcjet_sequence(correlation_id="outer"):
            assert current_correlation_id() == "outer"
            with pytest.raises(ValueError):
                with arcjet_sequence(correlation_id="inner"):
                    assert current_correlation_id() == "inner"
                    raise ValueError("intentional")
            assert current_correlation_id() == "outer"
        assert current_correlation_id() is None


class TestAC33Validation:
    """AC3.3: Over-length, non-ASCII, and other invalid IDs are rejected."""

    def test_rejects_id_over_256_bytes(self):
        """ID longer than 256 bytes raises ValueError."""
        long_id = "a" * 257
        with pytest.raises(ValueError, match="at most 256 bytes"):
            with arcjet_sequence(correlation_id=long_id):
                pass
        assert current_correlation_id() is None

    def test_accepts_id_exactly_256_bytes(self):
        """ID of exactly 256 bytes is accepted."""
        exact_id = "a" * 256
        with arcjet_sequence(correlation_id=exact_id) as cid:
            assert cid == exact_id
            assert current_correlation_id() == exact_id
        assert current_correlation_id() is None

    def test_rejects_non_ascii(self):
        """Non-ASCII characters raise ValueError."""
        with pytest.raises(ValueError, match="printable ASCII"):
            with arcjet_sequence(correlation_id="café"):
                pass
        assert current_correlation_id() is None

    def test_rejects_control_character_tab(self):
        """Control character (tab) raises ValueError."""
        with pytest.raises(ValueError, match="printable ASCII"):
            with arcjet_sequence(correlation_id="a\tb"):
                pass
        assert current_correlation_id() is None

    def test_rejects_control_character_newline(self):
        """Control character (newline) raises ValueError."""
        with pytest.raises(ValueError, match="printable ASCII"):
            with arcjet_sequence(correlation_id="a\nb"):
                pass
        assert current_correlation_id() is None

    def test_rejects_empty_string(self):
        """Empty string raises ValueError."""
        with pytest.raises(ValueError, match="must not be empty"):
            with arcjet_sequence(correlation_id=""):
                pass
        assert current_correlation_id() is None

    def test_rejects_non_string_type(self):
        """Non-string type raises TypeError."""
        with pytest.raises(TypeError, match="must be a str"):
            with arcjet_sequence(correlation_id=123):  # type: ignore[arg-type]
                pass
        assert current_correlation_id() is None


class TestAC34OutsideSequence:
    """AC3.4: Outside any sequence, current_correlation_id() and metadata return None."""

    def test_returns_none_outside_sequence(self):
        """Outside any sequence, current_correlation_id() is None."""
        assert current_correlation_id() is None

    def test_metadata_returns_none_outside_sequence(self):
        """Outside any sequence, current_sequence_metadata() is None."""
        assert current_sequence_metadata() is None


class TestAC61AsyncCreateTask:
    """AC6.1: Correlation ID is visible inside asyncio.create_task()."""

    def test_correlation_visible_in_created_task(self):
        """Correlation set before create_task() is visible inside the task."""

        async def read_in_task():
            return current_correlation_id()

        async def main():
            with arcjet_sequence(correlation_id="task-1"):
                result = await asyncio.create_task(read_in_task())
                assert result == "task-1"

        asyncio.run(main())


class TestAC62AsyncToThread:
    """AC6.2: Correlation ID is visible inside asyncio.to_thread()."""

    def test_correlation_visible_in_to_thread(self):
        """Correlation set before to_thread() is visible inside the thread."""

        async def main():
            with arcjet_sequence(correlation_id="thread-1"):
                result = await asyncio.to_thread(current_correlation_id)
                assert result == "thread-1"

        asyncio.run(main())


class TestAC63ThreadPoolExecutor:
    """AC6.3: Bare ThreadPoolExecutor.submit() does not inherit; copy_context() does."""

    def test_thread_pool_executor_does_not_propagate(self):
        """ThreadPoolExecutor.submit() does not inherit correlation."""
        with arcjet_sequence(correlation_id="pool-1"):
            with ThreadPoolExecutor(max_workers=1) as pool:
                result = pool.submit(current_correlation_id).result()
                assert result is None

    def test_thread_pool_executor_with_copy_context_propagates(self):
        """ThreadPoolExecutor.submit() with copy_context() idiom does inherit."""
        with arcjet_sequence(correlation_id="pool-2"):
            with ThreadPoolExecutor(max_workers=1) as pool:
                ctx = copy_context()
                result = pool.submit(ctx.run, current_correlation_id).result()
                assert result == "pool-2"

    def test_loop_run_in_executor_does_not_propagate(self):
        """loop.run_in_executor() does not inherit correlation."""

        async def main():
            with arcjet_sequence(correlation_id="exec-1"):
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor(max_workers=1) as pool:
                    result = await loop.run_in_executor(pool, current_correlation_id)
                    assert result is None

        asyncio.run(main())


class TestMetadataManagement:
    """Metadata handling: passing, inheriting, and replacing across nesting."""

    def test_current_sequence_metadata_returns_passed_metadata(self):
        """Metadata passed to arcjet_sequence() is returned by current_sequence_metadata()."""
        meta = {"request_id": "req-1", "user": {"id": "u_123"}}
        with arcjet_sequence(correlation_id="corr-1", metadata=meta):
            assert current_sequence_metadata() == meta

    def test_nested_with_none_inherits_outer_metadata(self):
        """Nested block with metadata=None inherits outer metadata."""
        outer_meta = {"level": "outer"}
        with arcjet_sequence(correlation_id="outer", metadata=outer_meta):
            assert current_sequence_metadata() == outer_meta
            with arcjet_sequence(correlation_id="inner"):
                assert current_sequence_metadata() == outer_meta
            assert current_sequence_metadata() == outer_meta

    def test_nested_with_metadata_replaces_outer(self):
        """Nested block with new metadata replaces outer, restored on exit."""
        outer_meta = {"level": "outer"}
        inner_meta = {"level": "inner"}
        with arcjet_sequence(correlation_id="outer", metadata=outer_meta):
            assert current_sequence_metadata() == outer_meta
            with arcjet_sequence(correlation_id="inner", metadata=inner_meta):
                assert current_sequence_metadata() == inner_meta
            assert current_sequence_metadata() == outer_meta
