"""Tests for the singleton get_component / reset_component API."""

from __future__ import annotations

import threading

import pytest

from arcjet._analyze import (
    AnalyzeComponent,
    Ok,
    get_component,
    reset_component,
)
from arcjet._analyze._types import AllowedBotConfig

from .conftest import BOT_REQUEST, WASM_PATH


@pytest.fixture(autouse=True)
def _reset_singleton() -> None:  # type: ignore[misc]
    """Ensure each test starts with a fresh singleton."""
    reset_component()
    yield  # type: ignore[misc]
    reset_component()


class TestGetComponent:
    def test_returns_analyze_component(self) -> None:
        ac = get_component(WASM_PATH)
        assert isinstance(ac, AnalyzeComponent)

    def test_returns_same_instance(self) -> None:
        ac1 = get_component(WASM_PATH)
        ac2 = get_component()
        assert ac1 is ac2

    def test_ignores_args_after_first_call(self) -> None:
        ac1 = get_component(WASM_PATH)
        ac2 = get_component("/nonexistent/path.wasm")
        assert ac1 is ac2

    def test_default_wasm_path(self) -> None:
        """get_component() with no args uses bundled WASM."""
        ac = get_component()
        assert isinstance(ac, AnalyzeComponent)

    def test_functional_after_creation(self) -> None:
        ac = get_component(WASM_PATH)
        config = AllowedBotConfig(entities=[], skip_custom_detect=False)
        result = ac.detect_bot(BOT_REQUEST, config)
        assert isinstance(result, Ok)


class TestResetComponent:
    def test_reset_allows_reinit(self) -> None:
        ac1 = get_component(WASM_PATH)
        reset_component()
        ac2 = get_component(WASM_PATH)
        assert ac1 is not ac2

    def test_reset_closes_old_instance(self) -> None:
        ac = get_component(WASM_PATH)
        reset_component()
        with pytest.raises(RuntimeError, match="closed"):
            ac.match_filters("{}", "{}", [], True)

    def test_reset_when_no_instance(self) -> None:
        """reset_component() is safe to call with no existing singleton."""
        reset_component()  # Should not raise

    def test_double_reset(self) -> None:
        get_component(WASM_PATH)
        reset_component()
        reset_component()  # Should not raise


class TestThreadSafety:
    def test_concurrent_get_component(self) -> None:
        """Multiple threads calling get_component get the same instance."""
        results: list[AnalyzeComponent] = []
        barrier = threading.Barrier(10)

        def worker() -> None:
            barrier.wait()
            results.append(get_component(WASM_PATH))

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 10
        assert all(r is results[0] for r in results)
