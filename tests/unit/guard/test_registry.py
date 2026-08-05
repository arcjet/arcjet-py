"""Unit tests for optional client registration.

Registration is process-wide, so every test here unregisters afterwards via the
autouse fixture — a leaked client changes the meaning of every test after it.
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Any, Optional, Sequence

import pytest

from arcjet.guard._diagnostics import (
    CLIENT_ALREADY_REGISTERED,
    CLIENT_FLAVOR_MISMATCH,
)
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
from arcjet.guard._types import Decision, RuleResultError


class _RecorderBase:
    """Records what was called, and what the registry reported to it.

    Deliberately not a subclass of either real client: registration is
    structural, and this is what proves it.
    """

    def __init__(self) -> None:
        self.guards: list[str] = []
        self.captures: list[str] = []
        self.flushes: list[Optional[int]] = []
        self.diagnostics: list[str] = []

    def _diagnose(self, code: str, count: int = 1) -> None:
        self.diagnostics.append(code)

    def capture(self, *, action: str, **kwargs: Any) -> None:
        self.captures.append(action)

    def _record(self, label: str) -> Decision:
        self.guards.append(label)
        return Decision(conclusion="ALLOW", id="stub", results=(), reason="ERROR")


class AsyncRecorder(_RecorderBase):
    """Shaped like ``ArcjetGuard`` — awaitable ``guard`` and ``flush``."""

    async def guard(self, rules: Sequence[Any], **kwargs: Any) -> Decision:
        return self._record(str(kwargs.get("label")))

    async def flush(self, timeout_ms: Optional[int] = None) -> None:
        self.flushes.append(timeout_ms)


class SyncRecorder(_RecorderBase):
    """Shaped like ``ArcjetGuardSync`` — blocking ``guard`` and ``flush``."""

    def guard(self, rules: Sequence[Any], **kwargs: Any) -> Decision:
        return self._record(str(kwargs.get("label")))

    def flush(self, timeout_ms: Optional[int] = None) -> None:
        self.flushes.append(timeout_ms)


def async_recorder() -> Any:
    return AsyncRecorder()


def sync_recorder() -> Any:
    return SyncRecorder()


@pytest.fixture(autouse=True)
def _clear_registration():
    unregister_arcjet()
    try:
        yield
    finally:
        unregister_arcjet()


class TestRegisterArcjet:
    def test_launching_alone_registers_nothing(self) -> None:
        assert registered_client() is None

    def test_routes_the_free_calls_to_the_client(self) -> None:
        client = async_recorder()
        register_arcjet(client)

        asyncio.run(guard([], label="test"))
        capture(action="test.done")
        asyncio.run(flush(50))

        assert client.guards == ["test"]
        assert client.captures == ["test.done"]
        assert client.flushes == [50]

    def test_keeps_the_incumbent_when_a_second_registers(self) -> None:
        first = async_recorder()
        register_arcjet(first)
        register_arcjet(async_recorder())

        assert registered_client() is first

    def test_reports_the_refusal_on_the_incumbents_channel(self) -> None:
        first = async_recorder()
        register_arcjet(first)
        register_arcjet(async_recorder())

        # The warning belongs to whoever registered first: it is their telemetry
        # a silent takeover would have redirected.
        assert first.diagnostics == [CLIENT_ALREADY_REGISTERED]

    def test_re_registering_the_same_client_is_silent(self) -> None:
        client = async_recorder()
        register_arcjet(client)
        register_arcjet(client)

        assert registered_client() is client
        # A module imported twice must not look like a takeover attempt.
        assert client.diagnostics == []

    def test_a_client_without_a_diagnostics_channel_does_not_raise(self) -> None:
        class _Bare:
            async def guard(self, rules, **kwargs): ...
            def capture(self, **kwargs): ...
            async def flush(self, timeout_ms=None): ...

        register_arcjet(_Bare())  # type: ignore[arg-type]
        register_arcjet(_Bare())  # type: ignore[arg-type]


class TestUnregisterArcjet:
    def test_clears_the_registration(self) -> None:
        register_arcjet(async_recorder())
        unregister_arcjet()

        assert registered_client() is None

    def test_is_safe_with_nothing_registered(self) -> None:
        unregister_arcjet()
        unregister_arcjet()


class TestNothingRegistered:
    def test_guard_fails_open_rather_than_raising(self) -> None:
        decision = asyncio.run(guard([], label="test"))

        # Both halves matter. A plain ALLOW would satisfy the first assertion
        # too, and that is the actual bug worth catching: a silent bypass that
        # looks exactly like a guard which ran and permitted the call.
        assert decision.conclusion == "ALLOW"
        assert decision.has_failed_open()

    def test_guard_sync_fails_open_rather_than_raising(self) -> None:
        decision = guard_sync([], label="test")

        assert decision.conclusion == "ALLOW"
        assert decision.has_failed_open()

    def test_the_fail_open_decision_says_why(self) -> None:
        decision = asyncio.run(guard([], label="test"))

        result = decision.results[0]
        assert isinstance(result, RuleResultError)
        assert "no registered" in result.message

    def test_capture_drops_the_event_without_raising(self) -> None:
        capture(action="test.done")

    def test_flush_returns(self) -> None:
        asyncio.run(flush())
        flush_sync()


class TestSyncAsyncFlavor:
    """The failure mode Python has and JavaScript does not.

    ``register_arcjet`` erases which flavor it took, so a mismatch is not
    statically catchable — which is exactly why it has to degrade predictably
    and say so.
    """

    def test_async_guard_reaches_an_async_client(self) -> None:
        client = async_recorder()
        register_arcjet(client)

        asyncio.run(guard([], label="ok"))

        assert client.guards == ["ok"]
        assert client.diagnostics == []

    def test_sync_guard_reaches_a_sync_client(self) -> None:
        client = sync_recorder()
        register_arcjet(client)

        guard_sync([], label="ok")

        assert client.guards == ["ok"]
        assert client.diagnostics == []

    def test_async_guard_with_a_sync_client_fails_open(self) -> None:
        client = sync_recorder()
        register_arcjet(client)

        decision = asyncio.run(guard([], label="test"))

        assert decision.has_failed_open()
        assert client.guards == []
        assert client.diagnostics == [CLIENT_FLAVOR_MISMATCH]

    def test_sync_guard_with_an_async_client_fails_open(self) -> None:
        client = async_recorder()
        register_arcjet(client)

        decision = guard_sync([], label="test")

        # The important half: it must not return a coroutine dressed up as a
        # decision, which is what calling through blindly would produce.
        assert decision.has_failed_open()
        assert client.guards == []
        assert client.diagnostics == [CLIENT_FLAVOR_MISMATCH]

    def test_flush_flavor_mismatch_is_reported(self) -> None:
        client = sync_recorder()
        register_arcjet(client)

        asyncio.run(flush())

        assert client.flushes == []
        assert client.diagnostics == [CLIENT_FLAVOR_MISMATCH]

    def test_capture_works_with_either_flavor(self) -> None:
        # One free function for both, because capture() queues and returns on
        # each of them.
        for client in (async_recorder(), sync_recorder()):
            unregister_arcjet()
            register_arcjet(client)

            capture(action="either.works")

            assert client.captures == ["either.works"]

    def test_nothing_registered_is_silent_but_a_mismatch_is_not(self) -> None:
        # Nothing registered is the ordinary unconfigured case; a registered
        # client of the wrong flavor is a wiring mistake, and there is a
        # configured logger on it to report to.
        asyncio.run(guard([], label="test"))  # no client, no channel, no line

        client = sync_recorder()
        register_arcjet(client)
        asyncio.run(guard([], label="test"))

        assert client.diagnostics == [CLIENT_FLAVOR_MISMATCH]


class TestThreadVisibility:
    def test_a_registration_is_visible_from_a_worker_thread(self) -> None:
        """The reason this is a module global and not a ContextVar.

        A ContextVar set at startup returns None in a new thread, so this test
        is what fails if anyone 'modernizes' the registry onto one. Flask,
        Django and every other WSGI server run handlers exactly this way.
        """
        import threading

        client = sync_recorder()
        register_arcjet(client)

        seen: list[Any] = []
        thread = threading.Thread(target=lambda: seen.append(registered_client()))
        thread.start()
        thread.join()

        assert seen == [client]

    def test_capture_from_a_worker_thread_reaches_the_client(self) -> None:
        import threading

        client = sync_recorder()
        register_arcjet(client)

        thread = threading.Thread(target=lambda: capture(action="from.thread"))
        thread.start()
        thread.join()

        assert client.captures == ["from.thread"]


class TestNamespaceShape:
    """Pins how the free calls are reached, because one spelling is a trap.

    ``guard`` names both the subpackage and a function inside it. That is
    survivable — ``arcjet.guard.guard`` stutters but resolves, and
    ``from arcjet.guard import guard`` is the spelling the docs use. What is not
    survivable is a *top-level* ``arcjet.guard`` function: it would collide with
    the submodule of the same name and win or lose depending on whether
    ``import arcjet.guard`` had run yet, which is an order-dependent bug in
    somebody else's application.
    """

    def test_the_free_calls_are_importable_from_the_subpackage(self) -> None:
        from arcjet.guard import capture as pkg_capture
        from arcjet.guard import flush as pkg_flush
        from arcjet.guard import flush_sync as pkg_flush_sync
        from arcjet.guard import guard as pkg_guard
        from arcjet.guard import guard_sync as pkg_guard_sync

        for fn in (
            pkg_guard,
            pkg_guard_sync,
            pkg_capture,
            pkg_flush,
            pkg_flush_sync,
        ):
            assert callable(fn)

    def test_registered_client_is_not_public(self) -> None:
        import arcjet.guard

        # Internal on purpose: the ADR does not define it, and the JavaScript
        # SDK tests that its equivalent stays unexported. Publishing it would
        # make removing it a breaking change.
        assert not hasattr(arcjet.guard, "registered_client")
        assert "registered_client" not in arcjet.guard.__all__

    def test_the_top_level_arcjet_namespace_does_not_define_guard(self) -> None:
        import arcjet
        import arcjet.guard

        # `from arcjet import guard` must keep meaning the module. If a function
        # named `guard` is ever added to arcjet/__init__.py, this fails — which
        # is the point.
        assert inspect.ismodule(arcjet.guard)
        assert "guard" not in getattr(arcjet, "__all__", ())

    def test_async_and_sync_pairs_are_distinct_callables(self) -> None:
        # The pairing is the whole reason both spellings exist; aliasing one to
        # the other would silently reintroduce the blocking-in-async problem.
        assert guard is not guard_sync
        assert flush is not flush_sync
        assert inspect.iscoroutinefunction(guard)
        assert not inspect.iscoroutinefunction(guard_sync)
        assert inspect.iscoroutinefunction(flush)
        assert not inspect.iscoroutinefunction(flush_sync)


class TestAtomicRegistryOperations:
    """The test client's register and teardown must be indivisible.

    Honest note on what these can and cannot prove. A genuine TOCTOU
    reproduction is not reliably expressible here — the window between a check
    and a following mutation is a couple of bytecodes, and threads racing on a
    barrier do not land inside it dependably. Tests written that way passed
    against the buggy implementation, so they were decoration.

    What is pinned instead is the property that makes the race impossible: both
    operations do their check *and* their mutation inside the registry lock, so
    there is no window to land in. If someone reintroduces a check-then-act by
    composing the public helpers, the atomicity tests below fail.
    """

    def test_test_registration_happens_inside_the_lock(self) -> None:
        import threading

        from arcjet.guard._registry import _lock, register_arcjet_for_testing

        finished = threading.Event()

        def attempt() -> None:
            try:
                register_arcjet_for_testing(sync_recorder())
            finally:
                finished.set()

        with _lock:
            worker = threading.Thread(target=attempt)
            worker.start()
            # Blocked: the occupancy check is inside the critical section, not
            # before it.
            assert not finished.wait(0.2)

        worker.join(timeout=2)
        assert finished.is_set()
        unregister_arcjet()

    def test_compare_and_clear_happens_inside_the_lock(self) -> None:
        import threading

        from arcjet.guard._registry import _lock, unregister_arcjet_if

        client = sync_recorder()
        register_arcjet(client)
        finished = threading.Event()

        def attempt() -> None:
            try:
                unregister_arcjet_if(client)
            finally:
                finished.set()

        with _lock:
            worker = threading.Thread(target=attempt)
            worker.start()
            assert not finished.wait(0.2)

        worker.join(timeout=2)
        assert finished.is_set()
        assert registered_client() is None

    def test_a_second_test_client_is_refused(self) -> None:
        from arcjet.guard.testing import register_test_client

        first = register_test_client()
        try:
            with pytest.raises(RuntimeError, match="already registered"):
                register_test_client()
        finally:
            first.unregister()

    def test_a_stale_client_cannot_clear_its_replacement(self) -> None:
        from arcjet.guard.testing import register_test_client

        first = register_test_client()
        first.unregister()

        second = register_test_client()
        try:
            # The stale handle must not clear a slot it no longer owns.
            first.unregister()

            assert registered_client() is second
        finally:
            second.unregister()

    def test_compare_and_clear_ignores_a_client_that_does_not_hold_the_slot(
        self,
    ) -> None:
        from arcjet.guard._registry import unregister_arcjet_if

        holder = sync_recorder()
        register_arcjet(holder)

        unregister_arcjet_if(sync_recorder())

        assert registered_client() is holder
