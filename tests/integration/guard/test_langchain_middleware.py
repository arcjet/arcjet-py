"""Integration tests for ArcjetMiddleware and langchain import isolation."""

from __future__ import annotations

import asyncio
import subprocess
import sys
from typing import cast

import pytest
from guard_doubles import (
    AsyncOnlyStubGuardClient,
    StubGuardClient,
    make_allow_decision,
    make_deny_decision,
)
from langchain_core.messages import ToolMessage
from langgraph.prebuilt.tool_node import ToolCallRequest, ToolRuntime

from arcjet.guard._client import ArcjetGuard, ArcjetGuardSync
from arcjet.guard._context import arcjet_sequence
from arcjet.guard._errors import ArcjetDeniedError, ArcjetUnavailableError
from arcjet.guard.langchain.middleware import ArcjetMiddleware, ToolPolicy


def _runtime() -> ToolRuntime:
    """A real ToolRuntime. The middleware never reads it, but the request it
    belongs to has to be the shape LangGraph actually passes."""
    return ToolRuntime(
        state={},
        context=None,
        config={},
        stream_writer=lambda _chunk: None,
        tool_call_id="call-1",
        store=None,
    )


class _SyncGuardStub(ArcjetGuardSync):
    """Test stub guard that passes isinstance checks.

    This is a minimal subclass of ArcjetGuardSync that delegates to a
    StubGuardClient for guard/capture methods while satisfying type checks.
    """

    def __init__(self, decision=None, exception=None):
        # Don't call super().__init__() - we're not a real guard
        self._stub = StubGuardClient(decision=decision, exception=exception)
        # Set minimal required fields to avoid AttributeError in dataclass
        self._key = "stub"
        self._client = None  # type: ignore
        self._timeout_ms = 0
        self._user_agent = "test"

    def guard_sync(self, **kwargs):
        return self._stub.guard_sync(**kwargs)

    def guard(self, **kwargs):  # type: ignore[override]
        # For compatibility with the flexible _blocking() method
        return self._stub.guard_sync(**kwargs)

    def capture(self, **kwargs):
        return self._stub.capture(**kwargs)

    @property
    def guards(self):
        return self._stub.guards

    @property
    def captures(self):
        return self._stub.captures


class _AsyncGuardStub(ArcjetGuard):
    """Test stub guard that passes isinstance checks for async.

    This is a minimal subclass of ArcjetGuard that delegates to a
    StubGuardClient for guard/capture methods while satisfying type checks.
    """

    def __init__(self, decision=None, exception=None):
        # Don't call super().__init__() - we're not a real guard
        self._stub = StubGuardClient(decision=decision, exception=exception)
        # Set minimal required fields to avoid AttributeError in dataclass
        self._key = "stub"
        self._client = None  # type: ignore
        self._timeout_ms = 0
        self._user_agent = "test"

    async def guard(self, **kwargs):  # type: ignore[override]
        # Call the underlying stub's async guard method
        return await self._stub.guard(**kwargs)

    def capture(self, **kwargs):
        return self._stub.capture(**kwargs)

    @property
    def guards(self):
        return self._stub.guards

    @property
    def captures(self):
        return self._stub.captures


class _AsyncOnlyGuardStub(ArcjetGuard):
    """Test stub guard with only async guard method (no sync).

    This passes isinstance checks for ArcjetGuard and has no guard_sync method.
    """

    def __init__(self, decision=None, exception=None):
        # Don't call super().__init__() - we're not a real guard
        self._stub = AsyncOnlyStubGuardClient(decision=decision, exception=exception)
        # Set minimal required fields to avoid AttributeError in dataclass
        self._key = "stub"
        self._client = None  # type: ignore
        self._timeout_ms = 0
        self._user_agent = "test"

    async def guard(self, **kwargs):  # type: ignore[override]
        return await self._stub.guard(**kwargs)

    def capture(self, **kwargs):
        # AsyncOnlyStubGuardClient doesn't have capture, but checkpoint expects it
        pass

    @property
    def guards(self):
        return self._stub.guards


class _SyncOnlyGuardStub(ArcjetGuardSync):
    """Test stub guard with only sync guard method (no async).

    This passes isinstance checks for ArcjetGuardSync and has no async guard method.
    """

    def __init__(self, decision=None, exception=None):
        # Don't call super().__init__() - we're not a real guard
        from guard_doubles import SyncOnlyStubGuardClient as SyncOnlyStub

        self._stub = SyncOnlyStub(decision=decision, exception=exception)
        # Set minimal required fields to avoid AttributeError in dataclass
        self._key = "stub"
        self._client = None  # type: ignore
        self._timeout_ms = 0
        self._user_agent = "test"

    def guard_sync(self, **kwargs):
        return self._stub.guard(**kwargs)

    def guard(self, **kwargs):  # type: ignore[override]
        # For compatibility with the flexible _blocking() method
        return self._stub.guard(**kwargs)

    def capture(self, **kwargs):
        pass

    @property
    def guards(self):
        return self._stub.guards


class TestImportIsolation:
    """Verify that arcjet.guard.langchain works without LangGraph."""

    def test_guard_tool_imports_without_langchain(self) -> None:
        """guard_tool must import successfully with langchain unimportable."""
        code = """
import sys

class ImportBlocker:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith(("langchain.agents", "langgraph")):
            raise ImportError(f"Blocked: {fullname}")
        return None

sys.meta_path.insert(0, ImportBlocker())

import arcjet.guard.langchain
from arcjet.guard.langchain import guard_tool

print("ok")
"""
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert result.stdout.strip() == "ok"
        assert result.stderr == ""

    def test_middleware_import_blocked_without_langgraph(self) -> None:
        """Middleware import must fail when langgraph is unimportable.

        This proves the blocker works and the above test is not vacuous.
        """
        code = """
import sys

class ImportBlocker:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith(("langchain.agents", "langgraph")):
            raise ImportError(f"Blocked: {fullname}")
        return None

sys.meta_path.insert(0, ImportBlocker())

try:
    import arcjet.guard.langchain.middleware
    print("ERROR: middleware should not import")
    sys.exit(1)
except ImportError:
    print("ok")
"""
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert result.stdout.strip() == "ok"
        assert result.stderr == ""


class TestDenialShortCircuit:
    """Denial must prevent handler invocation."""

    def test_wrap_tool_call_denies_without_calling_handler(self) -> None:
        """wrap_tool_call raises ArcjetDeniedError and skips handler."""
        handler_calls = 0

        def handler(request: ToolCallRequest) -> ToolMessage:
            nonlocal handler_calls
            handler_calls += 1
            return ToolMessage(content="result", tool_call_id="call_1")

        client = _SyncGuardStub(decision=make_deny_decision())
        middleware = ArcjetMiddleware(
            guard=client,
            policies={"test_tool": ToolPolicy(action="test.action")},
        )

        request = ToolCallRequest(
            tool_call={"name": "test_tool", "args": {}, "id": "call_1"},
            tool=None,
            state={},
            runtime=_runtime(),
        )

        with pytest.raises(ArcjetDeniedError):
            middleware.wrap_tool_call(request, handler)

        assert handler_calls == 0

    def test_awrap_tool_call_denies_without_calling_handler(self) -> None:
        """awrap_tool_call raises ArcjetDeniedError and skips handler."""
        handler_calls = 0

        async def handler(request: ToolCallRequest) -> ToolMessage:
            nonlocal handler_calls
            handler_calls += 1
            return ToolMessage(content="result", tool_call_id="call_1")

        client = _AsyncGuardStub(decision=make_deny_decision())
        middleware = ArcjetMiddleware(
            guard=client,
            policies={"test_tool": ToolPolicy(action="test.action")},
        )

        request = ToolCallRequest(
            tool_call={"name": "test_tool", "args": {}, "id": "call_1"},
            tool=None,
            state={},
            runtime=_runtime(),
        )

        with pytest.raises(ArcjetDeniedError):
            asyncio.run(middleware.awrap_tool_call(request, handler))

        assert handler_calls == 0


class TestAllowedPassthrough:
    """Allowed calls pass through with request unmodified."""

    def test_wrap_tool_call_handler_called_once_request_unchanged(self) -> None:
        """Handler runs exactly once and receives the same request."""
        handler_calls = 0
        received_request = None

        def handler(request: ToolCallRequest) -> ToolMessage:
            nonlocal handler_calls, received_request
            handler_calls += 1
            received_request = request
            return ToolMessage(content="result", tool_call_id="call_1")

        client = _SyncGuardStub(decision=make_allow_decision())
        middleware = ArcjetMiddleware(
            guard=client,
            policies={"test_tool": ToolPolicy(action="test.action")},
        )

        original_args = {"key": "value", "number": 42}
        request = ToolCallRequest(
            tool_call={"name": "test_tool", "args": original_args, "id": "call_1"},
            tool=None,
            state={},
            runtime=_runtime(),
        )

        result = middleware.wrap_tool_call(request, handler)

        assert handler_calls == 1
        assert received_request is request
        assert request.tool_call["args"] == original_args
        assert cast(ToolMessage, result).content == "result"

    def test_awrap_tool_call_handler_called_once_request_unchanged(self) -> None:
        """Handler runs exactly once and receives the same request."""
        handler_calls = 0
        received_request = None

        async def handler(request: ToolCallRequest) -> ToolMessage:
            nonlocal handler_calls, received_request
            handler_calls += 1
            received_request = request
            return ToolMessage(content="result", tool_call_id="call_1")

        client = _AsyncGuardStub(decision=make_allow_decision())
        middleware = ArcjetMiddleware(
            guard=client,
            policies={"test_tool": ToolPolicy(action="test.action")},
        )

        original_args = {"key": "value", "number": 42}
        request = ToolCallRequest(
            tool_call={"name": "test_tool", "args": original_args, "id": "call_1"},
            tool=None,
            state={},
            runtime=_runtime(),
        )

        result = asyncio.run(middleware.awrap_tool_call(request, handler))

        assert handler_calls == 1
        assert received_request is request
        assert request.tool_call["args"] == original_args
        assert cast(ToolMessage, result).content == "result"


class TestUnconfiguredTools:
    """Unconfigured tools bypass guarding."""

    def test_unconfigured_tool_no_guard_call_wrap(self) -> None:
        """Unconfigured tool passes to handler with no guard call."""
        handler_calls = 0

        def handler(request: ToolCallRequest) -> ToolMessage:
            nonlocal handler_calls
            handler_calls += 1
            return ToolMessage(content="result", tool_call_id="call_1")

        client = _SyncGuardStub(decision=make_allow_decision())
        middleware = ArcjetMiddleware(
            guard=client,
            policies={"configured_tool": ToolPolicy(action="test.action")},
        )

        request = ToolCallRequest(
            tool_call={"name": "unconfigured_tool", "args": {}, "id": "call_1"},
            tool=None,
            state={},
            runtime=_runtime(),
        )

        result = middleware.wrap_tool_call(request, handler)

        assert handler_calls == 1
        assert len(client.guards) == 0
        assert len(client.captures) == 0
        assert cast(ToolMessage, result).content == "result"

    def test_unconfigured_tool_no_guard_call_async(self) -> None:
        """Unconfigured tool passes to handler with no guard call."""
        handler_calls = 0

        async def handler(request: ToolCallRequest) -> ToolMessage:
            nonlocal handler_calls
            handler_calls += 1
            return ToolMessage(content="result", tool_call_id="call_1")

        client = _AsyncGuardStub(decision=make_allow_decision())
        middleware = ArcjetMiddleware(
            guard=client,
            policies={"configured_tool": ToolPolicy(action="test.action")},
        )

        request = ToolCallRequest(
            tool_call={"name": "unconfigured_tool", "args": {}, "id": "call_1"},
            tool=None,
            state={},
            runtime=_runtime(),
        )

        result = asyncio.run(middleware.awrap_tool_call(request, handler))

        assert handler_calls == 1
        assert len(client.guards) == 0
        assert len(client.captures) == 0
        assert cast(ToolMessage, result).content == "result"


class TestOnGuardError:
    """Guard errors are handled per policy."""

    def test_on_guard_error_deny_default_denies_handler(self) -> None:
        """Default on_guard_error='deny' denies and skips handler."""
        handler_calls = 0

        def handler(request: ToolCallRequest) -> ToolMessage:
            nonlocal handler_calls
            handler_calls += 1
            return ToolMessage(content="result", tool_call_id="call_1")

        guard_error = RuntimeError("guard failed")
        client = _SyncGuardStub(exception=guard_error)
        middleware = ArcjetMiddleware(
            guard=client,
            policies={"test_tool": ToolPolicy(action="test.action")},
        )

        request = ToolCallRequest(
            tool_call={"name": "test_tool", "args": {}, "id": "call_1"},
            tool=None,
            state={},
            runtime=_runtime(),
        )

        with pytest.raises(ArcjetUnavailableError):
            middleware.wrap_tool_call(request, handler)

        assert handler_calls == 0

    def test_on_guard_error_allow_passes_through(self) -> None:
        """on_guard_error='allow' passes through when guard raises."""
        handler_calls = 0

        def handler(request: ToolCallRequest) -> ToolMessage:
            nonlocal handler_calls
            handler_calls += 1
            return ToolMessage(content="result", tool_call_id="call_1")

        guard_error = RuntimeError("guard failed")
        client = _SyncGuardStub(exception=guard_error)
        middleware = ArcjetMiddleware(
            guard=client,
            policies={"test_tool": ToolPolicy(action="test.action")},
            on_guard_error="allow",
        )

        request = ToolCallRequest(
            tool_call={"name": "test_tool", "args": {}, "id": "call_1"},
            tool=None,
            state={},
            runtime=_runtime(),
        )

        result = middleware.wrap_tool_call(request, handler)

        assert handler_calls == 1
        assert cast(ToolMessage, result).content == "result"

    def test_on_guard_error_allow_passes_through_async(self) -> None:
        """on_guard_error='allow' passes through when guard raises (async)."""
        handler_calls = 0

        async def handler(request: ToolCallRequest) -> ToolMessage:
            nonlocal handler_calls
            handler_calls += 1
            return ToolMessage(content="result", tool_call_id="call_1")

        guard_error = RuntimeError("guard failed")
        client = _AsyncGuardStub(exception=guard_error)
        middleware = ArcjetMiddleware(
            guard=client,
            policies={"test_tool": ToolPolicy(action="test.action")},
            on_guard_error="allow",
        )

        request = ToolCallRequest(
            tool_call={"name": "test_tool", "args": {}, "id": "call_1"},
            tool=None,
            state={},
            runtime=_runtime(),
        )

        result = asyncio.run(middleware.awrap_tool_call(request, handler))

        assert handler_calls == 1
        assert cast(ToolMessage, result).content == "result"


class TestCapture:
    """Capture events record outcomes correctly."""

    def test_allowed_call_captures_success_with_correlation_id(self) -> None:
        """Allowed call emits capture with outcome='success' and correlation_id."""

        def handler(request: ToolCallRequest) -> ToolMessage:
            return ToolMessage(content="result", tool_call_id="call_1")

        client = _SyncGuardStub(decision=make_allow_decision())
        middleware = ArcjetMiddleware(
            guard=client,
            policies={"test_tool": ToolPolicy(action="test.action")},
        )

        request = ToolCallRequest(
            tool_call={"name": "test_tool", "args": {}, "id": "call_1"},
            tool=None,
            state={},
            runtime=_runtime(),
        )

        with arcjet_sequence(correlation_id="corr-1"):
            middleware.wrap_tool_call(request, handler)

        assert len(client.captures) == 1
        capture = client.captures[0]
        assert capture["correlation_id"] == "corr-1"
        assert capture["metadata"]["outcome"] == "success"

    def test_denied_call_captures_denied_with_correlation_id(self) -> None:
        """Denied call emits capture with outcome='denied' and correlation_id."""

        def handler(request: ToolCallRequest) -> ToolMessage:
            return ToolMessage(content="result", tool_call_id="call_1")

        client = _SyncGuardStub(decision=make_deny_decision())
        middleware = ArcjetMiddleware(
            guard=client,
            policies={"test_tool": ToolPolicy(action="test.action")},
        )

        request = ToolCallRequest(
            tool_call={"name": "test_tool", "args": {}, "id": "call_1"},
            tool=None,
            state={},
            runtime=_runtime(),
        )

        with arcjet_sequence(correlation_id="corr-1"):
            with pytest.raises(ArcjetDeniedError):
                middleware.wrap_tool_call(request, handler)

        assert len(client.captures) == 1
        capture = client.captures[0]
        assert capture["correlation_id"] == "corr-1"
        assert capture["metadata"]["outcome"] == "denied"

    def test_allowed_call_captures_success_async(self) -> None:
        """Allowed async call emits capture with outcome='success'."""

        async def handler(request: ToolCallRequest) -> ToolMessage:
            return ToolMessage(content="result", tool_call_id="call_1")

        client = _AsyncGuardStub(decision=make_allow_decision())
        middleware = ArcjetMiddleware(
            guard=client,
            policies={"test_tool": ToolPolicy(action="test.action")},
        )

        request = ToolCallRequest(
            tool_call={"name": "test_tool", "args": {}, "id": "call_1"},
            tool=None,
            state={},
            runtime=_runtime(),
        )

        with arcjet_sequence(correlation_id="corr-2"):
            asyncio.run(middleware.awrap_tool_call(request, handler))

        assert len(client.captures) == 1
        capture = client.captures[0]
        assert capture["correlation_id"] == "corr-2"
        assert capture["metadata"]["outcome"] == "success"

    def test_denied_call_captures_denied_async(self) -> None:
        """Denied async call emits capture with outcome='denied'."""

        async def handler(request: ToolCallRequest) -> ToolMessage:
            return ToolMessage(content="result", tool_call_id="call_1")

        client = _AsyncGuardStub(decision=make_deny_decision())
        middleware = ArcjetMiddleware(
            guard=client,
            policies={"test_tool": ToolPolicy(action="test.action")},
        )

        request = ToolCallRequest(
            tool_call={"name": "test_tool", "args": {}, "id": "call_1"},
            tool=None,
            state={},
            runtime=_runtime(),
        )

        with arcjet_sequence(correlation_id="corr-2"):
            with pytest.raises(ArcjetDeniedError):
                asyncio.run(middleware.awrap_tool_call(request, handler))

        assert len(client.captures) == 1
        capture = client.captures[0]
        assert capture["correlation_id"] == "corr-2"
        assert capture["metadata"]["outcome"] == "denied"


class TestSyncGuardTypeChecking:
    """Sync/async guard type checking is enforced."""

    def test_wrap_tool_call_requires_sync_guard(self) -> None:
        """wrap_tool_call requires ArcjetGuardSync."""

        def handler(request: ToolCallRequest) -> ToolMessage:
            return ToolMessage(content="result", tool_call_id="call_1")

        # Use async-only guard to trigger type error
        client = _AsyncOnlyGuardStub(decision=make_allow_decision())
        middleware = ArcjetMiddleware(
            guard=client,
            policies={"test_tool": ToolPolicy(action="test.action")},
        )

        request = ToolCallRequest(
            tool_call={"name": "test_tool", "args": {}, "id": "call_1"},
            tool=None,
            state={},
            runtime=_runtime(),
        )

        with pytest.raises(TypeError, match="synchronous"):
            middleware.wrap_tool_call(request, handler)

    def test_awrap_tool_call_requires_async_guard(self) -> None:
        """awrap_tool_call requires ArcjetGuard."""

        async def handler(request: ToolCallRequest) -> ToolMessage:
            return ToolMessage(content="result", tool_call_id="call_1")

        client = _SyncOnlyGuardStub(decision=make_allow_decision())
        middleware = ArcjetMiddleware(
            guard=client,
            policies={"test_tool": ToolPolicy(action="test.action")},
        )

        request = ToolCallRequest(
            tool_call={"name": "test_tool", "args": {}, "id": "call_1"},
            tool=None,
            state={},
            runtime=_runtime(),
        )

        with pytest.raises(TypeError, match="asynchronous"):
            asyncio.run(middleware.awrap_tool_call(request, handler))
