"""Strands Agents wrap + hooks. Skips when ``arcjet[strands-agents]`` is absent."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from guard_doubles import StubGuardClient, make_allow_decision, make_deny_decision

pytest.importorskip("strands", reason="arcjet[strands-agents] extra is not installed")

from strands import tool  # noqa: E402
from strands.hooks import AfterToolCallEvent, BeforeToolCallEvent  # noqa: E402
from strands.tools.decorator import DecoratedFunctionTool  # noqa: E402

from arcjet.guard.strands_agents import (  # noqa: E402
    guard_hooks,
    guard_tool,
    strands_agent_context,
)
from arcjet.guard.strands_agents._tool import _GUARD_BRAND  # noqa: E402

_ECHO_CALLS: list[str] = []


@tool
def echo(value: str) -> str:
    """Echo a value."""
    _ECHO_CALLS.append(value)
    return value


@pytest.fixture(autouse=True)
def _clean_calls() -> Any:
    _ECHO_CALLS.clear()
    yield
    _ECHO_CALLS.clear()


class _Registry:
    def __init__(self) -> None:
        self.callbacks: list[tuple[Any, Any]] = []

    def add_callback(self, event_type: Any, callback: Any, **_kwargs: Any) -> None:
        self.callbacks.append((event_type, callback))


def test_guard_tool_wraps_handler_and_returns_a_branded_copy() -> None:
    client = StubGuardClient(decision=make_allow_decision())
    guarded = guard_tool(guard=client, tool=echo, action="echo.invoked")
    assert isinstance(guarded, DecoratedFunctionTool)
    assert guarded is not echo
    assert getattr(guarded, _GUARD_BRAND, False) is True
    assert getattr(echo, _GUARD_BRAND, False) is False
    assert guarded._tool_func is not echo._tool_func


def test_second_wrap_is_skipped() -> None:
    client = StubGuardClient(decision=make_allow_decision())
    first = guard_tool(guard=client, tool=echo, action="echo.invoked")
    second = guard_tool(guard=client, tool=first, action="echo.invoked")
    assert second is first


def test_deny_skips_handler_and_returns_payload() -> None:
    client = StubGuardClient(decision=make_deny_decision())
    guarded = guard_tool(guard=client, tool=echo, action="echo.invoked")
    result = asyncio.run(guarded._tool_func(value="hello"))
    assert _ECHO_CALLS == []
    assert result["arcjetDenied"] is True
    assert result["reason"] == "RATE_LIMIT"


def test_allow_runs_handler() -> None:
    client = StubGuardClient(decision=make_allow_decision())
    guarded = guard_tool(guard=client, tool=echo, action="echo.invoked")
    result = asyncio.run(guarded._tool_func(value="hello"))
    assert _ECHO_CALLS == ["hello"]
    assert result == "hello"


def test_handler_never_throws_on_unavailable() -> None:
    client = StubGuardClient(exception=RuntimeError("down"))
    guarded = guard_tool(guard=client, tool=echo, action="echo.invoked")
    result = asyncio.run(guarded._tool_func(value="hello"))
    assert _ECHO_CALLS == []
    assert result["reason"] == "ERROR"
    assert result["retryable"] is True


def test_guard_hooks_registers_per_tool_events_not_batch_cancel() -> None:
    client = StubGuardClient(decision=make_deny_decision())
    hooks = guard_hooks(guard=client, action="echo.invoked")
    registry = _Registry()
    hooks.register_hooks(registry)
    event_types = {event_type for event_type, _callback in registry.callbacks}
    assert BeforeToolCallEvent in event_types
    assert AfterToolCallEvent in event_types
    assert all(event_type.__name__ != "BeforeToolsEvent" for event_type in event_types)


def test_strands_agent_context_reads_invocation_state() -> None:
    ctx = strands_agent_context({"correlationId": "corr-1", "sessionId": "sess-1"})
    assert ctx.correlation_id == "corr-1"
    assert ctx.metadata is not None
    assert ctx.metadata["strands.session"] == "sess-1"


def test_public_exports_are_only_the_locked_names() -> None:
    from arcjet.guard import strands_agents as adapter

    assert adapter.__all__ == ["guard_tool", "guard_hooks", "strands_agent_context"]
    assert not hasattr(adapter, "guard_inbound")
    assert not hasattr(adapter, "guard_approval")
