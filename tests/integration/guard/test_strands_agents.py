"""Strands Agents wrap + hooks. Skips when ``arcjet[strands-agents]`` is absent."""

from __future__ import annotations

import asyncio
import json
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


def _tool_use(*, value: str = "hello") -> dict[str, Any]:
    return {"name": "echo", "input": {"value": value}, "toolUseId": "tu_1"}


def _stream_events(guarded: Any, *, value: str = "hello", **state: Any) -> list[Any]:
    async def collect() -> list[Any]:
        return [
            event async for event in guarded.stream(_tool_use(value=value), dict(state))
        ]

    return asyncio.run(collect())


def _tool_result_payload(event: Any) -> dict[str, Any]:
    """JSON the model would read from a stream event / tool result."""
    result = getattr(event, "tool_result", None)
    if result is None:
        result = getattr(event, "result", None)
    if result is None and isinstance(event, dict):
        result = event
    if not isinstance(result, dict):
        raise AssertionError(f"unrecognized stream event: {event!r}")
    assert result["status"] == "error"
    return json.loads(result["content"][0]["text"])


def test_guard_tool_wraps_stream_and_returns_a_branded_copy() -> None:
    client = StubGuardClient(decision=make_allow_decision())
    guarded = guard_tool(guard=client, tool=echo, action="echo.invoked")
    assert isinstance(guarded, DecoratedFunctionTool)
    assert guarded is not echo
    assert getattr(guarded, _GUARD_BRAND, False) is True
    assert getattr(echo, _GUARD_BRAND, False) is False
    assert guarded.stream is not echo.stream
    assert guarded._tool_func is echo._tool_func
    assert guarded._tool_func.__name__ == "echo"


def test_second_wrap_is_skipped() -> None:
    client = StubGuardClient(decision=make_allow_decision())
    first = guard_tool(guard=client, tool=echo, action="echo.invoked")
    second = guard_tool(guard=client, tool=first, action="echo.invoked")
    assert second is first


def test_deny_skips_handler_and_stream_yields_json_envelope() -> None:
    client = StubGuardClient(decision=make_deny_decision())
    guarded = guard_tool(guard=client, tool=echo, action="echo.invoked")
    events = _stream_events(guarded, sessionId="sess-1")
    assert _ECHO_CALLS == []
    payload = _tool_result_payload(events[-1])
    assert payload["arcjetDenied"] is True
    assert payload["reason"] == "RATE_LIMIT"
    assert client.guards[0]["correlation_id"] == "sess-1"


def test_allow_runs_handler_through_stream() -> None:
    client = StubGuardClient(decision=make_allow_decision())
    guarded = guard_tool(guard=client, tool=echo, action="echo.invoked")
    events = _stream_events(guarded, value="hello", sessionId="sess-1")
    assert _ECHO_CALLS == ["hello"]
    result = getattr(events[-1], "tool_result", None) or getattr(
        events[-1], "result", None
    )
    assert isinstance(result, dict)
    assert result["status"] == "success"
    assert result["content"][0]["text"] == "hello"
    assert client.guards[0]["correlation_id"] == "sess-1"


def test_stream_never_throws_on_unavailable() -> None:
    client = StubGuardClient(exception=RuntimeError("down"))
    guarded = guard_tool(guard=client, tool=echo, action="echo.invoked")
    events = _stream_events(guarded)
    assert _ECHO_CALLS == []
    payload = _tool_result_payload(events[-1])
    assert payload["reason"] == "ERROR"
    assert payload["retryable"] is True


def test_tool_kwargs_are_not_correlation_ids() -> None:
    client = StubGuardClient(decision=make_allow_decision())
    guarded = guard_tool(guard=client, tool=echo, action="echo.invoked")
    asyncio.run(
        _consume(
            guarded.stream(
                {
                    "name": "echo",
                    "input": {"value": "hello", "session_id": "model-controlled"},
                    "toolUseId": "tu_1",
                },
                {},
            )
        )
    )
    assert client.guards[0]["correlation_id"] is None


async def _consume(stream: Any) -> list[Any]:
    return [event async for event in stream]


def test_guard_hooks_registers_per_tool_events_not_batch_cancel() -> None:
    client = StubGuardClient(decision=make_deny_decision())
    hooks = guard_hooks(guard=client, action="echo.invoked")
    registry = _Registry()
    hooks.register_hooks(registry)
    event_types = {event_type for event_type, _callback in registry.callbacks}
    assert BeforeToolCallEvent in event_types
    assert AfterToolCallEvent in event_types
    assert all(event_type.__name__ != "BeforeToolsEvent" for event_type in event_types)


def _before_callback(hooks: Any) -> Any:
    registry = _Registry()
    hooks.register_hooks(registry)
    for event_type, callback in registry.callbacks:
        if event_type is BeforeToolCallEvent:
            return callback
    raise AssertionError("BeforeToolCallEvent callback was not registered")


def _make_before_event(*, selected_tool: Any, **kwargs: Any) -> BeforeToolCallEvent:
    fields: dict[str, Any] = {
        "selected_tool": selected_tool,
        "tool_use": _tool_use(),
        "invocation_state": {"sessionId": "sess-hook"},
        "cancel_tool": False,
    }
    fields.update(kwargs)
    try:
        return BeforeToolCallEvent(agent=None, **fields)  # type: ignore[arg-type]
    except TypeError:
        return BeforeToolCallEvent(**fields)


def test_before_tool_call_sets_cancel_tool_to_json() -> None:
    client = StubGuardClient(decision=make_deny_decision())
    hooks = guard_hooks(guard=client, action="echo.invoked")
    event = _make_before_event(selected_tool=echo)
    asyncio.run(_before_callback(hooks)(event))
    assert event.cancel_tool not in (False, True, None)
    payload = json.loads(str(event.cancel_tool))
    assert payload["arcjetDenied"] is True
    assert payload["reason"] == "RATE_LIMIT"
    assert client.guards[0]["correlation_id"] == "sess-hook"


def test_before_tool_call_skips_branded_tool() -> None:
    client = StubGuardClient(decision=make_deny_decision())
    guarded = guard_tool(guard=client, tool=echo, action="echo.invoked")
    hooks = guard_hooks(guard=client, action="echo.invoked")
    event = _make_before_event(selected_tool=guarded)
    asyncio.run(_before_callback(hooks)(event))
    assert event.cancel_tool is False
    assert client.guards == []


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
