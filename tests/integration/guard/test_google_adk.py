"""Google ADK callback + plugin. Skips when ``arcjet[google-adk]`` is absent."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from guard_doubles import StubGuardClient, make_allow_decision, make_deny_decision

pytest.importorskip("google.adk", reason="arcjet[google-adk] extra is not installed")

from google.adk.plugins.base_plugin import BasePlugin  # noqa: E402
from google.adk.tools.function_tool import FunctionTool  # noqa: E402

from arcjet.guard.google_adk import (  # noqa: E402
    google_adk_context,
    guard_plugin,
    guard_tool,
)

_ECHO_CALLS: list[str] = []


def echo(value: str) -> dict[str, str]:
    """Echo a value."""
    _ECHO_CALLS.append(value)
    return {"value": value}


@pytest.fixture(autouse=True)
def _clean_calls() -> Any:
    _ECHO_CALLS.clear()
    yield
    _ECHO_CALLS.clear()


def _run_agent_callback(callback: Any, tool: Any, args: dict[str, Any]) -> Any:
    return asyncio.run(callback(tool, args, object()))


def test_guard_plugin_is_a_base_plugin() -> None:
    client = StubGuardClient(decision=make_allow_decision())
    plugin = guard_plugin(guard=client, action="echo.invoked")
    assert isinstance(plugin, BasePlugin)
    assert plugin.name.startswith("arcjet-guard-")


def test_allow_plugin_returns_none_and_tool_can_run() -> None:
    client = StubGuardClient(decision=make_allow_decision())
    plugin = guard_plugin(guard=client, action="echo.invoked")
    tool = FunctionTool(echo)
    result = asyncio.run(
        plugin.before_tool_callback(
            tool=tool, tool_args={"value": "hello"}, tool_context=object()
        )
    )
    assert result is None
    assert echo("hello") == {"value": "hello"}
    assert _ECHO_CALLS[-1] == "hello"


def test_deny_plugin_returns_dict_and_tool_function_does_not_run() -> None:
    client = StubGuardClient(decision=make_deny_decision())
    plugin = guard_plugin(guard=client, action="echo.invoked")
    tool = FunctionTool(echo)
    before = list(_ECHO_CALLS)
    result = asyncio.run(
        plugin.before_tool_callback(
            tool=tool, tool_args={"value": "blocked"}, tool_context=object()
        )
    )
    assert result is not None
    assert result != {}
    assert result["arcjetDenied"] is True
    assert _ECHO_CALLS == before


def test_guard_tool_callback_allow_is_none() -> None:
    client = StubGuardClient(decision=make_allow_decision())
    callback = guard_tool(guard=client, action="echo.invoked")
    tool = FunctionTool(echo)
    result = _run_agent_callback(callback, tool, {"value": "hello"})
    assert result is None


def test_guard_tool_callback_deny_skips_function() -> None:
    client = StubGuardClient(decision=make_deny_decision())
    callback = guard_tool(guard=client, action="echo.invoked")
    tool = FunctionTool(echo)
    before = list(_ECHO_CALLS)
    result = _run_agent_callback(callback, tool, {"value": "blocked"})
    assert isinstance(result, dict)
    assert result["arcjetDenied"] is True
    assert _ECHO_CALLS == before


def test_context_helper_reads_caller_owned_id() -> None:
    ctx = google_adk_context({"context": {"session_id": "sess-adk"}})
    assert ctx.correlation_id == "sess-adk"
    assert ctx.metadata is not None
    assert ctx.metadata["google-adk.session"] == "sess-adk"
