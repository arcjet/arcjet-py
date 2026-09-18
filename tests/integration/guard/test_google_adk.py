"""Google ADK callback / plugin integration. Skips when the extra is absent."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest
from guard_doubles import StubGuardClient, make_allow_decision, make_deny_decision

pytest.importorskip("google.adk", reason="arcjet[google-adk] extra is not installed")

from google.adk.plugins.base_plugin import BasePlugin  # noqa: E402

from arcjet.guard.google_adk import guard_plugin, guard_tool  # noqa: E402
from arcjet.guard.google_adk._plugin import _PLUGIN_NAME  # noqa: E402


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _tool(name: str = "echo") -> SimpleNamespace:
    return SimpleNamespace(name=name)


def test_plugin_is_base_plugin_named_arcjet() -> None:
    plugin = guard_plugin(guard=StubGuardClient(decision=make_allow_decision()))
    assert isinstance(plugin, BasePlugin)
    assert plugin.name == _PLUGIN_NAME


def test_plugin_allow_returns_none() -> None:
    client = StubGuardClient(decision=make_allow_decision())
    plugin = guard_plugin(guard=client, action="echo.invoked")
    result = _run(
        plugin.before_tool_callback(
            tool=_tool(),
            tool_args={"value": "hello"},
            tool_context=SimpleNamespace(state={}),
        )
    )
    assert result is None
    assert len(client.guards) == 1


def test_plugin_deny_returns_skip_dict() -> None:
    client = StubGuardClient(decision=make_deny_decision())
    plugin = guard_plugin(guard=client, action="echo.invoked")
    result = _run(
        plugin.before_tool_callback(
            tool=_tool(),
            tool_args={"value": "hello"},
            tool_context=SimpleNamespace(state={}),
        )
    )
    assert result is not None
    assert result != {}
    assert result["arcjetDenied"] is True
    assert result["reason"] == "RATE_LIMIT"


def test_plugin_unavailable_fail_closed() -> None:
    client = StubGuardClient(exception=RuntimeError("down"))
    plugin = guard_plugin(guard=client, action="echo.invoked")
    result = _run(
        plugin.before_tool_callback(
            tool=_tool(),
            tool_args={"value": "hello"},
            tool_context=SimpleNamespace(state={}),
        )
    )
    assert result is not None
    assert result["reason"] == "ERROR"
    assert result["retryable"] is True


def test_plugin_default_action_is_tool_invoked() -> None:
    client = StubGuardClient(decision=make_allow_decision())
    plugin = guard_plugin(guard=client)
    _run(
        plugin.before_tool_callback(
            tool=_tool("lookup_order"),
            tool_args={"order": "1"},
            tool_context=SimpleNamespace(state={}),
        )
    )
    assert client.guards[0]["label"] == "lookup_order.invoked"


def test_plugin_exclude_skips_named_tool() -> None:
    client = StubGuardClient(decision=make_deny_decision())
    plugin = guard_plugin(
        guard=client,
        action="echo.invoked",
        exclude=["send_email"],
    )
    result = _run(
        plugin.before_tool_callback(
            tool=_tool("send_email"),
            tool_args={"to": "a@example.com"},
            tool_context=SimpleNamespace(state={}),
        )
    )
    assert result is None
    assert client.guards == []


def test_guard_tool_callback_allow_and_deny() -> None:
    allow_client = StubGuardClient(decision=make_allow_decision())
    callback = guard_tool(guard=allow_client, action="echo.invoked")
    assert (
        _run(callback(tool=_tool(), args={"value": "hello"}, tool_context={})) is None
    )

    deny_client = StubGuardClient(decision=make_deny_decision())
    callback = guard_tool(guard=deny_client, action="echo.invoked")
    result = _run(callback(tool=_tool(), args={"value": "hello"}, tool_context={}))
    assert result is not None
    assert result["arcjetDenied"] is True
