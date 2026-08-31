"""Claude Agent SDK wrap + hooks. Skips when the extra is absent."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from guard_doubles import StubGuardClient, make_allow_decision, make_deny_decision

pytest.importorskip(
    "claude_agent_sdk", reason="arcjet[claude-agent-sdk] extra is not installed"
)

from claude_agent_sdk import HookMatcher, SdkMcpTool, tool  # noqa: E402

from arcjet.guard.claude_agent_sdk import (  # noqa: E402
    claude_agent_context,
    guard_hooks,
    guard_tool,
)
from arcjet.guard.claude_agent_sdk._tool import _GUARD_BRAND  # noqa: E402

_ECHO_CALLS: list[str] = []
SESSION_ID = "550e8400-e29b-41d4-a716-446655440000"


@tool("echo", "Echo a value", {"value": str})
async def echo(args: dict[str, Any]) -> dict[str, Any]:
    _ECHO_CALLS.append(str(args["value"]))
    return {"content": [{"type": "text", "text": str(args["value"])}]}


@pytest.fixture(autouse=True)
def _clean_calls() -> Any:
    _ECHO_CALLS.clear()
    yield
    _ECHO_CALLS.clear()


def test_guard_tool_wraps_handler_and_returns_a_branded_copy() -> None:
    client = StubGuardClient(decision=make_allow_decision())
    guarded = guard_tool(guard=client, tool=echo, action="echo.invoked")
    assert isinstance(guarded, SdkMcpTool)
    assert guarded is not echo
    assert getattr(guarded, _GUARD_BRAND, False) is True
    assert getattr(echo, _GUARD_BRAND, False) is False
    assert guarded.handler is not echo.handler


def test_second_wrap_is_skipped() -> None:
    client = StubGuardClient(decision=make_allow_decision())
    first = guard_tool(guard=client, tool=echo, action="echo.invoked")
    second = guard_tool(guard=client, tool=first, action="echo.invoked")
    assert second is first


def test_deny_skips_handler_and_returns_envelope() -> None:
    client = StubGuardClient(decision=make_deny_decision())
    guarded = guard_tool(guard=client, tool=echo, action="echo.invoked")
    result = asyncio.run(guarded.handler({"value": "hello"}))
    assert _ECHO_CALLS == []
    assert result["is_error"] is True
    assert "structuredContent" not in result
    payload = json.loads(result["content"][0]["text"])
    assert payload["arcjetDenied"] is True


def test_allow_runs_handler() -> None:
    client = StubGuardClient(decision=make_allow_decision())
    guarded = guard_tool(guard=client, tool=echo, action="echo.invoked")
    result = asyncio.run(guarded.handler({"value": "hello"}))
    assert _ECHO_CALLS == ["hello"]
    assert result["is_error"] is not True
    assert result["content"][0]["text"] == "hello"


def test_handler_never_throws_on_unavailable() -> None:
    client = StubGuardClient(exception=RuntimeError("down"))
    guarded = guard_tool(guard=client, tool=echo, action="echo.invoked")
    result = asyncio.run(guarded.handler({"value": "hello"}))
    assert _ECHO_CALLS == []
    assert result["is_error"] is True
    assert json.loads(result["content"][0]["text"])["reason"] == "ERROR"


def test_guard_hooks_builds_real_matchers() -> None:
    client = StubGuardClient(decision=make_deny_decision())
    hooks = guard_hooks(
        guard=client,
        action=lambda hook: f"{hook['tool_name']}.invoked",
        exclude=[{"server": "support", "name": "echo"}],
        inbound={"action": "message.received"},
        session_id=SESSION_ID,
    )
    assert set(hooks) == {"PreToolUse", "UserPromptSubmit"}
    assert isinstance(hooks["PreToolUse"][0], HookMatcher)
    assert isinstance(hooks["UserPromptSubmit"][0], HookMatcher)

    pre = hooks["PreToolUse"][0].hooks[0]
    denied = asyncio.run(
        pre(
            {
                "hook_event_name": "PreToolUse",
                "session_id": SESSION_ID,
                "tool_name": "Bash",
                "tool_input": {"command": "ls"},
                "tool_use_id": "tu_1",
                "transcript_path": "/tmp/t",
                "cwd": "/tmp",
            },
            None,
            {"signal": None},
        )
    )
    assert denied["hookSpecificOutput"]["permissionDecision"] == "deny"

    skipped = asyncio.run(
        pre(
            {
                "hook_event_name": "PreToolUse",
                "session_id": SESSION_ID,
                "tool_name": "mcp__support__echo",
                "tool_input": {"value": "x"},
                "tool_use_id": "tu_2",
                "transcript_path": "/tmp/t",
                "cwd": "/tmp",
            },
            None,
            {"signal": None},
        )
    )
    assert skipped == {}

    inbound = hooks["UserPromptSubmit"][0].hooks[0]
    blocked = asyncio.run(
        inbound(
            {
                "hook_event_name": "UserPromptSubmit",
                "session_id": SESSION_ID,
                "prompt": "hello",
                "transcript_path": "/tmp/t",
                "cwd": "/tmp",
            },
            None,
            {"signal": None},
        )
    )
    assert blocked["decision"] == "block"


def test_claude_agent_context_reads_hook_session_id() -> None:
    ctx = claude_agent_context({"session_id": SESSION_ID, "agent_id": "sub-1"})
    assert ctx.correlation_id == SESSION_ID
    assert ctx.metadata is not None
    assert ctx.metadata["claude.agent"] == "sub-1"
