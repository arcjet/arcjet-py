"""CrewAI hook + wrap integration. Skips when ``arcjet[crewai]`` is absent."""

from __future__ import annotations

from typing import Any

import pytest
from guard_doubles import StubGuardClient, make_allow_decision, make_deny_decision

pytest.importorskip("crewai", reason="arcjet[crewai] extra is not installed")

from crewai.hooks import (  # noqa: E402
    HookAborted,
    InterceptionPoint,
    clear_hooks,
    get_hooks,
)
from crewai.hooks.tool_hooks import (  # noqa: E402
    ToolCallHookContext,
    run_after_tool_call_hooks,
    run_before_tool_call_hooks,
)
from crewai.tools.base_tool import BaseTool  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

from arcjet.guard import ArcjetDeniedError, ArcjetUnavailableError  # noqa: E402
from arcjet.guard._types import RuleResultError  # noqa: E402
from arcjet.guard.crewai import (  # noqa: E402
    register_arcjet_hooks,
    sanitize_tool_name,
    unregister_arcjet_hooks,
)
from arcjet.guard.crewai._tool import guard_tool  # noqa: E402


class _EchoArgs(BaseModel):
    value: str = Field(description="text")


_ECHO_CALLS: list[str] = []


class _EchoTool(BaseTool):
    name: str = "echo"
    description: str = "echo a value"
    args_schema: type[BaseModel] = _EchoArgs

    def _run(self, value: str) -> str:
        _ECHO_CALLS.append(value)
        return value


class _DummyStructured:
    name = "echo"


def _context(tool: Any = None, **kwargs: Any) -> ToolCallHookContext:
    return ToolCallHookContext(
        tool_name=kwargs.get("tool_name", "echo"),
        tool_input=kwargs.get("tool_input", {"value": "hello"}),
        tool=tool if tool is not None else _DummyStructured(),
        agent=kwargs.get("agent"),
        task=kwargs.get("task"),
        crew=kwargs.get("crew"),
        tool_result=kwargs.get("tool_result"),
    )


@pytest.fixture(autouse=True)
def _clean_hooks():
    clear_hooks(InterceptionPoint.PRE_TOOL_CALL)
    clear_hooks(InterceptionPoint.POST_TOOL_CALL)
    yield
    clear_hooks(InterceptionPoint.PRE_TOOL_CALL)
    clear_hooks(InterceptionPoint.POST_TOOL_CALL)


def _execute(ctx: ToolCallHookContext, tool_fn: Any) -> str:
    """The executor shape CrewAI uses: PRE can block; POST always runs."""
    if run_before_tool_call_hooks(ctx):
        blocked = f"Tool execution blocked by hook. Tool: {ctx.tool_name}"
        blocked_ctx = ToolCallHookContext(
            tool_name=ctx.tool_name,
            tool_input=ctx.tool_input,
            tool=ctx.tool,
            agent=ctx.agent,
            task=ctx.task,
            crew=ctx.crew,
            tool_result=blocked,
            raw_tool_result=blocked,
        )
        modified = run_after_tool_call_hooks(blocked_ctx)
        return modified if modified is not None else blocked
    result = tool_fn()
    ctx.tool_result = result
    modified = run_after_tool_call_hooks(ctx)
    return modified if modified is not None else result


def test_pre_tool_call_deny_never_runs_the_tool() -> None:
    client = StubGuardClient(decision=make_deny_decision())
    handle = register_arcjet_hooks(guard=client, action="echo.invoked")
    ran: list[str] = []

    result = _execute(_context(), lambda: ran.append("ran") or "ok")

    assert ran == []
    assert result == "Tool execution blocked by hook. Tool: echo"
    assert client.captures[0]["metadata"]["outcome"] == "denied"
    unregister_arcjet_hooks(handle)


def test_hook_aborted_source_is_arcjet() -> None:
    client = StubGuardClient(decision=make_deny_decision())
    register_arcjet_hooks(guard=client, action="echo.invoked")
    hooks = get_hooks(InterceptionPoint.PRE_TOOL_CALL)
    with pytest.raises(HookAborted) as exc_info:
        hooks[0](_context())
    assert exc_info.value.source == "arcjet"
    assert "echo.invoked" in exc_info.value.reason


def test_pre_tool_call_allow_runs_the_tool() -> None:
    client = StubGuardClient(decision=make_allow_decision())
    register_arcjet_hooks(guard=client, action="echo.invoked")
    ran: list[str] = []

    result = _execute(_context(), lambda: ran.append("ran") or "ok")

    assert ran == ["ran"]
    assert result == "ok"
    assert client.captures[0]["metadata"]["outcome"] == "success"


def test_fail_closed_on_guard_error() -> None:
    client = StubGuardClient(exception=RuntimeError("down"))
    register_arcjet_hooks(guard=client, action="echo.invoked")
    ran: list[str] = []

    result = _execute(_context(), lambda: ran.append("ran") or "ok")

    assert ran == []
    assert result.startswith("Tool execution blocked by hook.")
    assert client.captures[0]["metadata"]["outcome"] == "unavailable"


def test_failed_open_fail_closed() -> None:
    decision = make_allow_decision(
        results=(RuleResultError(code="TIMEOUT", message="deadline"),)
    )
    client = StubGuardClient(decision=decision)
    register_arcjet_hooks(guard=client)
    ran: list[str] = []
    result = _execute(_context(), lambda: ran.append("ran") or "ok")
    assert ran == []
    assert result.startswith("Tool execution blocked by hook.")


def test_post_does_not_change_blocked_or_allowed_result() -> None:
    deny = StubGuardClient(decision=make_deny_decision())
    register_arcjet_hooks(guard=deny, action="echo.invoked")
    blocked = _execute(_context(), lambda: "should-not-run")
    assert blocked == "Tool execution blocked by hook. Tool: echo"

    clear_hooks(InterceptionPoint.PRE_TOOL_CALL)
    clear_hooks(InterceptionPoint.POST_TOOL_CALL)
    allow = StubGuardClient(decision=make_allow_decision())
    register_arcjet_hooks(guard=allow, action="echo.invoked")
    assert _execute(_context(), lambda: "kept") == "kept"


def test_correlation_is_caller_owned() -> None:
    client = StubGuardClient(decision=make_allow_decision())
    register_arcjet_hooks(
        guard=client, action="echo.invoked", correlation_id="user-session"
    )
    _execute(_context(), lambda: "ok")
    assert client.guards[0]["correlation_id"] == "user-session"


def test_sanitize_matches_installed_crewai() -> None:
    from crewai.utilities.string_utils import sanitize_tool_name as crewai_sanitize

    for name in ("Send Email", "sendEmail", "HTTPRequest", "already_sane"):
        assert sanitize_tool_name(name) == crewai_sanitize(name)


def test_guard_tool_deny_raises_arcjet_error_and_skips_body() -> None:
    _ECHO_CALLS.clear()
    tool = _EchoTool()
    client = StubGuardClient(decision=make_deny_decision())
    guarded = guard_tool(guard=client, tool=tool, action="echo.invoked")
    with pytest.raises(ArcjetDeniedError):
        guarded.run(value="hello")
    assert _ECHO_CALLS == []


def test_guard_tool_unavailable_raises_arcjet_error() -> None:
    _ECHO_CALLS.clear()
    tool = _EchoTool()
    client = StubGuardClient(exception=RuntimeError("down"))
    guarded = guard_tool(guard=client, tool=tool, action="echo.invoked")
    with pytest.raises(ArcjetUnavailableError):
        guarded.run(value="hello")
    assert _ECHO_CALLS == []


def test_guard_tool_allow_runs_the_tool() -> None:
    _ECHO_CALLS.clear()
    tool = _EchoTool()
    client = StubGuardClient(decision=make_allow_decision())
    guarded = guard_tool(guard=client, tool=tool, action="echo.invoked")
    assert guarded.run(value="hello") == "hello"
    assert _ECHO_CALLS == ["hello"]


def test_hook_skips_already_wrapped_tool() -> None:
    tool = _EchoTool()
    client = StubGuardClient(decision=make_deny_decision())
    guarded = guard_tool(guard=client, tool=tool, action="echo.invoked")
    hook_client = StubGuardClient(decision=make_deny_decision())
    register_arcjet_hooks(guard=hook_client, action="echo.invoked")

    class _Structured:
        name = "echo"
        _original_tool = guarded

    ctx = _context(tool=_Structured())
    ran: list[str] = []
    result = _execute(ctx, lambda: ran.append("ran") or "ok")
    assert ran == ["ran"]
    assert result == "ok"
    assert hook_client.guards == []
