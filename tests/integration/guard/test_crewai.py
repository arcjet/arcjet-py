"""CrewAI hook + wrap integration. Skips when ``arcjet[crewai]`` is absent."""

from __future__ import annotations

import asyncio
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
from crewai.tools.base_tool import BaseTool, Tool  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

from arcjet._errors import ArcjetMisconfiguration  # noqa: E402
from arcjet.guard import ArcjetDeniedError, ArcjetUnavailableError  # noqa: E402
from arcjet.guard._types import RuleResultError  # noqa: E402
from arcjet.guard.crewai import _hooks as hooks_module  # noqa: E402
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


class _Structured:
    """The shape CrewAI hands a hook: a structured tool over a ``BaseTool``."""

    name = "echo"

    def __init__(self, original: Any = None) -> None:
        if original is not None:
            self._original_tool = original


def _context(tool: Any = None, **kwargs: Any) -> ToolCallHookContext:
    return ToolCallHookContext(
        tool_name=kwargs.get("tool_name", "echo"),
        tool_input=kwargs.get("tool_input", {"value": "hello"}),
        tool=tool if tool is not None else _Structured(),
        agent=kwargs.get("agent"),
        task=kwargs.get("task"),
        crew=kwargs.get("crew"),
        tool_result=kwargs.get("tool_result"),
    )


@pytest.fixture(autouse=True)
def _clean_hooks():
    """Leave CrewAI's global registry, and Arcjet's record of it, empty.

    Both halves matter: ``clear_all_hooks`` does not tell this package its
    registration is gone, and a leaked record makes the next registration
    raise in an unrelated test.
    """
    _ECHO_CALLS.clear()
    yield
    clear_hooks(InterceptionPoint.PRE_TOOL_CALL)
    clear_hooks(InterceptionPoint.POST_TOOL_CALL)
    hooks_module._registered = None


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


def test_post_tool_call_is_not_registered() -> None:
    """POST fires on blocked calls, so it is not a policy surface at all."""
    client = StubGuardClient(decision=make_allow_decision())
    register_arcjet_hooks(guard=client, action="echo.invoked")
    assert get_hooks(InterceptionPoint.POST_TOOL_CALL) == []
    assert _execute(_context(), lambda: "kept") == "kept"


def test_correlation_is_caller_owned() -> None:
    client = StubGuardClient(decision=make_allow_decision())
    register_arcjet_hooks(
        guard=client, action="echo.invoked", correlation_id="user-session"
    )
    _execute(_context(), lambda: "ok")
    assert client.guards[0]["correlation_id"] == "user-session"


def test_second_registration_is_refused() -> None:
    """CrewAI's registry appends, so a second hook would double-charge."""
    client = StubGuardClient(decision=make_allow_decision())
    handle = register_arcjet_hooks(guard=client, action="echo.invoked")
    with pytest.raises(ArcjetMisconfiguration, match="already registered"):
        register_arcjet_hooks(guard=client, action="echo.invoked")

    _execute(_context(), lambda: "ok")
    assert len(client.guards) == 1

    handle.unregister()
    assert get_hooks(InterceptionPoint.PRE_TOOL_CALL) == []
    handle.unregister()  # idempotent
    register_arcjet_hooks(guard=client).unregister()


def test_sanitize_matches_installed_crewai() -> None:
    from crewai.utilities.string_utils import sanitize_tool_name as crewai_sanitize

    for name in ("Send Email", "sendEmail", "HTTPRequest", "a" * 80, "café tool"):
        assert sanitize_tool_name(name) == crewai_sanitize(name)


def test_guard_tool_deny_raises_arcjet_error_and_skips_body() -> None:
    client = StubGuardClient(decision=make_deny_decision())
    guarded = guard_tool(guard=client, tool=_EchoTool(), action="echo.invoked")
    with pytest.raises(ArcjetDeniedError):
        guarded.run(value="hello")
    assert _ECHO_CALLS == []


def test_guard_tool_unavailable_raises_arcjet_error() -> None:
    client = StubGuardClient(exception=RuntimeError("down"))
    guarded = guard_tool(guard=client, tool=_EchoTool(), action="echo.invoked")
    with pytest.raises(ArcjetUnavailableError):
        guarded.run(value="hello")
    assert _ECHO_CALLS == []


def test_guard_tool_allow_runs_the_tool_once() -> None:
    client = StubGuardClient(decision=make_allow_decision())
    guarded = guard_tool(guard=client, tool=_EchoTool(), action="echo.invoked")
    assert guarded.run(value="hello") == "hello"
    assert _ECHO_CALLS == ["hello"]
    # run() delegates to _run(), and both are guarded: one call, one decision.
    assert len(client.guards) == 1


def test_guard_tool_guards_the_run_implementation_too() -> None:
    """``to_structured_tool()`` hands CrewAI ``_run``, so it is a checkpoint."""
    client = StubGuardClient(decision=make_deny_decision())
    guarded = guard_tool(guard=client, tool=_EchoTool(), action="echo.invoked")
    with pytest.raises(ArcjetDeniedError):
        guarded._run(value="hello")
    assert _ECHO_CALLS == []


def test_hook_skips_the_wrapped_tool_but_not_the_original() -> None:
    """Branding the original would leave a crew given it running unguarded."""
    original = _EchoTool()
    wrapped = guard_tool(
        guard=StubGuardClient(decision=make_allow_decision()),
        tool=original,
        action="echo.invoked",
    )
    hook_client = StubGuardClient(decision=make_deny_decision())
    register_arcjet_hooks(guard=hook_client, action="echo.invoked")

    ran: list[str] = []
    assert _execute(
        _context(tool=_Structured(wrapped)), lambda: ran.append("w") or "ok"
    )
    assert ran == ["w"], "the hook must not evaluate an already-wrapped tool"
    assert hook_client.guards == []

    blocked = _execute(
        _context(tool=_Structured(original)), lambda: ran.append("o") or "ok"
    )
    assert blocked.startswith("Tool execution blocked by hook.")
    assert ran == ["w"], "the unwrapped original must still be guarded"
    assert len(hook_client.guards) == 1


def test_nested_guarded_tool_is_evaluated() -> None:
    """A guarded tool called from inside another one is a separate effect."""
    inner_client = StubGuardClient(decision=make_deny_decision())
    inner = guard_tool(guard=inner_client, tool=_EchoTool(), action="inner.invoked")

    class _Outer(BaseTool):
        name: str = "outer"
        description: str = "calls inner"
        args_schema: type[BaseModel] = _EchoArgs

        def _run(self, value: str) -> str:
            return inner.run(value=value)

    outer = guard_tool(
        guard=StubGuardClient(decision=make_allow_decision()),
        tool=_Outer(),
        action="outer.invoked",
    )

    with pytest.raises(ArcjetDeniedError):
        outer.run(value="payload")
    assert len(inner_client.guards) == 1
    assert _ECHO_CALLS == []


def test_guard_tool_guards_the_async_entrypoints() -> None:
    class _AsyncEcho(BaseTool):
        name: str = "async_echo"
        description: str = "echo a value"
        args_schema: type[BaseModel] = _EchoArgs

        def _run(self, value: str) -> str:
            _ECHO_CALLS.append(value)
            return value

        async def _arun(self, value: str) -> str:
            _ECHO_CALLS.append(value)
            return value

    deny = StubGuardClient(decision=make_deny_decision())
    denied = guard_tool(guard=deny, tool=_AsyncEcho(), action="echo.invoked")
    with pytest.raises(ArcjetDeniedError):
        asyncio.run(denied.arun(value="hello"))
    assert _ECHO_CALLS == []

    allow = StubGuardClient(decision=make_allow_decision())
    allowed = guard_tool(guard=allow, tool=_AsyncEcho(), action="echo.invoked")
    assert asyncio.run(allowed.arun(value="hello")) == "hello"
    assert _ECHO_CALLS == ["hello"]
    assert len(allow.guards) == 1


def test_guard_tool_guards_a_tools_own_func() -> None:
    """A ``Tool`` executes ``func``, so that is a checkpoint too."""
    calls: list[str] = []
    tool = Tool(
        name="echo",
        description="echo a value",
        args_schema=_EchoArgs,
        func=lambda value: calls.append(value) or value,
    )
    client = StubGuardClient(decision=make_deny_decision())
    guarded = guard_tool(guard=client, tool=tool, action="echo.invoked")
    with pytest.raises(ArcjetDeniedError):
        guarded.func(value="hello")
    with pytest.raises(ArcjetDeniedError):
        guarded.run(value="hello")
    assert calls == []


def test_guard_tool_leaves_the_original_unwrapped() -> None:
    original = _EchoTool()
    guarded = guard_tool(
        guard=StubGuardClient(decision=make_deny_decision()),
        tool=original,
        action="echo.invoked",
    )
    assert guarded is not original
    assert original.run(value="direct") == "direct"
    assert _ECHO_CALLS == ["direct"]
