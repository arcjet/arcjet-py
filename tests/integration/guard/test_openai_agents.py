"""OpenAI Agents FunctionTool wrap. Skips when the extra is absent."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from guard_doubles import StubGuardClient, make_allow_decision, make_deny_decision

pytest.importorskip("agents", reason="arcjet[openai-agents] extra is not installed")

from agents import Agent, function_tool  # noqa: E402
from agents.run_context import RunContextWrapper  # noqa: E402
from agents.tool_context import ToolContext  # noqa: E402
from agents.tool_guardrails import (  # noqa: E402
    ToolGuardrailFunctionOutput,
    ToolInputGuardrailData,
)

from arcjet.guard.openai_agents import guard_tool, openai_agents_context  # noqa: E402
from arcjet.guard.openai_agents._tool import _GUARD_BRAND, _GUARDRAIL_NAME  # noqa: E402

_ECHO_CALLS: list[str] = []


@function_tool
def echo(value: str) -> str:
    """Echo a value."""
    _ECHO_CALLS.append(value)
    return value


@pytest.fixture(autouse=True)
def _clean_calls() -> Any:
    _ECHO_CALLS.clear()
    yield
    _ECHO_CALLS.clear()


def _tool_data(
    tool: Any,
    *,
    arguments: str = '{"value": "hello"}',
    context: Any = None,
) -> ToolInputGuardrailData:
    tool_context = ToolContext(
        context=context if context is not None else {},
        tool_name=tool.name,
        tool_call_id="call_1",
        tool_arguments=arguments,
    )
    agent = Agent(name="test", tools=[tool])
    return ToolInputGuardrailData(context=tool_context, agent=agent)


def _run_arcjet_guardrail(tool: Any, data: ToolInputGuardrailData) -> Any:
    guardrails = tool.tool_input_guardrails or []
    assert guardrails, "guard_tool must prepend a ToolInputGuardrail"
    return asyncio.run(guardrails[0].run(data))


def test_guard_tool_prepends_input_guardrail_and_does_not_wrap_approval() -> None:
    original_approval = echo.needs_approval
    client = StubGuardClient(decision=make_allow_decision())
    guarded = guard_tool(guard=client, tool=echo, action="echo.invoked")
    assert guarded is not echo
    assert getattr(guarded, _GUARD_BRAND, False) is True
    assert getattr(echo, _GUARD_BRAND, False) is False
    assert guarded.needs_approval == original_approval
    names = [g.get_name() for g in (guarded.tool_input_guardrails or [])]
    assert names[0] == _GUARDRAIL_NAME


def test_deny_skips_invoke_via_reject_content() -> None:
    client = StubGuardClient(decision=make_deny_decision())
    guarded = guard_tool(guard=client, tool=echo, action="echo.invoked")
    output = _run_arcjet_guardrail(guarded, _tool_data(guarded))
    assert output.behavior["type"] == "reject_content"
    payload = json.loads(output.behavior["message"])
    assert payload["arcjetDenied"] is True
    assert payload["reason"] == "RATE_LIMIT"
    assert _ECHO_CALLS == []
    # The primary gate is reject_content, not raise_exception (which halts).
    assert output.behavior["type"] != "raise_exception"


def test_allow_lets_invoke_run() -> None:
    client = StubGuardClient(decision=make_allow_decision())
    guarded = guard_tool(guard=client, tool=echo, action="echo.invoked")
    output = _run_arcjet_guardrail(guarded, _tool_data(guarded))
    assert output.behavior["type"] == "allow"
    result = asyncio.run(
        guarded.on_invoke_tool(
            ToolContext(
                context={},
                tool_name=guarded.name,
                tool_call_id="call_1",
                tool_arguments='{"value": "hello"}',
            ),
            '{"value": "hello"}',
        )
    )
    assert result == "hello"
    assert _ECHO_CALLS == ["hello"]


def test_unavailable_reject_content() -> None:
    client = StubGuardClient(exception=RuntimeError("down"))
    guarded = guard_tool(guard=client, tool=echo, action="echo.invoked")
    output = _run_arcjet_guardrail(guarded, _tool_data(guarded))
    assert output.behavior["type"] == "reject_content"
    payload = json.loads(output.behavior["message"])
    assert payload["reason"] == "ERROR"
    assert payload["retryable"] is True
    assert _ECHO_CALLS == []


def test_brand_skip_does_not_double_wrap() -> None:
    client = StubGuardClient(decision=make_allow_decision())
    first = guard_tool(guard=client, tool=echo, action="echo.invoked")
    second = guard_tool(guard=client, tool=first, action="echo.invoked")
    assert second is first
    assert len(first.tool_input_guardrails or []) == 1


def test_correlation_from_run_context() -> None:
    client = StubGuardClient(decision=make_deny_decision())
    guarded = guard_tool(guard=client, tool=echo, action="echo.invoked")
    _run_arcjet_guardrail(
        guarded,
        _tool_data(guarded, context={"session_id": "sess-22"}),
    )
    assert client.guards[0]["correlation_id"] == "sess-22"


def test_openai_agents_context_does_not_read_run_context_wrapper_trace() -> None:
    wrapper = RunContextWrapper(context={"session_id": "sess"})
    derived = openai_agents_context(wrapper)
    assert derived.correlation_id == "sess"


def test_existing_guardrails_are_kept_after_the_arcjet_one() -> None:
    def other(_data: Any) -> ToolGuardrailFunctionOutput:
        return ToolGuardrailFunctionOutput.allow()

    from agents.tool_guardrails import ToolInputGuardrail

    echo.tool_input_guardrails = [
        ToolInputGuardrail(guardrail_function=other, name="other")
    ]
    try:
        client = StubGuardClient(decision=make_allow_decision())
        guarded = guard_tool(guard=client, tool=echo, action="echo.invoked")
        names = [g.get_name() for g in (guarded.tool_input_guardrails or [])]
        assert names == [_GUARDRAIL_NAME, "other"]
        # The original is left as the caller had it.
        original_names = [g.get_name() for g in (echo.tool_input_guardrails or [])]
        assert original_names == ["other"]
    finally:
        echo.tool_input_guardrails = None


def test_guard_tool_rejects_a_non_function_tool() -> None:
    with pytest.raises(TypeError, match="FunctionTool"):
        guard_tool(
            guard=StubGuardClient(decision=make_allow_decision()),
            tool=object(),
            action="x.done",
        )
