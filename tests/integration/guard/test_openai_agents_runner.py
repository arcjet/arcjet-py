"""Full ``Runner.run`` integration — mock model, real tool execution path."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import pytest
from guard_doubles import StubGuardClient, make_allow_decision, make_deny_decision

pytest.importorskip("agents", reason="arcjet[openai-agents] extra is not installed")

from agents import Agent, Runner, function_tool  # noqa: E402
from agents.items import ModelResponse  # noqa: E402
from agents.models.interface import (  # noqa: E402
    Model,
    ModelProvider,
    ModelTracing,
)
from agents.run_config import RunConfig  # noqa: E402
from agents.usage import Usage  # noqa: E402
from openai.types.responses import (  # noqa: E402
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from arcjet.guard.openai_agents import guard_tool, openai_agents_context  # noqa: E402

_ECHO_CALLS: list[str] = []


@function_tool
def echo(value: str) -> str:
    """Echo the value."""
    _ECHO_CALLS.append(value)
    return value


class _StubModel(Model):
    """Returns canned ``ModelResponse``s in order."""

    def __init__(self, responses: list[ModelResponse]) -> None:
        self._responses = responses
        self._index = 0

    async def get_response(
        self,
        system_instructions: str | None,
        input: str | list[Any],
        model_settings: Any,
        tools: list[Any],
        output_schema: Any,
        handoffs: list[Any],
        tracing: ModelTracing,
        *,
        previous_response_id: str | None,
        conversation_id: str | None,
        prompt: Any,
    ) -> ModelResponse:
        if self._index >= len(self._responses):
            return ModelResponse(output=[], usage=Usage(), response_id=None)
        response = self._responses[self._index]
        self._index += 1
        return response

    def stream_response(
        self,
        system_instructions: str | None,
        input: str | list[Any],
        model_settings: Any,
        tools: list[Any],
        output_schema: Any,
        handoffs: list[Any],
        tracing: ModelTracing,
        *,
        previous_response_id: str | None,
        conversation_id: str | None,
        prompt: Any,
    ) -> AsyncIterator[Any]:
        raise NotImplementedError("streaming not used in this test")


class _StubModelProvider(ModelProvider):
    def __init__(self, model: Model) -> None:
        self._model = model

    def get_model(self, model_name: str | None) -> Model:
        return self._model


def _tool_call_response(tool_name: str, arguments: str) -> ModelResponse:
    return ModelResponse(
        output=[
            ResponseFunctionToolCall(
                call_id="call_runner_1",
                name=tool_name,
                arguments=arguments,
                type="function_call",
            )
        ],
        usage=Usage(),
        response_id="resp_tool",
    )


def _text_response(text: str) -> ModelResponse:
    return ModelResponse(
        output=[
            ResponseOutputMessage(
                id="msg_1",
                role="assistant",
                status="completed",
                type="message",
                content=[
                    ResponseOutputText(
                        type="output_text",
                        text=text,
                        annotations=[],
                    )
                ],
            )
        ],
        usage=Usage(),
        response_id="resp_text",
    )


@pytest.fixture(autouse=True)
def _clean_calls() -> Any:
    _ECHO_CALLS.clear()
    yield
    _ECHO_CALLS.clear()


def test_runner_deny_skips_tool_body_and_surfaces_json() -> None:
    client = StubGuardClient(decision=make_deny_decision())
    guarded = guard_tool(guard=client, tool=echo, action="echo.invoked")
    agent = Agent(name="test", tools=[guarded], model="stub")
    model = _StubModel(
        [
            _tool_call_response("echo", '{"value":"blocked"}'),
            _text_response("ack"),
        ]
    )
    run_config = RunConfig(model_provider=_StubModelProvider(model))
    app_context = {"session_id": "runner-session-1"}

    result = asyncio.run(
        Runner.run(
            agent,
            "please echo",
            context=app_context,
            run_config=run_config,
        )
    )

    assert _ECHO_CALLS == []
    assert client.guards[0]["correlation_id"] == "runner-session-1"
    assert client.captures[0]["metadata"]["outcome"] == "denied"
    # Tool output should be JSON denial in the run items somewhere
    denial_found = False
    for item in result.new_items:
        raw = getattr(item, "raw_item", None)
        if isinstance(raw, dict) and raw.get("type") == "function_call_output":
            output = raw.get("output")
            if isinstance(output, str) and "arcjetDenied" in output:
                payload = json.loads(output)
                assert payload["arcjetDenied"] is True
                assert payload["reason"] == "RATE_LIMIT"
                denial_found = True
    assert denial_found


def test_runner_allow_executes_tool() -> None:
    client = StubGuardClient(decision=make_allow_decision())
    guarded = guard_tool(guard=client, tool=echo, action="echo.invoked")
    agent = Agent(name="test", tools=[guarded], model="stub")
    model = _StubModel(
        [
            _tool_call_response("echo", '{"value":"hello"}'),
            _text_response("done"),
        ]
    )
    run_config = RunConfig(model_provider=_StubModelProvider(model))

    asyncio.run(
        Runner.run(
            agent,
            "please echo",
            context={"session_id": "sess-allow"},
            run_config=run_config,
        )
    )

    assert _ECHO_CALLS == ["hello"]
    assert client.captures[0]["metadata"]["outcome"] == "success"


def test_openai_agents_context_for_inbound_screening() -> None:
    ctx = openai_agents_context({"session_id": "sess-inbound"})
    assert ctx.correlation_id == "sess-inbound"
    assert ctx.metadata is not None
    assert ctx.metadata["openai-agents.session"] == "sess-inbound"
