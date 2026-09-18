"""Google ADK callback / plugin integration. Skips when the extra is absent."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from types import SimpleNamespace
from typing import Any

import pytest
from guard_doubles import StubGuardClient, make_allow_decision, make_deny_decision

pytest.importorskip("google.adk", reason="arcjet[google-adk] extra is not installed")

from google.adk.agents import LlmAgent  # noqa: E402
from google.adk.models.base_llm import BaseLlm  # noqa: E402
from google.adk.models.llm_request import LlmRequest  # noqa: E402
from google.adk.models.llm_response import LlmResponse  # noqa: E402
from google.adk.plugins.base_plugin import BasePlugin  # noqa: E402
from google.adk.runners import InMemoryRunner  # noqa: E402
from google.adk.sessions.state import State  # noqa: E402
from google.genai import types  # noqa: E402

from arcjet.guard.google_adk import (  # noqa: E402
    google_adk_context,
    guard_plugin,
    guard_tool,
)
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


def test_real_adk_state_is_not_a_mapping() -> None:
    from collections.abc import Mapping

    state = State({"sessionId": "from-adk-state"}, {})
    assert not isinstance(state, Mapping)
    assert state.get("sessionId") == "from-adk-state"
    ctx = google_adk_context(state)
    assert ctx.correlation_id == "from-adk-state"


class _ScriptedRefundLlm(BaseLlm):
    """Always calls ``issue_refund`` once, then answers in text."""

    model: str = "scripted-refund"

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        del stream
        if llm_request.contents:
            last = llm_request.contents[-1]
            for part in last.parts or []:
                if getattr(part, "function_response", None) is not None:
                    yield LlmResponse(
                        content=types.Content(
                            role="model",
                            parts=[types.Part(text="Refund handled.")],
                        )
                    )
                    return
        yield LlmResponse(
            content=types.Content(
                role="model",
                parts=[
                    types.Part(
                        function_call=types.FunctionCall(
                            name="issue_refund",
                            args={
                                "order_id": "ord-100",
                                "amount_cents": 2000,
                                "reason": "item never arrived",
                            },
                        )
                    )
                ],
            )
        )


def test_plugin_allow_and_deny_through_real_runner() -> None:
    """End-to-end: InMemoryRunner + BasePlugin + ADK State, no Gemini."""
    refunds: list[str] = []

    def issue_refund(order_id: str, amount_cents: int, reason: str) -> dict[str, str]:
        refunds.append(order_id)
        return {"status": f"refunded {order_id} ({amount_cents}) {reason}"}

    async def _once(client: StubGuardClient) -> str:
        refunds.clear()
        plugin = guard_plugin(guard=client, action="refund.issued", actor="user-42")
        agent = LlmAgent(
            name="refund_agent",
            model=_ScriptedRefundLlm(),
            instruction="Always call issue_refund.",
            tools=[issue_refund],
        )
        runner = InMemoryRunner(agent=agent, app_name="refund-desk", plugins=[plugin])
        await runner.session_service.create_session(
            app_name="refund-desk",
            user_id="user-42",
            session_id="sess-adk-state",
            state={"sessionId": "sess-adk-state"},
        )
        parts: list[str] = []
        async for event in runner.run_async(
            user_id="user-42",
            session_id="sess-adk-state",
            new_message=types.Content(
                role="user",
                parts=[types.Part(text="Refund order ord-100")],
            ),
        ):
            content = getattr(event, "content", None)
            event_parts = getattr(content, "parts", None) if content else None
            if not event_parts:
                continue
            for part in event_parts:
                text = getattr(part, "text", None)
                if isinstance(text, str) and text:
                    parts.append(text)
        return "".join(parts)

    allow_client = StubGuardClient(decision=make_allow_decision())
    reply = _run(_once(allow_client))
    assert refunds == ["ord-100"]
    assert allow_client.guards[0]["correlation_id"] == "sess-adk-state"
    assert allow_client.guards[0]["actor"] == "user-42"
    assert allow_client.guards[0]["label"] == "refund.issued"
    assert "Refund handled" in reply or refunds == ["ord-100"]

    deny_client = StubGuardClient(decision=make_deny_decision())
    _run(_once(deny_client))
    assert refunds == []
    result_meta = deny_client.captures[0]["metadata"]
    assert result_meta["outcome"] == "denied"
