"""End-to-end verification of ``arcjet.guard.openai_agents`` guard controls.

No API keys or network: a stub ``ModelProvider`` and in-memory guard client
drive deny / allow / unavailable / inbound screening / brand-skip paths the
same way a production app uses ``launch_arcjet`` and a real provider.
"""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, Optional

from agents import Agent, Runner, function_tool
from agents.items import ModelResponse
from agents.models.interface import Model, ModelProvider, ModelTracing
from agents.run_config import RunConfig
from agents.usage import Usage
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from arcjet.guard import server_input
from arcjet.guard._types import Decision, RuleResultError
from arcjet.guard.openai_agents import guard_tool, openai_agents_context
from arcjet.guard.openai_agents._tool import _GUARD_BRAND

ScenarioName = Literal[
    "allow",
    "deny",
    "unavailable",
    "inbound-deny",
    "inbound-failed-open",
    "brand-skip",
    "correlation",
]

ALL_SCENARIOS: tuple[ScenarioName, ...] = (
    "allow",
    "deny",
    "unavailable",
    "inbound-deny",
    "inbound-failed-open",
    "brand-skip",
    "correlation",
)

_ECHO_CALLS: list[str] = []


@function_tool
def echo(value: str) -> str:
    """Echo the value back."""
    _ECHO_CALLS.append(value)
    return value


class ScenarioGuard:
    """In-memory guard client — same contract as ``launch_arcjet`` clients."""

    def __init__(
        self,
        decision: Optional[Decision] = None,
        exception: Optional[Exception] = None,
    ) -> None:
        self.decision = decision
        self.exception = exception
        self.guards: list[dict[str, Any]] = []
        self.captures: list[dict[str, Any]] = []

    async def guard(
        self,
        rules: Sequence[Any] = (),
        *,
        label: str,
        metadata: Optional[dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
        actor: Optional[str] = None,
        inputs: Optional[dict[str, Any]] = None,
    ) -> Decision:
        if self.exception is not None:
            raise self.exception
        self.guards.append(
            {
                "rules": rules,
                "label": label,
                "metadata": metadata,
                "correlation_id": correlation_id,
                "actor": actor,
                "inputs": inputs,
            }
        )
        if self.decision is None:
            raise RuntimeError("ScenarioGuard not configured with a decision")
        return self.decision

    def guard_sync(
        self,
        rules: Sequence[Any] = (),
        *,
        label: str,
        metadata: Optional[dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
        actor: Optional[str] = None,
        inputs: Optional[dict[str, Any]] = None,
    ) -> Decision:
        if self.exception is not None:
            raise self.exception
        self.guards.append(
            {
                "rules": rules,
                "label": label,
                "metadata": metadata,
                "correlation_id": correlation_id,
                "actor": actor,
                "inputs": inputs,
            }
        )
        if self.decision is None:
            raise RuntimeError("ScenarioGuard not configured with a decision")
        return self.decision

    def capture(
        self,
        *,
        action: str,
        correlation_id: Optional[str] = None,
        decision_id: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        self.captures.append(
            {
                "action": action,
                "correlation_id": correlation_id,
                "decision_id": decision_id,
                "metadata": metadata,
                **kwargs,
            }
        )


def _allow() -> Decision:
    return Decision(
        conclusion="ALLOW", id="verify_allow", reason="UNKNOWN", results=()
    )


def _deny() -> Decision:
    return Decision(
        conclusion="DENY", id="verify_deny", reason="RATE_LIMIT", results=()
    )


def _failed_open() -> Decision:
    return Decision(
        conclusion="ALLOW",
        id="verify_failed_open",
        reason="UNKNOWN",
        results=(RuleResultError(code="TIMEOUT", message="deadline"),),
    )


class _StubModel(Model):
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
        raise NotImplementedError("streaming not used in this harness")


class _StubModelProvider(ModelProvider):
    def __init__(self, model: Model) -> None:
        self._model = model

    def get_model(self, model_name: str | None) -> Model:
        return self._model


def _tool_call(tool_name: str, arguments: str) -> ModelResponse:
    return ModelResponse(
        output=[
            ResponseFunctionToolCall(
                call_id="call_verify",
                name=tool_name,
                arguments=arguments,
                type="function_call",
            )
        ],
        usage=Usage(),
        response_id="resp_tool",
    )


def _text(text: str) -> ModelResponse:
    return ModelResponse(
        output=[
            ResponseOutputMessage(
                id="msg_verify",
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


def _denial_in_result(result: Any) -> Optional[Mapping[str, Any]]:
    for item in result.new_items:
        raw = getattr(item, "raw_item", None)
        if isinstance(raw, dict) and raw.get("type") == "function_call_output":
            output = raw.get("output")
            if isinstance(output, str) and "arcjetDenied" in output:
                return json.loads(output)
    return None


async def _run_tool_scenario(
    guard: ScenarioGuard,
    *,
    session_id: str,
    tool_arguments: str,
) -> Any:
    guarded = guard_tool(guard=guard, tool=echo, action="echo.invoked")
    agent = Agent(name="verify", tools=[guarded], model="stub")
    model = _StubModel(
        [
            _tool_call("echo", tool_arguments),
            _text("done"),
        ]
    )
    run_config = RunConfig(model_provider=_StubModelProvider(model))
    return await Runner.run(
        agent,
        "please echo",
        context={"session_id": session_id},
        run_config=run_config,
    )


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    name: ScenarioName
    ok: bool
    detail: str


def _capture_outcome(guard: ScenarioGuard) -> str:
    assert guard.captures, "expected a guard capture after the tool path ran"
    metadata = guard.captures[0].get("metadata") or {}
    outcome = metadata.get("outcome")
    assert outcome is not None, "expected capture metadata.outcome"
    return str(outcome)


async def run_allow() -> ScenarioResult:
    _ECHO_CALLS.clear()
    guard = ScenarioGuard(decision=_allow())
    await _run_tool_scenario(
        guard, session_id="sess-allow", tool_arguments='{"value":"hello"}'
    )
    outcome = _capture_outcome(guard)
    ok = _ECHO_CALLS == ["hello"] and outcome == "success"
    return ScenarioResult("allow", ok, f"echo_calls={_ECHO_CALLS!r}, outcome={outcome}")


async def run_deny() -> ScenarioResult:
    _ECHO_CALLS.clear()
    guard = ScenarioGuard(decision=_deny())
    result = await _run_tool_scenario(
        guard, session_id="sess-deny", tool_arguments='{"value":"blocked"}'
    )
    payload = _denial_in_result(result)
    outcome = _capture_outcome(guard)
    ok = (
        _ECHO_CALLS == []
        and payload is not None
        and payload.get("arcjetDenied") is True
        and payload.get("reason") == "RATE_LIMIT"
        and outcome == "denied"
    )
    return ScenarioResult("deny", ok, f"echo_calls={_ECHO_CALLS!r}, denial={payload}")


async def run_unavailable() -> ScenarioResult:
    _ECHO_CALLS.clear()
    guard = ScenarioGuard(exception=RuntimeError("guard down"))
    result = await _run_tool_scenario(
        guard, session_id="sess-unavail", tool_arguments='{"value":"x"}'
    )
    payload = _denial_in_result(result)
    outcome = _capture_outcome(guard)
    ok = (
        _ECHO_CALLS == []
        and payload is not None
        and payload.get("reason") == "ERROR"
        and payload.get("retryable") is True
        and outcome == "unavailable"
    )
    return ScenarioResult("unavailable", ok, f"denial={payload}")


async def _screen_inbound(
    guard: ScenarioGuard,
    user_text: str,
    session_id: str,
) -> tuple[bool, str]:
    app_context = {"session_id": session_id}
    ctx = openai_agents_context(app_context)
    decision = await guard.guard(
        label="chat.inbound",
        inputs={"content": server_input.string(user_text)},
        correlation_id=ctx.correlation_id,
        metadata=ctx.metadata,
    )
    if decision.conclusion == "DENY" or decision.has_failed_open():
        return False, f"refused inbound ({decision.conclusion}, failed_open={decision.has_failed_open()})"
    return True, "inbound allowed"


async def run_inbound_deny() -> ScenarioResult:
    guard = ScenarioGuard(decision=_deny())
    allowed, detail = await _screen_inbound(guard, "hello", "sess-in-deny")
    ok = not allowed and guard.guards[0]["correlation_id"] == "sess-in-deny"
    return ScenarioResult("inbound-deny", ok, detail)


async def run_inbound_failed_open() -> ScenarioResult:
    guard = ScenarioGuard(decision=_failed_open())
    allowed, detail = await _screen_inbound(guard, "hello", "sess-in-fo")
    ok = not allowed and guard.guards[0]["label"] == "chat.inbound"
    return ScenarioResult("inbound-failed-open", ok, detail)


async def run_brand_skip() -> ScenarioResult:
    guard = ScenarioGuard(decision=_allow())
    first = guard_tool(guard=guard, tool=echo, action="echo.invoked")
    second = guard_tool(guard=guard, tool=first, action="echo.invoked")
    ok = (
        second is first
        and getattr(first, _GUARD_BRAND, False)
        and len(first.tool_input_guardrails or []) == 1
    )
    return ScenarioResult("brand-skip", ok, f"same_object={second is first}, guardrails={len(first.tool_input_guardrails or [])}")


async def run_correlation() -> ScenarioResult:
    guard = ScenarioGuard(decision=_deny())
    await _run_tool_scenario(
        guard,
        session_id="sess-corr-42",
        tool_arguments='{"value":"x"}',
    )
    ok = guard.guards[0]["correlation_id"] == "sess-corr-42"
    meta = guard.guards[0]["metadata"] or {}
    ok = ok and meta.get("openai-agents.session") == "sess-corr-42"
    return ScenarioResult("correlation", ok, f"correlation_id={guard.guards[0]['correlation_id']!r}")


RUNNERS: dict[ScenarioName, Any] = {
    "allow": run_allow,
    "deny": run_deny,
    "unavailable": run_unavailable,
    "inbound-deny": run_inbound_deny,
    "inbound-failed-open": run_inbound_failed_open,
    "brand-skip": run_brand_skip,
    "correlation": run_correlation,
}


async def run_scenarios(names: Sequence[ScenarioName]) -> list[ScenarioResult]:
    results: list[ScenarioResult] = []
    for name in names:
        results.append(await RUNNERS[name]())
    return results


def main(argv: list[str]) -> int:
    requested = argv or list(ALL_SCENARIOS)
    names: list[ScenarioName] = []
    for arg in requested:
        if arg == "all":
            names.extend(ALL_SCENARIOS)
        elif arg in RUNNERS:
            names.append(arg)  # type: ignore[arg-type]
        else:
            print(f"unknown scenario: {arg}", file=sys.stderr)
            return 2

    results = asyncio.run(run_scenarios(names))
    failed = 0
    for result in results:
        status = "PASS" if result.ok else "FAIL"
        print(f"[{status}] {result.name}: {result.detail}")
        if not result.ok:
            failed += 1
    if failed:
        print(f"{failed} scenario(s) failed", file=sys.stderr)
        return 1
    print(f"all {len(results)} scenario(s) passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
