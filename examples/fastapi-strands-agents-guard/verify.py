"""End-to-end verification of the FastAPI + Strands Agents Guard example.

Exercises the same adapter contracts the app uses: `guard_tool` deny envelope
(no throw), `guard_hooks` `BeforeToolCallEvent.cancel_tool` / brand-skip /
`AfterToolCallEvent` capture, caller-owned session id, and the FastAPI
`/chat` session check. No Anthropic key is required. Pass `ARCJET_KEY` to
also hit live Guard.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal, Optional

_EXAMPLE_DIR = Path(__file__).resolve().parent
if str(_EXAMPLE_DIR) not in sys.path:
    sys.path.insert(0, str(_EXAMPLE_DIR))

from fastapi.testclient import TestClient
from strands import tool
from strands.hooks import AfterToolCallEvent, BeforeToolCallEvent

from arcjet.guard import LocalDetectSensitiveInfo, server_input
from arcjet.guard._types import Decision, Reason, RuleResultError
from arcjet.guard.strands_agents import (
    guard_hooks,
    guard_tool,
    strands_agent_context,
)

ScenarioName = Literal[
    "allow",
    "deny",
    "unavailable",
    "brand-skip",
    "hook-allow",
    "hook-deny",
    "post-capture",
    "correlation",
    "session-reject",
    "no-batch-cancel",
    "no-guard-inbound",
]

ALL_SCENARIOS: tuple[ScenarioName, ...] = (
    "allow",
    "deny",
    "unavailable",
    "brand-skip",
    "hook-allow",
    "hook-deny",
    "post-capture",
    "correlation",
    "session-reject",
    "no-batch-cancel",
    "no-guard-inbound",
)

SESSION_ID = "550e8400-e29b-41d4-a716-446655440000"
_SEND_CALLS: list[str] = []
_LOOKUP_CALLS: list[str] = []


@tool
def send_email(to: str, body: str) -> str:
    """Send an email to a recipient."""
    _SEND_CALLS.append(to)
    return f"Email sent to {to}"


@tool
def lookup_account(account_id: str) -> str:
    """Look up an account by its internal id."""
    _LOOKUP_CALLS.append(account_id)
    return f"Account found for {account_id}"


class ScenarioGuard:
    """In-memory guard client — same contract as `launch_arcjet` clients."""

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
        metadata: Any = None,
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
            raise AssertionError("ScenarioGuard not configured with a decision")
        return self.decision

    def capture(self, **kwargs: Any) -> None:
        self.captures.append(kwargs)


class _Registry:
    def __init__(self) -> None:
        self.callbacks: list[tuple[Any, Any]] = []

    def add_callback(self, event_type: Any, callback: Any, **_kwargs: Any) -> None:
        self.callbacks.append((event_type, callback))


class _HookEvent:
    """Duck-typed hook event. The adapter reads these fields only."""

    def __init__(
        self,
        *,
        selected_tool: Any,
        name: str,
        arguments: dict[str, Any],
        invocation_state: Optional[dict[str, Any]] = None,
    ) -> None:
        self.selected_tool = selected_tool
        self.tool_use = {"name": name, "input": arguments}
        self.invocation_state = invocation_state or {"sessionId": SESSION_ID}
        self.cancel_tool: bool | str = False
        self.retry = False


def _allow() -> Decision:
    return Decision(conclusion="ALLOW", id="gdec_allow", reason="UNKNOWN", results=())


def _deny(reason: Reason = "RATE_LIMIT") -> Decision:
    return Decision(conclusion="DENY", id="gdec_deny", reason=reason, results=())


def _failed_open() -> Decision:
    return Decision(
        conclusion="ALLOW",
        id="gdec_error",
        reason="ERROR",
        results=(
            RuleResultError(conclusion="ALLOW", reason="ERROR", message="down"),
        ),
    )


def _wrap(guard: ScenarioGuard) -> Any:
    return guard_tool(
        guard=guard,
        tool=send_email,
        action="email.sent",
        actor=SESSION_ID,
        inputs=lambda args: {
            "recipient": server_input.string(str(args.get("to", ""))),
            "body": server_input.string(str(args.get("body", ""))),
        },
        session_id=SESSION_ID,
        on_guard_error="deny",
    )


def _hooks(guard: ScenarioGuard, **kwargs: Any) -> Any:
    return guard_hooks(
        guard=guard,
        actor=SESSION_ID,
        session_id=SESSION_ID,
        on_guard_error="deny",
        **kwargs,
    )


def _registered(hooks: Any) -> _Registry:
    registry = _Registry()
    hooks.register_hooks(registry)
    return registry


def _callback(registry: _Registry, event_type: Any) -> Any:
    for registered, callback in registry.callbacks:
        if registered is event_type:
            return callback
    raise AssertionError(f"no callback registered for {event_type.__name__}")


async def scenario_allow() -> None:
    _SEND_CALLS.clear()
    guard = ScenarioGuard(decision=_allow())
    guarded = _wrap(guard)
    result = await guarded._tool_func(to="onboarding-list", body="welcome")
    assert _SEND_CALLS == ["onboarding-list"], _SEND_CALLS
    assert result == "Email sent to onboarding-list"
    assert not isinstance(result, dict) or result.get("arcjetDenied") is not True


async def scenario_deny() -> None:
    _SEND_CALLS.clear()
    guard = ScenarioGuard(decision=_deny())
    guarded = _wrap(guard)
    result = await guarded._tool_func(to="onboarding-list", body="welcome")
    assert _SEND_CALLS == []
    assert isinstance(result, dict)
    assert result["arcjetDenied"] is True
    assert result["reason"] == "RATE_LIMIT"


async def scenario_unavailable() -> None:
    _SEND_CALLS.clear()
    guard = ScenarioGuard(exception=RuntimeError("down"))
    guarded = _wrap(guard)
    result = await guarded._tool_func(to="onboarding-list", body="welcome")
    assert _SEND_CALLS == []
    assert isinstance(result, dict)
    assert result["reason"] == "ERROR"
    assert result["retryable"] is True


async def scenario_brand_skip() -> None:
    guard = ScenarioGuard(decision=_deny())
    guarded = _wrap(guard)
    hooks = _hooks(guard)
    registry = _registered(hooks)
    before = _callback(registry, BeforeToolCallEvent)
    event = _HookEvent(
        selected_tool=guarded,
        name="send_email",
        arguments={"to": "onboarding-list", "body": "welcome"},
    )
    await before(event)
    assert event.cancel_tool is False
    assert guard.guards == []
    second = guard_tool(guard=guard, tool=guarded, action="email.sent")
    assert second is guarded


async def scenario_hook_allow() -> None:
    _LOOKUP_CALLS.clear()
    guard = ScenarioGuard(decision=_allow())
    hooks = _hooks(guard)
    registry = _registered(hooks)
    before = _callback(registry, BeforeToolCallEvent)
    event = _HookEvent(
        selected_tool=lookup_account,
        name="lookup_account",
        arguments={"account_id": "acct-onboarding"},
    )
    await before(event)
    assert event.cancel_tool is False
    assert len(guard.guards) == 1
    assert guard.guards[0]["label"] == "lookup_account.invoked"


async def scenario_hook_deny() -> None:
    guard = ScenarioGuard(decision=_deny())
    hooks = _hooks(guard)
    registry = _registered(hooks)
    before = _callback(registry, BeforeToolCallEvent)
    event = _HookEvent(
        selected_tool=lookup_account,
        name="lookup_account",
        arguments={"account_id": "acct-onboarding"},
    )
    await before(event)
    assert isinstance(event.cancel_tool, str)
    payload = json.loads(event.cancel_tool)
    assert payload["arcjetDenied"] is True
    assert payload["reason"] == "RATE_LIMIT"
    assert event.cancel_tool is not True


async def scenario_post_capture() -> None:
    guard = ScenarioGuard(decision=_allow())
    guarded = _wrap(guard)
    hooks = _hooks(guard)
    registry = _registered(hooks)
    after = _callback(registry, AfterToolCallEvent)
    branded = _HookEvent(
        selected_tool=guarded,
        name="send_email",
        arguments={"to": "onboarding-list", "body": "welcome"},
    )
    after(branded)
    unwrapped = _HookEvent(
        selected_tool=lookup_account,
        name="lookup_account",
        arguments={"account_id": "acct-onboarding"},
    )
    after(unwrapped)
    phases = [item["metadata"].get("strands.phase") for item in guard.captures]
    assert phases == ["after", "after"]
    assert branded.retry is False
    assert unwrapped.retry is False


async def scenario_correlation() -> None:
    preferred = strands_agent_context(
        {
            "correlationId": "corr-1",
            "sessionId": "sess-1",
            "requestId": "req-1",
        }
    )
    assert preferred.correlation_id == "corr-1"
    assert preferred.metadata is not None
    assert preferred.metadata["strands.session"] == "sess-1"
    assert preferred.metadata["strands.request"] == "req-1"

    session_only = strands_agent_context({"sessionId": SESSION_ID})
    assert session_only.correlation_id == SESSION_ID

    request_only = strands_agent_context({"requestId": "req-only"})
    assert request_only.correlation_id == "req-only"

    skipped = strands_agent_context({"trace_id": "tr_should_never_win"})
    assert skipped.correlation_id is None
    assert skipped.metadata is None or "trace_id" not in skipped.metadata


async def scenario_session_reject() -> None:
    previous = {
        name: os.environ.get(name)
        for name in ("ARCJET_KEY", "ANTHROPIC_API_KEY")
    }
    try:
        os.environ.setdefault("ARCJET_KEY", "ajkey_verify")
        os.environ.setdefault("ANTHROPIC_API_KEY", "sk-verify")
        import main as app_module

        client = TestClient(app_module.app)
        rejected = (
            "",
            "   ",
            "sess-\u2603",
            "sess-\nnewline",
            "x" * 257,
        )
        for session_id in rejected:
            response = client.post(
                "/chat",
                json={"message": "hi", "session_id": session_id},
            )
            assert response.status_code == 400, session_id
            assert "caller-owned printable ASCII id" in response.json()["error"]
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


async def scenario_no_batch_cancel() -> None:
    hooks = _hooks(ScenarioGuard(decision=_allow()))
    registry = _registered(hooks)
    event_types = {event_type for event_type, _callback in registry.callbacks}
    assert BeforeToolCallEvent in event_types
    assert AfterToolCallEvent in event_types
    assert all(event_type.__name__ != "BeforeToolsEvent" for event_type in event_types)
    assert not hasattr(hooks, "interrupt")
    before = _callback(registry, BeforeToolCallEvent)
    assert not getattr(before, "interrupt", None)


async def scenario_no_guard_inbound() -> None:
    from arcjet.guard import strands_agents as adapter

    assert adapter.__all__ == ["guard_tool", "guard_hooks", "strands_agent_context"]
    assert not hasattr(adapter, "guard_inbound")
    assert not hasattr(adapter, "guard_approval")
    assert _failed_open().has_failed_open() is True


async def scenario_live_local_pii() -> None:
    """Real LocalDetectSensitiveInfo through the adapter when a key is set."""
    from arcjet.guard import launch_arcjet

    key = os.environ["ARCJET_KEY"]
    client = launch_arcjet(key=key)
    detect = LocalDetectSensitiveInfo(deny=["EMAIL"])
    _SEND_CALLS.clear()
    guarded = guard_tool(
        guard=client,
        tool=send_email,
        action="email.sent",
        actor=SESSION_ID,
        session_id=SESSION_ID,
        # Same as the app: EMAIL in the body denies; EMAIL on `to` does not.
        rules=lambda args: (detect(str(args.get("body", ""))),),
        on_guard_error="deny",
    )
    result = await guarded._tool_func(
        to="onboarding-list",
        body="welcome alice@example.com",
    )
    await client.flush()
    assert _SEND_CALLS == [], _SEND_CALLS
    assert isinstance(result, dict)
    assert result["arcjetDenied"] is True
    print("  live-local-pii: handler skipped; envelope", result["reason"])


SCENARIOS: dict[ScenarioName, Any] = {
    "allow": scenario_allow,
    "deny": scenario_deny,
    "unavailable": scenario_unavailable,
    "brand-skip": scenario_brand_skip,
    "hook-allow": scenario_hook_allow,
    "hook-deny": scenario_hook_deny,
    "post-capture": scenario_post_capture,
    "correlation": scenario_correlation,
    "session-reject": scenario_session_reject,
    "no-batch-cancel": scenario_no_batch_cancel,
    "no-guard-inbound": scenario_no_guard_inbound,
}


async def main(names: Sequence[str]) -> int:
    selected = list(names) if names else list(ALL_SCENARIOS)
    failed = 0
    for name in selected:
        runner = SCENARIOS[name]  # type: ignore[index]
        try:
            await runner()
            print(f"ok  {name}")
        except Exception as exc:
            failed += 1
            print(f"FAIL {name}: {exc}")
    if os.getenv("ARCJET_VERIFY_LIVE") == "1" and os.getenv("ARCJET_KEY"):
        try:
            await scenario_live_local_pii()
            print("ok  live-local-pii")
        except Exception as exc:
            failed += 1
            print(f"FAIL live-local-pii: {exc}")
    else:
        print("skip live-local-pii (set ARCJET_VERIFY_LIVE=1 and ARCJET_KEY)")
    return 1 if failed else 0


if __name__ == "__main__":
    chosen = [item for item in sys.argv[1:] if item in ALL_SCENARIOS]
    raise SystemExit(asyncio.run(main(chosen)))
