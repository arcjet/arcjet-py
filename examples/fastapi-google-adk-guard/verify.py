"""End-to-end verification of the FastAPI + Google ADK Guard example.

Exercises the same adapter contracts the app uses: `guard_tool` deny
envelope (skip dict with `arcjetDenied`, never `{}`, no throw),
`guard_plugin` skip dict, inbound screening via `google_adk_context`,
caller-owned session id, and the FastAPI `/chat` session check. No
Gemini key is required for the adapter scenarios. Pass `ARCJET_KEY` to
also hit live Guard.
"""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal, Optional

_EXAMPLE_DIR = Path(__file__).resolve().parent
if str(_EXAMPLE_DIR) not in sys.path:
    sys.path.insert(0, str(_EXAMPLE_DIR))

os.environ.setdefault("ARCJET_KEY", "ajkey_verify_placeholder")
os.environ.setdefault("GEMINI_API_KEY", "gemini_verify_placeholder")

from fastapi.testclient import TestClient

from arcjet.guard import server_input
from arcjet.guard._types import Decision, Reason, RuleResultError
from arcjet.guard.google_adk import (
    google_adk_context,
    guard_plugin,
    guard_tool,
)

ScenarioName = Literal[
    "allow",
    "deny",
    "unavailable",
    "actor-inputs",
    "resolver-throw",
    "plugin-allow",
    "plugin-deny",
    "correlation",
    "session-reject",
    "no-empty-dict",
]

ALL_SCENARIOS: tuple[ScenarioName, ...] = (
    "allow",
    "deny",
    "unavailable",
    "actor-inputs",
    "resolver-throw",
    "plugin-allow",
    "plugin-deny",
    "correlation",
    "session-reject",
    "no-empty-dict",
)

SESSION_ID = "sess-verify-001"
_SEND_CALLS: list[str] = []


def send_email(to: str, body: str) -> dict[str, str]:
    """Send an email to a recipient."""
    _SEND_CALLS.append(to)
    return {"status": f"Email sent to {to}"}


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

    def capture(self, **kwargs: Any) -> None:
        self.captures.append(kwargs)


def _allow() -> Decision:
    return Decision(conclusion="ALLOW", id="gdec_allow", reason="UNKNOWN", results=())


def _deny(reason: Reason = "RATE_LIMIT") -> Decision:
    return Decision(conclusion="DENY", id="gdec_deny", reason=reason, results=())


def _failed_open() -> Decision:
    return Decision(
        conclusion="ALLOW",
        id="gdec_error",
        reason="ERROR",
        results=(RuleResultError(conclusion="ALLOW", reason="ERROR", message="down"),),
    )


def _tool(name: str = "send_email") -> SimpleNamespace:
    return SimpleNamespace(name=name)


def _callback(guard: ScenarioGuard, **kwargs: Any) -> Any:
    return guard_tool(
        guard=guard,
        action="email.sent",
        actor=SESSION_ID,
        inputs=lambda call: {
            "recipient": server_input.string(str(call.get("to", ""))),
            "body": server_input.string(str(call.get("body", ""))),
        },
        session_id=SESSION_ID,
        on_guard_error="deny",
        **kwargs,
    )


async def scenario_allow() -> None:
    _SEND_CALLS.clear()
    guard = ScenarioGuard(decision=_allow())
    callback = _callback(guard)
    result = await callback(
        tool=_tool(),
        args={"to": "onboarding-list", "body": "welcome"},
        tool_context=SimpleNamespace(state={"sessionId": SESSION_ID}),
    )
    assert result is None, result
    assert len(guard.guards) == 1
    assert guard.guards[0]["actor"] == SESSION_ID
    assert guard.guards[0]["inputs"] is not None


async def scenario_deny() -> None:
    _SEND_CALLS.clear()
    guard = ScenarioGuard(decision=_deny())
    callback = _callback(guard)
    result = await callback(
        tool=_tool(),
        args={"to": "onboarding-list", "body": "welcome"},
        tool_context=SimpleNamespace(state={"sessionId": SESSION_ID}),
    )
    assert result is not None
    assert result != {}
    assert result["arcjetDenied"] is True
    assert result["reason"] == "RATE_LIMIT"
    assert _SEND_CALLS == []


async def scenario_unavailable() -> None:
    guard = ScenarioGuard(exception=RuntimeError("down"))
    callback = _callback(guard)
    result = await callback(
        tool=_tool(),
        args={"to": "onboarding-list", "body": "welcome"},
        tool_context={},
    )
    assert result is not None
    assert result["reason"] == "ERROR"
    assert result["retryable"] is True


async def scenario_actor_inputs() -> None:
    guard = ScenarioGuard(decision=_allow())
    callback = _callback(guard)
    await callback(
        tool=_tool(),
        args={"to": "onboarding-list", "body": "welcome"},
        tool_context={},
    )
    recorded = guard.guards[0]
    assert recorded["actor"] == SESSION_ID
    assert recorded["inputs"] is not None
    assert "recipient" in recorded["inputs"]
    assert "body" in recorded["inputs"]


async def scenario_resolver_throw() -> None:
    guard = ScenarioGuard(decision=_allow())

    def boom(_call: Any) -> dict[str, Any]:
        raise RuntimeError("resolver exploded")

    callback = guard_tool(
        guard=guard,
        action="email.sent",
        inputs=boom,
        session_id=SESSION_ID,
    )
    result = await callback(
        tool=_tool(),
        args={"to": "onboarding-list", "body": "welcome"},
        tool_context={},
    )
    assert result is not None
    assert result["arcjetDenied"] is True
    assert len(guard.guards) == 1


async def scenario_plugin_allow() -> None:
    guard = ScenarioGuard(decision=_allow())
    plugin = guard_plugin(
        guard=guard,
        action="email.sent",
        actor=SESSION_ID,
        session_id=SESSION_ID,
    )
    result = await plugin.before_tool_callback(
        tool=_tool(),
        tool_args={"to": "onboarding-list", "body": "welcome"},
        tool_context=SimpleNamespace(state={"sessionId": SESSION_ID}),
    )
    assert result is None
    assert len(guard.guards) == 1


async def scenario_plugin_deny() -> None:
    guard = ScenarioGuard(decision=_deny())
    plugin = guard_plugin(
        guard=guard,
        action="email.sent",
        session_id=SESSION_ID,
    )
    result = await plugin.before_tool_callback(
        tool=_tool(),
        tool_args={"to": "onboarding-list", "body": "welcome"},
        tool_context=SimpleNamespace(state={}),
    )
    assert result is not None
    assert result != {}
    assert result["arcjetDenied"] is True


async def scenario_correlation() -> None:
    ctx = google_adk_context({"sessionId": SESSION_ID})
    assert ctx.correlation_id == SESSION_ID
    empty = google_adk_context({})
    assert empty.correlation_id is None


async def scenario_session_reject() -> None:
    from main import app

    client = TestClient(app)
    response = client.post(
        "/chat",
        json={"message": "hello", "session_id": "not\nvalid"},
    )
    assert response.status_code == 400
    assert "session_id" in response.json()["error"]


async def scenario_no_empty_dict() -> None:
    guard = ScenarioGuard(decision=_deny())
    callback = _callback(guard)
    result = await callback(tool=_tool(), args={}, tool_context={})
    assert result
    assert result.get("arcjetDenied") is True


SCENARIOS: dict[ScenarioName, Any] = {
    "allow": scenario_allow,
    "deny": scenario_deny,
    "unavailable": scenario_unavailable,
    "actor-inputs": scenario_actor_inputs,
    "resolver-throw": scenario_resolver_throw,
    "plugin-allow": scenario_plugin_allow,
    "plugin-deny": scenario_plugin_deny,
    "correlation": scenario_correlation,
    "session-reject": scenario_session_reject,
    "no-empty-dict": scenario_no_empty_dict,
}


def main() -> int:
    requested = [name for name in sys.argv[1:] if name in SCENARIOS]
    names: Sequence[ScenarioName] = requested or ALL_SCENARIOS
    failed = 0
    for name in names:
        try:
            asyncio.run(SCENARIOS[name]())
            print(f"ok  {name}")
        except Exception as exc:
            failed += 1
            print(f"FAIL {name}: {exc}")
    if failed:
        print(f"{failed} scenario(s) failed")
        return 1
    print(f"{len(names)} scenario(s) passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
