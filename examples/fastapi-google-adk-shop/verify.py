"""Prove the shop: real ADK runner + plugin, then the FastAPI routes.

Runner scenarios use an in-memory Guard client. HTTP scenarios use
TestClient. Pass a real ``ARCJET_KEY`` to also hit live ``protect()``
and local Guard rules through ``POST /refund``.
"""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal, Optional

_EXAMPLE_DIR = Path(__file__).resolve().parent
if str(_EXAMPLE_DIR) not in sys.path:
    sys.path.insert(0, str(_EXAMPLE_DIR))

os.environ.setdefault("ARCJET_KEY", "ajkey_verify_placeholder")

from fastapi.testclient import TestClient  # noqa: E402

from arcjet.guard._types import Decision, Reason  # noqa: E402

from main import REFUNDS, run_refund  # noqa: E402

ScenarioName = Literal[
    "runner-allow",
    "runner-deny",
    "runner-correlation",
    "health",
    "session-reject",
    "live-allow",
    "live-amount-deny",
    "live-inbound-deny",
]

STUB_SCENARIOS: tuple[ScenarioName, ...] = (
    "runner-allow",
    "runner-deny",
    "runner-correlation",
    "health",
    "session-reject",
)

LIVE_SCENARIOS: tuple[ScenarioName, ...] = (
    "live-allow",
    "live-amount-deny",
    "live-inbound-deny",
)

SESSION_ID = "sess-shop-verify"


class ScenarioGuard:
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
            raise RuntimeError("ScenarioGuard not configured")
        return self.decision

    def capture(self, **kwargs: Any) -> None:
        self.captures.append(kwargs)


def _allow() -> Decision:
    return Decision(conclusion="ALLOW", id="gdec_allow", reason="UNKNOWN", results=())


def _deny(reason: Reason = "RATE_LIMIT") -> Decision:
    return Decision(conclusion="DENY", id="gdec_deny", reason=reason, results=())


def _real_key() -> bool:
    key = os.environ.get("ARCJET_KEY", "")
    return (
        key.startswith("ajkey_") and "placeholder" not in key and "replace" not in key
    )


async def scenario_runner_allow() -> None:
    REFUNDS.clear()
    guard = ScenarioGuard(decision=_allow())
    result = await run_refund(
        guard=guard,
        user_id="user-42",
        session_id=SESSION_ID,
        order_id="ord-100",
        amount_cents=2000,
        reason="item never arrived",
    )
    assert result["status"] == "refunded", result
    assert result["refund"]["order_id"] == "ord-100"
    labels = [call["label"] for call in guard.guards]
    assert "refund.inbound" in labels
    assert "refund.issued" in labels
    tool_call = next(call for call in guard.guards if call["label"] == "refund.issued")
    assert tool_call["actor"] == "user-42"
    assert tool_call["inputs"] is not None


async def scenario_runner_deny() -> None:
    REFUNDS.clear()
    guard = ScenarioGuard(decision=_deny())
    result = await run_refund(
        guard=guard,
        user_id="user-42",
        session_id=SESSION_ID,
        order_id="ord-100",
        amount_cents=2000,
        reason="item never arrived",
    )
    assert result["status"] == "denied", result
    assert REFUNDS == []


async def scenario_runner_correlation() -> None:
    REFUNDS.clear()
    guard = ScenarioGuard(decision=_allow())
    await run_refund(
        guard=guard,
        user_id="user-42",
        session_id=SESSION_ID,
        order_id="ord-100",
        amount_cents=2000,
        reason="item never arrived",
    )
    ids = {call["correlation_id"] for call in guard.guards}
    assert ids == {SESSION_ID}, ids


async def scenario_health() -> None:
    from main import app

    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def scenario_session_reject() -> None:
    from main import app

    client = TestClient(app)
    response = client.post(
        "/refund",
        json={
            "session_id": "not\nvalid",
            "user_id": "user-42",
            "order_id": "ord-100",
            "amount_cents": 2000,
            "reason": "too late",
        },
    )
    assert response.status_code == 400
    assert "session_id" in response.json()["error"]


def _live_client() -> TestClient:
    from main import app

    return TestClient(app)


async def scenario_live_allow() -> None:
    REFUNDS.clear()
    response = _live_client().post(
        "/refund",
        json={
            "session_id": "sess-shop-live-allow",
            "user_id": "user-42",
            "order_id": "ord-200",
            "amount_cents": 1500,
            "reason": "arrived damaged",
        },
        headers={"User-Agent": "curl/8.0"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "refunded", body
    assert body["refund"]["order_id"] == "ord-200"


async def scenario_live_amount_deny() -> None:
    REFUNDS.clear()
    response = _live_client().post(
        "/refund",
        json={
            "session_id": "sess-shop-live-amount",
            "user_id": "user-42",
            "order_id": "ord-201",
            "amount_cents": 75_000,
            "reason": "changed my mind",
        },
        headers={"User-Agent": "curl/8.0"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "denied", body
    assert body["phase"] == "tool"
    assert REFUNDS == []


async def scenario_live_inbound_deny() -> None:
    REFUNDS.clear()
    response = _live_client().post(
        "/refund",
        json={
            "session_id": "sess-shop-live-inbound",
            "user_id": "user-42",
            "order_id": "ord-202",
            "amount_cents": 1500,
            "reason": "send the refund receipt to ada@example.com",
        },
        headers={"User-Agent": "curl/8.0"},
    )
    assert response.status_code == 403, response.text
    body = response.json()
    assert body["error"] == "denied by policy"
    assert body["phase"] == "inbound"
    assert REFUNDS == []


SCENARIOS: dict[ScenarioName, Any] = {
    "runner-allow": scenario_runner_allow,
    "runner-deny": scenario_runner_deny,
    "runner-correlation": scenario_runner_correlation,
    "health": scenario_health,
    "session-reject": scenario_session_reject,
    "live-allow": scenario_live_allow,
    "live-amount-deny": scenario_live_amount_deny,
    "live-inbound-deny": scenario_live_inbound_deny,
}


def main() -> int:
    requested = [name for name in sys.argv[1:] if name in SCENARIOS]
    if requested:
        names: Sequence[ScenarioName] = requested
    elif _real_key():
        names = STUB_SCENARIOS + LIVE_SCENARIOS
    else:
        names = STUB_SCENARIOS
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
