"""A refund desk: FastAPI + a real Google ADK runner, gated by Guard.

No Gemini key. A scripted ``BaseLlm`` always calls ``issue_refund`` so
the tool path is deterministic. ``guard_plugin`` is first on the Runner.
The caller-owned Sequence id is written only to ADK session state as
``sessionId`` — ``google_adk_context`` must read ADK's dict-like
``State`` (not a ``Mapping``). Wrap-time ``session_id=`` is omitted on
purpose so a missed state read would leave the call uncorrelated.
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any, Optional, TypedDict

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from google.adk.agents import LlmAgent
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import InMemoryRunner
from google.genai import types
from pydantic import BaseModel, Field

from arcjet import Mode, arcjet, detect_bot, shield
from arcjet.guard import (
    CustomEvaluateResult,
    DetectPromptInjection,
    LocalCustomRule,
    LocalDetectSensitiveInfo,
    arcjet_sequence,
    launch_arcjet,
    security_metadata,
    server_input,
)
from arcjet.guard.google_adk import google_adk_context, guard_plugin

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ARCJET_KEY = os.getenv("ARCJET_KEY")
if not ARCJET_KEY:
    raise RuntimeError(
        "ARCJET_KEY is required. Get one with `arcjet sites get-key`"
        " or from https://app.arcjet.com"
    )

aj = arcjet(
    key=ARCJET_KEY,
    rules=[
        shield(mode=Mode.LIVE),
        detect_bot(mode=Mode.LIVE, allow=["CURL"]),
    ],
)
guard_client = launch_arcjet(key=ARCJET_KEY)

detect_injection = DetectPromptInjection()
detect_sensitive_info = LocalDetectSensitiveInfo(deny=["EMAIL", "PHONE_NUMBER"])

REFUNDS: list[dict[str, Any]] = []
_MAX_SESSION_ID_BYTES = 256
_MAX_REFUND_CENTS = 50_000


class RefundLimitConfig(TypedDict):
    max_cents: str


class RefundLimitInput(TypedDict):
    amount_cents: str


class RefundLimitData(TypedDict):
    amount_cents: str


class RefundLimitRule(
    LocalCustomRule[RefundLimitConfig, RefundLimitInput, RefundLimitData]
):
    def evaluate(
        self,
        config: RefundLimitConfig,
        input: RefundLimitInput,
    ) -> CustomEvaluateResult:
        try:
            amount = int(input["amount_cents"])
            limit = int(config["max_cents"])
        except (KeyError, TypeError, ValueError):
            return CustomEvaluateResult(
                conclusion="DENY",
                data={"amount_cents": str(input.get("amount_cents", ""))},
            )
        if amount > limit:
            return CustomEvaluateResult(
                conclusion="DENY",
                data={"amount_cents": str(amount)},
            )
        return CustomEvaluateResult(conclusion="ALLOW")


refund_limit = RefundLimitRule(config={"max_cents": str(_MAX_REFUND_CENTS)})


def issue_refund(order_id: str, amount_cents: int, reason: str) -> dict[str, str]:
    """Issue a refund for an order.

    Args:
        order_id: The order to refund.
        amount_cents: Amount in cents.
        reason: Why the refund is being issued.
    """
    record = {
        "order_id": order_id,
        "amount_cents": amount_cents,
        "reason": reason,
    }
    REFUNDS.append(record)
    logger.info("issued refund %s", record)
    return {"status": f"Refunded {order_id} for {amount_cents} cents"}


class ScriptedRefundLlm(BaseLlm):
    """Calls ``issue_refund`` once with args set on this instance."""

    model: str = "scripted-refund"
    next_call: dict[str, Any] = {}

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
                            args=dict(self.next_call),
                        )
                    )
                ],
            )
        )


def _caller_owned_session_id(value: str) -> Optional[str]:
    candidate = value.strip()
    if not candidate:
        return None
    if not candidate.isascii() or not candidate.isprintable():
        return None
    if len(candidate.encode("utf-8")) > _MAX_SESSION_ID_BYTES:
        return None
    return candidate


def _reply_from_events(events: list[Any]) -> str:
    parts: list[str] = []
    for event in events:
        content = getattr(event, "content", None)
        event_parts = getattr(content, "parts", None) if content is not None else None
        if not event_parts:
            continue
        for part in event_parts:
            text = getattr(part, "text", None)
            if isinstance(text, str) and text:
                parts.append(text)
            function_response = getattr(part, "function_response", None)
            if function_response is not None:
                response = getattr(function_response, "response", None)
                if isinstance(response, dict) and response.get("arcjetDenied"):
                    parts.append("blocked by policy")
    return "".join(parts)


async def run_refund(
    *,
    guard: Any,
    user_id: str,
    session_id: str,
    order_id: str,
    amount_cents: int,
    reason: str,
) -> dict[str, Any]:
    """Drive one refund through a real ADK runner. Used by the route and verify."""
    app_context = {"sessionId": session_id}
    derived = google_adk_context(app_context)
    correlation_id = derived.correlation_id or session_id

    inbound = await guard.guard(
        (
            detect_injection(reason),
            detect_sensitive_info(reason),
        ),
        label="refund.inbound",
        actor=user_id,
        inputs={"reason": server_input.string(reason)},
        correlation_id=correlation_id,
        metadata=security_metadata(
            user=user_id,
            agent="refund-desk",
            workflow="refund",
        ),
    )
    if inbound.conclusion == "DENY":
        return {"status": "denied", "phase": "inbound", "reason": inbound.reason}
    if inbound.has_failed_open():
        return {"status": "unavailable", "phase": "inbound"}

    plugin = guard_plugin(
        guard=guard,
        action="refund.issued",
        actor=user_id,
        inputs=lambda call: {
            "order_id": server_input.string(str(call.get("order_id", ""))),
            "amount_cents": server_input.integer(int(call.get("amount_cents") or 0)),
            "reason": server_input.string(str(call.get("reason", ""))),
        },
        rules=lambda call: (
            refund_limit(data={"amount_cents": str(call.get("amount_cents") or 0)}),
            detect_injection(str(call.get("reason", ""))),
            detect_sensitive_info(str(call.get("reason", ""))),
        ),
        metadata=security_metadata(
            user=user_id,
            agent="refund-desk",
            workflow="refund",
            resource="order",
            reversibility="irreversible",
        ),
        on_guard_error="deny",
    )

    model = ScriptedRefundLlm(
        next_call={
            "order_id": order_id,
            "amount_cents": amount_cents,
            "reason": reason,
        }
    )
    agent = LlmAgent(
        name="refund_agent",
        model=model,
        instruction="Always call issue_refund exactly once.",
        tools=[issue_refund],
    )
    runner = InMemoryRunner(agent=agent, app_name="refund-desk", plugins=[plugin])
    await runner.session_service.create_session(
        app_name="refund-desk",
        user_id=user_id,
        session_id=session_id,
        state=app_context,
    )

    before = len(REFUNDS)
    events: list[Any] = []
    async for event in runner.run_async(
        user_id=user_id,
        session_id=session_id,
        new_message=types.Content(
            role="user",
            parts=[
                types.Part(text=f"Refund {order_id} for {amount_cents} cents. {reason}")
            ],
        ),
    ):
        events.append(event)

    issued = REFUNDS[before:]
    reply = _reply_from_events(events)
    if not issued:
        return {
            "status": "denied",
            "phase": "tool",
            "reply": reply,
            "session_id": session_id,
        }
    return {
        "status": "refunded",
        "phase": "tool",
        "reply": reply,
        "session_id": session_id,
        "refund": issued[-1],
    }


@asynccontextmanager
async def lifespan(_app: FastAPI):
    yield
    await guard_client.flush()


app = FastAPI(lifespan=lifespan)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


class RefundRequest(BaseModel):
    session_id: str
    user_id: str
    order_id: str
    amount_cents: int = Field(gt=0)
    reason: str


@app.post("/refund")
async def refund(request: Request, body: RefundRequest) -> Any:
    session_id = _caller_owned_session_id(body.session_id)
    if session_id is None:
        return JSONResponse(
            {
                "error": (
                    "session_id must be a caller-owned printable ASCII id "
                    "(at most 256 bytes)"
                )
            },
            status_code=400,
        )

    user_id = body.user_id.strip()
    if not user_id:
        return JSONResponse({"error": "user_id is required"}, status_code=400)

    # EXAMPLE ONLY: user_id / session_id come from the body. A real desk
    # takes them from the authenticated session.
    decision = await aj.protect(
        request,
        characteristics={"userId": user_id},
        correlation_id=session_id,
    )
    if decision.is_denied():
        status = 429 if decision.reason.is_rate_limit() else 403
        return JSONResponse(
            {"error": "Denied", "reason": decision.reason.to_dict()},
            status_code=status,
        )
    if decision.is_error():
        logger.error("arcjet request policy could not be evaluated; failing closed")
        return JSONResponse({"error": "policy unavailable"}, status_code=503)

    with arcjet_sequence(correlation_id=session_id):
        result = await run_refund(
            guard=guard_client,
            user_id=user_id,
            session_id=session_id,
            order_id=body.order_id,
            amount_cents=body.amount_cents,
            reason=body.reason,
        )
        await guard_client.flush()

    if result["status"] == "unavailable":
        return JSONResponse({"error": "policy unavailable"}, status_code=503)
    if result["status"] == "denied" and result.get("phase") == "inbound":
        return JSONResponse(
            {"error": "denied by policy", "phase": "inbound"},
            status_code=403,
        )
    return result
