"""A guarded Google ADK agent behind a FastAPI entrypoint.

Every Arcjet decision this file produces lands on one Sequence, because they
all share one caller-owned id: `protect()` on the route, the inbound
`guard()` call, and `guard_tool` on `LlmAgent.before_tool_callback`. The
id comes from the request and is put on `google_adk_context` as
`sessionId` only, so the helper's preference order (`correlationId` then
`sessionId` then `conversationId`) is visible. It is never minted here —
`google_adk_context` only reads it. ADK `session.id` / `invocation_id`
are never a source.
"""

import logging
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from google.adk.agents import LlmAgent
from google.adk.runners import InMemoryRunner
from google.genai import types
from pydantic import BaseModel

from arcjet import (
    Mode,
    arcjet,
    detect_bot,
    shield,
    token_bucket,
)
from arcjet.guard import (
    DetectPromptInjection,
    LocalDetectSensitiveInfo,
    arcjet_sequence,
    launch_arcjet,
    security_metadata,
    server_input,
)
from arcjet.guard.google_adk import google_adk_context, guard_tool

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Presence only. Nothing here validates a key or reaches the network, so
# placeholder values are enough to import this module and inspect the app.
ARCJET_KEY = os.getenv("ARCJET_KEY")
if not ARCJET_KEY:
    raise RuntimeError(
        "ARCJET_KEY is required. Get one with `arcjet sites get-key`"
        " or from https://app.arcjet.com"
    )

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise RuntimeError(
        "GEMINI_API_KEY is required. Get one at https://aistudio.google.com"
    )

# Request-path client. FastAPI and `runner.run_async` are async, so this
# route is async and uses `arcjet` for `protect()`.
aj = arcjet(
    key=ARCJET_KEY,
    rules=[
        shield(mode=Mode.LIVE),
        detect_bot(
            mode=Mode.LIVE,
            # An empty allow list blocks all bots. CURL stays so the README
            # curl can reach the agent.
            allow=["CURL"],
        ),
        # EXAMPLE ONLY: `userId` is later bound to the request-body
        # `session_id`. A caller who rotates that field bypasses the
        # bucket. In a real service key it on an authenticated identity.
        token_bucket(
            characteristics=["userId"],
            mode=Mode.LIVE,
            refill_rate=5,
            interval=10,
            capacity=10,
        ),
    ],
)

# Inbound- and tool-path client. The runner is async, so this is
# `launch_arcjet`, not `launch_arcjet_sync`.
guard_client = launch_arcjet(key=ARCJET_KEY)

# Rule configuration is built once; each request binds its own input to it.
detect_injection = DetectPromptInjection()
detect_sensitive_info = LocalDetectSensitiveInfo(deny=["EMAIL", "PHONE_NUMBER"])

# Overridable so a dated snapshot does not pin the example shut.
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")


def send_email(to: str, body: str) -> dict[str, str]:
    """Send an email to a recipient.

    Args:
        to: The recipient address.
        body: The email body.
    """
    logger.info("sending email")
    return {"status": f"Email sent to {to}"}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    yield
    # Capture queues rather than blocking the request path, so anything still
    # in the queue is lost unless the process flushes on the way out.
    await guard_client.flush()


app = FastAPI(lifespan=lifespan)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


class ChatRequest(BaseModel):
    message: str
    session_id: str


# Same bound Guard enforces on a Sequence id. Rejecting beats truncating.
_MAX_SESSION_ID_BYTES = 256


def _caller_owned_session_id(value: str) -> str | None:
    """Return *value* if Guard will accept it as a Sequence id. Never mint."""
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
    return "".join(parts)


@app.post("/chat")
async def chat(request: Request, body: ChatRequest) -> Any:
    # Derive the correlation ID from something the caller already has — here a
    # session id off the request. A generated id would still join this run's
    # events together, but it would build a Sequence nobody goes looking for;
    # the point is that a human investigating "what did session X do" can find
    # it. The same value is passed to `protect()`, inbound `guard()`,
    # `guard_tool`, and `runner.run_async(..., session_id=)`.
    # `google_adk_context` reads `correlationId` then `sessionId` then
    # `conversationId` (JS camelCase first, snake_case aliases second). Only
    # `sessionId` is set here so that order is not hidden by writing the
    # same value into every slot. It never mints, never reads `trace_id`,
    # never reads an ADK-generated `invocation_id`, and never reads
    # `toolContext.sessionId` or `session.id`.
    #
    # EXAMPLE ONLY: this trusts `session_id` from the request body, so a caller
    # could write to another session's Sequence and to its actor and metadata.
    # In a real service take it from the authenticated session — a signed
    # cookie, a verified token claim — never from a field the caller controls.
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

    app_context = {"sessionId": session_id}
    derived = google_adk_context(app_context)
    # Already validated above, so this is that same id — not a second
    # failure mode.
    correlation_id = derived.correlation_id or session_id

    decision = await aj.protect(
        request,
        requested=5,
        characteristics={"userId": session_id},
        correlation_id=correlation_id,
    )
    # `protect()` is fail-open. An evaluated DENY is `is_denied()`. An
    # unevaluated request (transport / invalid response) is `is_error()` —
    # the request-path equivalent of Guard's `has_failed_open()`. Either way
    # this route refuses to start the agent.
    if decision.is_denied():
        status = 429 if decision.reason.is_rate_limit() else 403
        return JSONResponse(
            {"error": "Denied", "reason": decision.reason.to_dict()},
            status_code=status,
        )
    if decision.is_error():
        logger.error("arcjet request policy could not be evaluated; failing closed")
        return JSONResponse({"error": "policy unavailable"}, status_code=503)

    with arcjet_sequence(correlation_id=correlation_id):
        # Screen inbound user text yourself. There is no `guard_inbound`
        # helper. Core `guard()` fails open — an unevaluated policy is an
        # ALLOW with `has_failed_open()` — so this route refuses to start
        # `run_async` on either DENY or a failed-open ALLOW.
        inbound = await guard_client.guard(
            (
                detect_injection(body.message),
                detect_sensitive_info(body.message),
            ),
            label="chat.inbound",
            actor=session_id,
            inputs={"content": server_input.string(body.message)},
            correlation_id=correlation_id,
            metadata=security_metadata(
                user=session_id,
                agent="email-agent",
                workflow="chat",
            ),
        )
        if inbound.conclusion == "DENY":
            logger.warning("arcjet denied inbound text: %s", inbound.reason)
            return JSONResponse({"error": "denied by policy"}, status_code=403)
        if inbound.has_failed_open():
            logger.error("arcjet inbound policy could not be evaluated; failing closed")
            return JSONResponse({"error": "policy unavailable"}, status_code=503)

        # `guard_tool` is `LlmAgent.before_tool_callback`, not a
        # `FunctionTool` wrap. On DENY the original handler does not run.
        # The deny is a skip dict with `arcjetDenied`. `None` allows.
        # Never `{}` (falsy in ADK's callback chain, so the tool would
        # run). Do not throw. Fail closed: if policy cannot be evaluated
        # at all, the tool does not run. This is the one place Arcjet
        # diverges from its platform-wide fail-open convention.
        #
        # Actor is the authenticated session id, never a model-produced
        # argument. Inputs are the policyInput equivalent (`server_input`).
        # Omit them and a remote policy that requires those values never
        # fires.
        #
        # `request_confirmation` is HITL, not a policy gate — this
        # callback never calls it. Do not also attach `guard_plugin` to
        # this agent; plugins run first and a second gate double-calls
        # Guard.
        before_tool = guard_tool(
            guard=guard_client,
            action="email.sent",
            actor=session_id,
            inputs=lambda call: {
                "recipient": server_input.string(str(call.get("to", ""))),
                "body": server_input.string(str(call.get("body", ""))),
            },
            rules=lambda call: (
                detect_injection(str(call.get("body", ""))),
                # Sensitive info DENIES; it does not redact. The recipient
                # address is the point of this tool, so EMAIL on `to` is
                # not a rule — that would deny every real send. EMAIL in
                # the body still blocks.
                detect_sensitive_info(str(call.get("body", ""))),
            ),
            metadata=security_metadata(
                user=session_id,
                agent="email-agent",
                workflow="chat",
                resource="email",
                destination="email",
                reversibility="irreversible",
            ),
            session_id=session_id,
            on_guard_error="deny",
        )

        # A new agent + runner per request so conversation history does
        # not leak across sessions. Pass the caller-owned id as ADK
        # `session_id` so ADK does not mint one. `google_adk_context`
        # still does not read that generated field — the wrap-time
        # `session_id=` and the inbound `guard()` share the same value.
        agent = LlmAgent(
            name="email_agent",
            model=GEMINI_MODEL,
            instruction=(
                "You always use the send_email tool to fulfill a request. "
                "You never skip the tool to answer in text alone. "
                "Call send_email exactly once. If the tool is blocked, do "
                "not call it again; explain that security blocked it."
            ),
            tools=[send_email],
            before_tool_callback=before_tool,
        )
        runner = InMemoryRunner(agent=agent, app_name="email-agent")
        await runner.session_service.create_session(
            app_name="email-agent",
            user_id=session_id,
            session_id=session_id,
            state=app_context,
        )

        events = []
        async for event in runner.run_async(
            user_id=session_id,
            session_id=session_id,
            new_message=types.Content(
                role="user",
                parts=[types.Part(text=body.message)],
            ),
        ):
            events.append(event)
        await guard_client.flush()

        reply = _reply_from_events(events)

    return {"reply": reply, "session_id": session_id}
