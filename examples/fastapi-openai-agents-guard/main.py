"""A guarded OpenAI Agents agent behind a FastAPI entrypoint.

Every Arcjet decision this file produces lands on one Sequence, because they
all share one caller-owned id: `protect()` on the route, the inbound
`guard()` call, and `guard_tool` on the authored `FunctionTool`. The id
comes from the request and is put on `Runner.run(..., context=)` as
`session_id` only, so the helper's preference order (`correlation_id` then
`session_id` then `conversation_id` then `group_id`) is visible. It is
never minted here — `openai_agents_context` only reads it.
"""

import logging
import os
from contextlib import asynccontextmanager
from typing import Any

from agents import Agent, Runner, function_tool
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
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
from arcjet.guard.openai_agents import guard_tool, openai_agents_context

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

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise RuntimeError(
        "OPENAI_API_KEY is required. Get one at https://platform.openai.com"
    )

# Request-path client. FastAPI and `Runner.run` are async, so this route
# is async and uses `arcjet` for `protect()`.
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
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")


@function_tool
def send_email(to: str, body: str) -> str:
    """Send an email to a recipient.

    Args:
        to: The recipient address.
        body: The email body.
    """
    logger.info("sending email")
    return f"Email sent to {to}"


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


@app.post("/chat")
async def chat(request: Request, body: ChatRequest) -> Any:
    # Derive the correlation ID from something the caller already has — here a
    # session id off the request. A generated id would still join this run's
    # events together, but it would build a Sequence nobody goes looking for;
    # the point is that a human investigating "what did session X do" can find
    # it. The same value is passed to `protect()`, inbound `guard()`,
    # `guard_tool`, and `Runner.run(..., context={"session_id": ...})`.
    # `openai_agents_context` reads `correlation_id` then `session_id` then
    # `conversation_id` then `group_id` (snake_case first, JS camelCase
    # aliases second). Only `session_id` is set here so that order is not
    # hidden by writing the same value into every slot. It never mints,
    # never reads `trace_id`, and never constructs
    # `OpenAIConversationsSession()` just for an id.
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

    app_context = {"session_id": session_id}
    derived = openai_agents_context(app_context)
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
        # helper. SDK `input_guardrails` on the `Agent` are not Arcjet.
        # Core `guard()` fails open — an unevaluated policy is an ALLOW
        # with `has_failed_open()` — so this route refuses to start
        # `Runner.run` on either DENY or a failed-open ALLOW.
        inbound = await guard_client.guard(
            (
                detect_injection(body.message),
                detect_sensitive_info(body.message),
            ),
            label="chat.inbound",
            actor=session_id,
            inputs={"content": server_input.string(body.message)},
            correlation_id=derived.correlation_id,
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

        # Wrap the authored `FunctionTool`. On DENY the original handler
        # does not run. The deny is `reject_content` of a JSON
        # `ArcjetDenialResult` — do not `raise_exception()` (that halts
        # the run) and do not raise an Arcjet error from `on_invoke_tool`
        # (the SDK `default_tool_error_function` would swallow it). Fail
        # closed: if policy cannot be evaluated at all, the tool does not
        # run. This is the one place Arcjet diverges from its platform-wide
        # fail-open convention. Pass "allow" to opt out — but note an
        # evaluated DENY still blocks either way.
        #
        # Tool-path rules judge the call arguments, not the inbound prompt.
        # `needs_approval` is HITL, not a policy gate — this wrap never
        # sets it. Hosted tools, MCP, Computer / Shell / ApplyPatch,
        # handoffs, and `Agent.as_tool()` are not on this path.
        guarded_send_email = guard_tool(
            guard=guard_client,
            tool=send_email,
            action="email.sent",
            actor=session_id,
            inputs=lambda args: {
                "recipient": server_input.string(str(args.get("to", ""))),
                "body": server_input.string(str(args.get("body", ""))),
            },
            rules=lambda args: (
                detect_injection(str(args.get("body", ""))),
                # Sensitive info DENIES; it does not redact. The recipient
                # address is the point of this tool, so EMAIL on `to` is
                # not a rule — that would deny every real send. EMAIL in
                # the body still blocks.
                detect_sensitive_info(str(args.get("body", ""))),
            ),
            metadata=security_metadata(
                user=session_id,
                agent="email-agent",
                workflow="chat",
                resource="email",
                destination="email",
                reversibility="irreversible",
            ),
            correlation_id=session_id,
            on_guard_error="deny",
        )

        # A new Agent per request so conversation history does not leak
        # across sessions. Do not pass a session object — that would mint
        # an id. Do not pass `trace_id` as a Sequence id.
        agent = Agent(
            name="email-agent",
            model=OPENAI_MODEL,
            instructions=(
                "You always use the send_email tool to fulfill a request. "
                "You never skip the tool to answer in text alone. "
                "Call send_email exactly once. If the tool is blocked, do "
                "not call it again; explain that security blocked it."
            ),
            tools=[guarded_send_email],
        )

        result = await Runner.run(
            agent,
            body.message,
            context=app_context,
        )
        await guard_client.flush()

        reply = str(result.final_output)

    return {"reply": reply, "session_id": session_id}
