"""A guarded OpenAI Agents agent behind a FastAPI entrypoint.

Every Arcjet decision this file produces lands on one Sequence, because they
all share one caller-owned correlation ID: `protect()` on the route, the
inbound `guard()` call, and `guard_tool` on the authored FunctionTool. The
id comes from the request, is put on `Runner.run(..., context=...)`, and is
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

# Request-path client. FastAPI and `Runner.run` are async, so this route is
# async and uses `arcjet` for `protect()`.
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


@function_tool
def send_email(to: str, body: str) -> str:
    """Send an email to a recipient.

    Args:
        to: The recipient address.
        body: The email body.
    """
    logger.info("sending email to %s", to)
    return f"Email sent to {to}"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    yield
    # Capture queues rather than blocking the request path, so anything still
    # in the queue is lost unless the process flushes on the way out.
    await guard_client.flush()


app = FastAPI(lifespan=lifespan)


class ChatRequest(BaseModel):
    message: str
    session_id: str


@app.post("/chat")
async def chat(request: Request, body: ChatRequest) -> Any:
    # Derive the correlation ID from something the caller already has — here a
    # session id off the request. A generated id would still join this run's
    # events together, but it would build a Sequence nobody goes looking for;
    # the point is that a human investigating "what did session X do" can find
    # it. The same value is passed to `protect()`, inbound `guard()`, and
    # `Runner.run(..., context=...)`. `openai_agents_context` reads that
    # context. It never mints, never reads `trace_id`, and never constructs
    # `OpenAIConversationsSession()` just for an id.
    #
    # EXAMPLE ONLY: this trusts `session_id` from the request body, so a caller
    # could write to another session's Sequence and to its actor and metadata.
    # In a real service take it from the authenticated session — a signed
    # cookie, a verified token claim — never from a field the caller controls.
    correlation_id = body.session_id
    app_context = {"session_id": body.session_id}

    decision = await aj.protect(
        request,
        requested=5,
        characteristics={"userId": body.session_id},
        correlation_id=correlation_id,
    )
    if decision.is_denied():
        status = 429 if decision.reason.is_rate_limit() else 403
        return JSONResponse(
            {"error": "Denied", "reason": decision.reason.to_dict()},
            status_code=status,
        )

    with arcjet_sequence(correlation_id=correlation_id):
        # Screen inbound user text yourself. There is no `guard_inbound`
        # helper. Core `guard()` fails open — an unevaluated policy is an
        # ALLOW with `has_failed_open()` — so this route refuses to start
        # `Runner.run` on either DENY or a failed-open ALLOW.
        derived = openai_agents_context(app_context)
        inbound = await guard_client.guard(
            (
                detect_injection(body.message),
                detect_sensitive_info(body.message),
            ),
            label="chat.inbound",
            actor=body.session_id,
            inputs={"content": server_input.string(body.message)},
            correlation_id=derived.correlation_id,
            metadata=security_metadata(
                user=body.session_id,
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

        # Wrap the authored FunctionTool. The copy's tool_input_guardrails
        # start with Arcjet; a DENY is reject_content so invoke never runs.
        # Fail closed: if policy cannot be evaluated at all, the tool does
        # not run. This is the one place Arcjet diverges from its
        # platform-wide fail-open convention. Pass "allow" to opt out — but
        # note an evaluated DENY still blocks either way.
        #
        # Hosted tools, MCP, Computer/Shell/ApplyPatch, handoffs, and
        # Agent.as_tool() are not on this authored FunctionTool path.
        guarded_send_email = guard_tool(
            guard=guard_client,
            tool=send_email,
            action="email.sent",
            actor=body.session_id,
            inputs=lambda args: {
                "recipient": server_input.string(str(args.get("to", ""))),
                "body": server_input.string(str(args.get("body", ""))),
            },
            rules=(
                detect_injection(body.message),
                # Sensitive info DENIES; it does not redact. If this
                # trips, the tool does not run and nothing is rewritten on
                # the way through.
                detect_sensitive_info(body.message),
            ),
            metadata=security_metadata(
                user=body.session_id,
                agent="email-agent",
                workflow="chat",
                resource="email",
                destination="email",
                reversibility="irreversible",
            ),
            on_guard_error="deny",
        )

        agent = Agent(
            name="Email assistant",
            instructions=(
                "You always use the send_email tool to fulfill a request. "
                "You never skip the tool to answer in text alone. "
                "Call send_email exactly once. If the tool is blocked, do "
                "not call it again; explain that security blocked it."
            ),
            tools=[guarded_send_email],
        )

        # needs_approval is HITL, not a policy gate. This example does not
        # set it and does not mutate RunConfig.
        # pre_approval_tool_input_guardrails=True is an application opt-in
        # if you want input guardrails before a HITL pause; Arcjet does not
        # set it.
        result = await Runner.run(
            agent,
            body.message,
            context=app_context,
        )
        await guard_client.flush()

        reply = str(result.final_output)

    return {"reply": reply, "session_id": body.session_id}
