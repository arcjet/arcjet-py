"""A guarded Strands Agents agent behind a FastAPI entrypoint.

Every Arcjet decision this file produces lands on one Sequence, because they
all share one caller-owned id: `protect()` on the route, the inbound
`guard()` call, `guard_tool` on the authored `@tool`, and `guard_hooks` on
the unwrapped tool. The id comes from the request and is put on
`invocation_state` as `sessionId` only, so the helper's preference order
(`correlationId` then `sessionId` then `requestId`) is visible. It is never
minted here — `strands_agent_context` only reads it.
"""

import logging
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from strands import Agent, tool
from strands.models.anthropic import AnthropicModel

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
from arcjet.guard.strands_agents import (
    guard_hooks,
    guard_tool,
    strands_agent_context,
)

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

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
if not ANTHROPIC_API_KEY:
    raise RuntimeError(
        "ANTHROPIC_API_KEY is required. Get one at https://console.anthropic.com"
    )

# Request-path client. FastAPI and `Agent.invoke_async` are async, so this
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
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
model = AnthropicModel(
    client_args={"api_key": ANTHROPIC_API_KEY},
    model_id=ANTHROPIC_MODEL,
)


@tool
def send_email(to: str, body: str) -> str:
    """Send an email to a recipient.

    Args:
        to: The recipient address.
        body: The email body.
    """
    logger.info("sending email to %s", to)
    return f"Email sent to {to}"


@tool
def lookup_account(account_id: str) -> str:
    """Look up an account by its internal id.

    Args:
        account_id: The account id to look up. This is not an email address.
    """
    logger.info("looking up account %s", account_id)
    return f"Account found for {account_id}"


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
    # `guard_tool` / `guard_hooks`, and `invoke_async(..., invocation_state=)`.
    # `strands_agent_context` reads `correlationId` then `sessionId` then
    # `requestId` (JS camelCase first, snake_case aliases second). Only
    # `sessionId` is set here so that order is not hidden by writing the
    # same value into every slot. It never mints, never reads `trace_id`,
    # and never constructs a SessionManager just for an id.
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

    invocation_state = {"sessionId": session_id}
    derived = strands_agent_context(invocation_state)
    correlation_id = derived.correlation_id
    if correlation_id is None:
        return JSONResponse(
            {
                "error": (
                    "session_id must be a caller-owned printable ASCII id "
                    "(at most 256 bytes)"
                )
            },
            status_code=400,
        )

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
        # helper and no inbound hook on the Strands bus (`MessageAddedEvent`
        # is observe-only; `BeforeInvocationEvent.cancel` aborts the whole
        # run, not a prompt screen). Core `guard()` fails open — an
        # unevaluated policy is an ALLOW with `has_failed_open()` — so this
        # route refuses to start `invoke_async` on either DENY or a
        # failed-open ALLOW.
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

        # Wrap the authored `@tool`. On DENY the original handler does not
        # run. The deny is a returned `ArcjetDenialResult` dict — do not
        # throw (the SDK swallows into `Error: {Type} - {message}`). Fail
        # closed: if policy cannot be evaluated at all, the tool does not
        # run. This is the one place Arcjet diverges from its platform-wide
        # fail-open convention. Pass "allow" to opt out — but note an
        # evaluated DENY still blocks either way.
        #
        # Tool-path rules judge the call arguments, not the inbound prompt.
        # `event.interrupt()` is HITL, not a policy gate — this wrap never
        # calls it.
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
            session_id=session_id,
            on_guard_error="deny",
        )

        # `BeforeToolCallEvent` fires for every tool, including the wrapped
        # one. `guard_tool` brands its copy; `guard_hooks` skips branded
        # tools on the before path so Guard is not called twice. There is
        # no `exclude=` list — brand-skip is the only skip.
        #
        # Deny is `cancel_tool` set to the JSON `ArcjetDenialResult` (a str)
        # or `True`. Do not set `BeforeToolsEvent.cancel`: a batch cancel
        # skips per-tool `BeforeToolCallEvent` hooks, so brand-skip would
        # never run and every tool in the batch would share one deny.
        #
        # `lookup_account` is left unwrapped so `cancel_tool` is its only
        # gate. Its argument is an account id, not an email, so a clean
        # lookup can allow and still emit `AfterToolCallEvent` capture.
        # EMAIL in that id still denies. `AfterToolCallEvent` is
        # capture-only (`strands.phase: after`) and is not skipped by the
        # brand. `event.interrupt()` is HITL, not policy, and is never
        # called.
        hooks = guard_hooks(
            guard=guard_client,
            actor=session_id,
            inputs=lambda call: {
                key: server_input.string(str(value))
                for key, value in call.items()
                if key != "tool_name"
            },
            rules=lambda call: (
                detect_injection(
                    str(
                        call.get("body")
                        or call.get("command")
                        or call.get("account_id")
                        or ""
                    )
                ),
                detect_sensitive_info(
                    " ".join(
                        str(value)
                        for key, value in call.items()
                        if key != "tool_name"
                    )
                ),
            ),
            metadata=security_metadata(
                user=session_id,
                agent="email-agent",
                workflow="chat",
            ),
            session_id=session_id,
            on_guard_error="deny",
        )

        # A new Agent per request so conversation history does not leak
        # across sessions. Do not pass `session_manager` — that would mint
        # an id. Do not pass `trace_attributes` as a Sequence id.
        agent = Agent(
            model=model,
            system_prompt=(
                "You always use the send_email tool to fulfill a request. "
                "You never skip the tool to answer in text alone. "
                "Call send_email exactly once. Use lookup_account with an "
                "account id (not an email) only when you must resolve a "
                "recipient. If a tool is blocked, do not call it again; "
                "explain that security blocked it."
            ),
            tools=[guarded_send_email, lookup_account],
            hooks=[hooks],
            callback_handler=None,
        )

        result = await agent.invoke_async(
            body.message,
            invocation_state=invocation_state,
        )
        await guard_client.flush()

        reply = str(result)

    return {"reply": reply, "session_id": session_id}
