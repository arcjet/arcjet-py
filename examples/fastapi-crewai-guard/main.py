"""A guarded CrewAI crew behind a FastAPI entrypoint.

Every Arcjet decision this file produces lands on one Sequence, because they
all share one caller-owned correlation ID: `protect()` on the route, the
inbound `guard()` call, and `register_arcjet_hooks` before `crew.kickoff`.
The id comes from the request, not from `crew.id` or `task.id`.
"""

import logging
import os
import threading
from contextlib import asynccontextmanager
from typing import Any

from crewai import LLM, Agent, Crew, Task
from crewai.tools import tool
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from arcjet import (
    Mode,
    arcjet_sync,
    detect_bot,
    shield,
    token_bucket,
)
from arcjet.guard import (
    DetectPromptInjection,
    LocalDetectSensitiveInfo,
    arcjet_sequence,
    launch_arcjet_sync,
    security_metadata,
    server_input,
)
from arcjet.guard.crewai import register_arcjet_hooks, sanitize_tool_name

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

# Request-path client. FastAPI is usually async; the CrewAI hook path is
# sync-only, so this route is sync and uses `arcjet_sync` for `protect()`.
aj = arcjet_sync(
    key=ARCJET_KEY,
    rules=[
        shield(mode=Mode.LIVE),
        detect_bot(
            mode=Mode.LIVE,
            # An empty allow list blocks all bots. CURL stays so the README
            # curl can reach the crew.
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

# Tool-path client. `register_arcjet_hooks` cannot await; passing the async
# `ArcjetGuard` would fail closed on every call without reaching policy.
guard_client = launch_arcjet_sync(key=ARCJET_KEY)

llm = LLM(model="gpt-4o-mini", api_key=OPENAI_API_KEY)

# Rule configuration is built once; each request binds its own input to it.
detect_injection = DetectPromptInjection()
detect_sensitive_info = LocalDetectSensitiveInfo(deny=["EMAIL", "PHONE_NUMBER"])

# CrewAI's hook dispatcher is process-global. Registering per request is
# what lets this file bind that request's message and correlation ID; the
# lock keeps two in-flight requests from stacking hooks on each other.
_hooks_lock = threading.Lock()


@tool("Send Email")
def send_email(to: str, body: str) -> str:
    """Send an email to a recipient.

    Args:
        to: The recipient address.
        body: The email body.
    """
    logger.info("sending email")
    return f"Email sent to {to}"


@tool("Lookup Account")
def lookup_account(account_id: str) -> str:
    """Look up an account by its internal id.

    Args:
        account_id: The account id to look up. This is not an email address.
    """
    logger.info("looking up account")
    return f"Account found for {account_id}"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    yield
    # Capture queues rather than blocking the request path, so anything still
    # in the queue is lost unless the process flushes on the way out.
    guard_client.flush()


app = FastAPI(lifespan=lifespan)


@app.get("/health")
def health() -> dict[str, str]:
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
def chat(request: Request, body: ChatRequest) -> Any:
    # Derive the correlation ID from something the caller already has — here a
    # session id off the request. A generated id would still join this run's
    # events together, but it would build a Sequence nobody goes looking for;
    # the point is that a human investigating "what did session X do" can find
    # it. The same value is passed to `protect()`, inbound `guard()`, and
    # `register_arcjet_hooks`. Crew, task, and agent ids are never read and
    # never minted into a Sequence.
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

    decision = aj.protect(
        request,
        requested=5,
        characteristics={"userId": session_id},
        correlation_id=session_id,
    )
    # `protect()` is fail-open. An evaluated DENY is `is_denied()`. An
    # unevaluated request (transport / invalid response) is `is_error()` —
    # the request-path equivalent of Guard's `has_failed_open()`. Either way
    # this route refuses to start the crew.
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
        # Screen inbound user text yourself. There is no `guard_inbound`
        # helper. Core `guard()` fails open — an unevaluated policy is an
        # ALLOW with `has_failed_open()` — so this route refuses to start
        # the crew on either DENY or a failed-open ALLOW.
        inbound = guard_client.guard(
            (
                detect_injection(body.message),
                detect_sensitive_info(body.message),
            ),
            label="chat.inbound",
            actor=session_id,
            inputs={"content": server_input.string(body.message)},
            correlation_id=session_id,
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

        def _hook_action(ctx: Any) -> str:
            name = sanitize_tool_name(getattr(ctx, "tool_name", "") or "")
            if name == "send_email":
                return "email.sent"
            return f"{name or 'tool'}.invoked"

        def _hook_metadata(args: dict[str, Any], _ctx: Any) -> dict[str, Any]:
            if "to" in args and "body" in args:
                return security_metadata(
                    user=session_id,
                    agent="email-agent",
                    workflow="chat",
                    resource="email",
                    destination="email",
                    reversibility="irreversible",
                )
            return security_metadata(
                user=session_id,
                agent="email-agent",
                workflow="chat",
            )

        agent = Agent(
            role="Email assistant",
            goal="Handle the user's request by sending one email",
            backstory=(
                "You always use the Send Email tool to fulfill a request. "
                "You never skip the tool to answer in text alone. "
                "Use Lookup Account with an account id (not an email) only "
                "when you must resolve a recipient."
            ),
            tools=[send_email, lookup_account],
            llm=llm,
            verbose=False,
        )
        task = Task(
            description=(
                "The user said:\n{message}\n\n"
                "Call the Send Email tool exactly once to handle the request. "
                "If a tool is blocked, do not call it again; explain that "
                "security blocked it."
            ),
            expected_output=(
                "A short confirmation of the email that was sent, or an "
                "explanation that security blocked the send."
            ),
            agent=agent,
            # human_input=True would pause for a human. Task.guardrail is a
            # post-output check. Neither is the Arcjet checkpoint — deny
            # happens in PRE_TOOL_CALL via register_arcjet_hooks below.
        )
        crew = Crew(agents=[agent], tasks=[task], verbose=False)

        # CrewAI hooks are process-global; only register/unregister around
        # kickoff so the lock does not cover agent construction.
        with _hooks_lock:
            # Register immediately before kickoff. Fail closed: if policy
            # cannot be evaluated at all, the tool does not run. This is the
            # one place Arcjet diverges from its platform-wide fail-open
            # convention. Pass "allow" to opt out — but note an evaluated
            # DENY still blocks either way.
            #
            # The agent always sees `Tool execution blocked by hook. Tool:
            # {name}`. HookAborted.reason is telemetry only. POST_TOOL_CALL
            # is not registered — it fires on blocked calls too.
            #
            # `tools=["Send Email", ...]` is the typo check: CrewAI sanitizes
            # that filter the same way it sanitizes hook tool names. The
            # `action=` resolver uses `sanitize_tool_name` so `email.sent`
            # still matches `Send Email` at execution time.
            #
            # Registrar `rules=` is a callable of the tool arguments, so
            # `send_email` body and `lookup_account` id are scanned at the
            # hook. A `ToolPolicy` would pin static `rules=` and could not
            # do that. The recipient address is the point of `send_email`, so
            # EMAIL on `to` is not scanned — that would deny every real send.
            handle = register_arcjet_hooks(
                guard=guard_client,
                correlation_id=session_id,
                on_guard_error="deny",
                tools=["Send Email", "Lookup Account"],
                action=_hook_action,
                actor=session_id,
                inputs=lambda args, _ctx: {
                    key: server_input.string(str(value)) for key, value in args.items()
                },
                rules=lambda args, _ctx: (
                    detect_injection(
                        str(args.get("body") or args.get("account_id") or "")
                    ),
                    detect_sensitive_info(
                        str(args.get("body") or args.get("account_id") or "")
                    ),
                ),
                metadata=_hook_metadata,
            )
            try:
                result = crew.kickoff(inputs={"message": body.message})
            finally:
                handle.unregister()
                guard_client.flush()

        reply = str(result)

    return {"reply": reply, "session_id": session_id}
