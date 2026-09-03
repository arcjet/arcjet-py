"""A guarded Google ADK agent behind a FastAPI entrypoint.

Every Arcjet decision this file produces lands on one Sequence, because they
all share one caller-owned id: `protect()` on the route, the inbound
`guard()` call, `guard_tool` on the authored `LlmAgent.before_tool_callback`,
and `guard_plugin` on the Runner. The id comes from the request and is put
on session state as `sessionId` only, so the helper's preference order
(`correlationId` then `sessionId` then `conversationId`) is visible. It is
never minted here — `google_adk_context` only reads it.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from google.adk.agents import LlmAgent
from google.adk.runners import InMemoryRunner
from google.adk.tools.function_tool import FunctionTool
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
from arcjet.guard.google_adk import (
    google_adk_context,
    guard_plugin,
    guard_tool,
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

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
if not GOOGLE_API_KEY:
    raise RuntimeError(
        "GOOGLE_API_KEY (or GEMINI_API_KEY) is required. Get one at"
        " https://aistudio.google.com/apikey"
    )
os.environ.setdefault("GOOGLE_API_KEY", GOOGLE_API_KEY)

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

# Stable brand the plugin / callback skip so Guard is not double-called.
# Same attribute `guard_tool` / `guard_plugin` read (`_arcjet_guarded`).
_GUARD_BRAND = "_arcjet_guarded"

APP_NAME = "email_agent"


def send_email(to: str, body: str) -> str:
    """Send an email to a recipient.

    Args:
        to: The recipient address.
        body: The email body.
    """
    logger.info("sending email")
    return f"Email sent to {to}"


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


def _final_text(event: Any) -> str:
    content = getattr(event, "content", None)
    parts = getattr(content, "parts", None) if content is not None else None
    if not parts:
        return ""
    return "".join(
        part.text or "" for part in parts if getattr(part, "text", None)
    )


@app.post("/chat")
async def chat(request: Request, body: ChatRequest) -> Any:
    # Derive the correlation ID from something the caller already has — here a
    # session id off the request. A generated id would still join this run's
    # events together, but it would build a Sequence nobody goes looking for;
    # the point is that a human investigating "what did session X do" can find
    # it. The same value is passed to `protect()`, inbound `guard()`,
    # `guard_tool` / `guard_plugin`, session `state={"sessionId": ...}`, and
    # `run_async(..., session_id=)`. `google_adk_context` reads
    # `correlationId` then `sessionId` then `conversationId` (JS camelCase
    # first, snake_case aliases second). Only `sessionId` is set here so that
    # order is not hidden by writing the same value into every slot. It never
    # mints, never reads `trace_id`, never reads an ADK-generated
    # `invocation_id`, and never reads `toolContext.session_id` / `session.id`.
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
    derived = google_adk_context({"context": app_context})
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
        # helper and no inbound plugin hook that denies with a dict
        # (`on_user_message_callback` replaces the user message). Core
        # `guard()` fails open — an unevaluated policy is an ALLOW with
        # `has_failed_open()` — so this route refuses to start
        # `run_async` on either DENY or a failed-open ALLOW.
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

        # Authored tool. Brand it so the Runner plugin skips it. The
        # LlmAgent `guard_tool` callback is then the only gate for this
        # tool — otherwise PluginManager first-win plus the agent
        # callback would double-call Guard on ALLOW.
        send_email_tool = FunctionTool(send_email)
        object.__setattr__(send_email_tool, _GUARD_BRAND, True)
        lookup_account_tool = FunctionTool(lookup_account)

        # `LlmAgent.before_tool_callback(tool, args, tool_context)`.
        # On DENY the original tool function does not run. The deny is a
        # skip-with-result dict (`arcjetDenied`). `None` allows. Never
        # `{}` — ADK treats an empty mapping as skip too. The callback
        # does not throw. Fail closed: if policy cannot be evaluated at
        # all, the tool does not run. This is the one place Arcjet
        # diverges from its platform-wide fail-open convention. Pass
        # "allow" to opt out — but note an evaluated DENY still blocks
        # either way.
        #
        # Tool-path rules judge the call arguments, not the inbound prompt.
        # `require_confirmation` / `request_confirmation` / ADK
        # `SecurityPlugin` are HITL, not a policy gate — this wrap never
        # sets or calls them.
        authored_before_tool = guard_tool(
            guard=guard_client,
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

        async def before_tool_callback(
            tool: Any, args: Any, tool_context: Any
        ) -> dict[str, Any] | None:
            # `guard_tool` also brand-skips, so the authored tool is
            # evaluated through a name-only view. Unwrapped tools return
            # None here — the Runner plugin already gated them.
            if getattr(tool, _GUARD_BRAND, False):
                view = SimpleNamespace(
                    name=getattr(tool, "name", None) or "send_email"
                )
                return await authored_before_tool(view, args, tool_context)
            return None

        # Runner `BasePlugin.before_tool_callback` — put it first.
        # PluginManager is first-win: the first plugin that returns a
        # non-None value short-circuits remaining plugins and the agent
        # callback. Brand-skip means this plugin does not evaluate
        # `send_email`. `lookup_account` is left unbranded so this is
        # its only gate.
        plugin = guard_plugin(
            guard=guard_client,
            action=lambda call: (
                "email.sent"
                if call.get("tool_name") == "send_email"
                else f"{call.get('tool_name') or 'tool'}.invoked"
            ),
            actor=session_id,
            inputs=lambda call: {
                key: server_input.string(str(value))
                for key, value in call.items()
                if key not in ("tool_name", "input")
            },
            rules=lambda call: (
                detect_injection(
                    str(
                        call.get("body")
                        or call.get("account_id")
                        or call.get("command")
                        or ""
                    )
                ),
                detect_sensitive_info(
                    " ".join(
                        str(value)
                        for key, value in call.items()
                        if key not in ("tool_name", "input")
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

        # A new agent + runner per request so conversation history does
        # not leak across sessions. Pass the caller-owned id into
        # `create_session` / `run_async` so ADK does not mint one. Do
        # not read `session.id`, `toolContext.session_id`, `trace_id`,
        # or `invocation_id` back as a Sequence id.
        agent = LlmAgent(
            name="email_agent",
            model=GEMINI_MODEL,
            instruction=(
                "You always use the send_email tool to fulfill a request. "
                "You never skip the tool to answer in text alone. "
                "Call send_email exactly once. Use lookup_account with an "
                "account id (not an email) only when you must resolve a "
                "recipient. If a tool is blocked, do not call it again; "
                "explain that security blocked it."
            ),
            tools=[send_email_tool, lookup_account_tool],
            before_tool_callback=before_tool_callback,
        )

        runner = InMemoryRunner(
            agent=agent,
            app_name=APP_NAME,
            plugins=[plugin],
        )
        await runner.session_service.create_session(
            app_name=APP_NAME,
            user_id=session_id,
            session_id=session_id,
            state=app_context,
        )

        reply = ""
        async for event in runner.run_async(
            user_id=session_id,
            session_id=session_id,
            new_message=types.Content(
                role="user",
                parts=[types.Part(text=body.message)],
            ),
        ):
            text = _final_text(event)
            is_final = getattr(event, "is_final_response", None)
            if callable(is_final) and is_final() and text:
                reply = text
            elif text:
                reply = text
        await guard_client.flush()

    return {"reply": reply, "session_id": session_id}
