"""A guarded Claude Managed Agents session behind a FastAPI entrypoint.

This is **not** the Claude Agent SDK. Anthropic runs the tool loop
(beta ``managed-agents-2026-04-01``). There is no PreToolUse, no
``guard_tool``, and no ``guard_inbound``.

Every Arcjet decision this file produces lands on one Sequence, because
they all share one caller-owned UUID: ``protect()`` on the route,
``guard_events`` on inbound ``user.message``, and ``guard_custom_tool``
on ``agent.custom_tool_use``. The id comes from the request, is read by
``claude_managed_agents_context``, and is never minted here. Anthropic's
``ses_...`` / ``sevt_...`` ids are theirs — never treated as ours.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from collections.abc import Mapping
from contextlib import asynccontextmanager
from typing import Any

from anthropic import APIError, AsyncAnthropic
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
    ArcjetDeniedError,
    ArcjetUnavailableError,
    DetectPromptInjection,
    LocalDetectSensitiveInfo,
    arcjet_sequence,
    launch_arcjet,
    security_metadata,
    server_input,
)
from arcjet.guard.claude_managed_agents import (
    claude_managed_agents_context,
    guard_custom_tool,
    guard_events,
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

ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5")
MAX_TOOL_ROUNDS = int(os.getenv("ANTHROPIC_MAX_TOOL_ROUNDS", "8"))

# Request-path client. FastAPI and the Managed Agents session are async,
# so this route is async and uses `arcjet` for `protect()`.
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

# Inbound- and tool-path client. The session is async, so this is
# `launch_arcjet`, not `launch_arcjet_sync`.
guard_client = launch_arcjet(key=ARCJET_KEY)
anthropic_client = AsyncAnthropic(api_key=ANTHROPIC_API_KEY)

# Rule configuration is built once; each request binds its own input to it.
detect_injection = DetectPromptInjection()
detect_sensitive_info = LocalDetectSensitiveInfo(deny=["EMAIL", "PHONE_NUMBER"])

# Cached Anthropic resources. Creating an agent / environment on every
# request would leave junk in the org. Override with ANTHROPIC_AGENT_ID /
# ANTHROPIC_ENVIRONMENT_ID to reuse ones you already have.
_agent_id: str | None = os.getenv("ANTHROPIC_AGENT_ID") or None
_environment_id: str | None = os.getenv("ANTHROPIC_ENVIRONMENT_ID") or None
_agent_lock = asyncio.Lock()


def _tool_input(event: Any) -> Mapping[str, Any]:
    raw = (
        event.get("input")
        if isinstance(event, Mapping)
        else getattr(event, "input", None)
    )
    return raw if isinstance(raw, Mapping) else {}


def _event_field(event: Any, name: str) -> Any:
    if isinstance(event, Mapping):
        return event.get(name)
    return getattr(event, name, None)


def _stop_reason_type(event: Any) -> str | None:
    """``session.status_idle.stop_reason.type``, if the payload has one."""
    stop = _event_field(event, "stop_reason")
    if stop is None:
        return None
    if isinstance(stop, str):
        return stop
    value = _event_field(stop, "type")
    if value is None:
        return None
    return value if isinstance(value, str) else str(value)


async def send_email(event: Any) -> str:
    """Hosted custom-tool body. Runs only after Guard allows the call."""
    args = _tool_input(event)
    to = str(args.get("to", ""))
    logger.info("sending email")
    return f"Email sent to {to}"


async def _ensure_agent() -> tuple[str, str]:
    """Return ``(agent_id, environment_id)``, creating them once if needed.

    The agent lists only the custom ``send_email`` tool. It does **not**
    enable ``agent_toolset_20260401``. Default ``permission_policy:
    always_allow`` cannot gate Anthropic-cloud bash / read / write, and
    ``web_search`` / ``web_fetch`` always run on Anthropic. HITL
    ``always_ask`` / ``user.tool_confirmation`` is not policy — this
    example does not set them.
    """
    global _agent_id, _environment_id
    async with _agent_lock:
        if _environment_id is None:
            environment = await anthropic_client.beta.environments.create(
                name="arcjet-fastapi-managed-agents-guard",
                config={"type": "cloud", "networking": {"type": "unrestricted"}},
            )
            _environment_id = environment.id
        if _agent_id is None:
            agent = await anthropic_client.beta.agents.create(
                name="arcjet-email-agent",
                model=ANTHROPIC_MODEL,
                system=(
                    "You always use the send_email tool to fulfill a request. "
                    "You never skip the tool to answer in text alone. "
                    "Call send_email exactly once. If the tool is blocked, do "
                    "not call it again; explain that security blocked it."
                ),
                tools=[
                    {
                        "type": "custom",
                        "name": "send_email",
                        "description": "Send an email to a recipient",
                        "input_schema": {
                            "type": "object",
                            "properties": {
                                "to": {
                                    "type": "string",
                                    "description": "The recipient address",
                                },
                                "body": {
                                    "type": "string",
                                    "description": "The email body",
                                },
                            },
                            "required": ["to", "body"],
                        },
                    }
                ],
            )
            _agent_id = agent.id
        return _agent_id, _environment_id


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


def _caller_owned_session_id(value: str) -> str | None:
    """Return the canonical form if *value* is already a UUID. Never mint.

    Requiring a UUID also rejects Anthropic-minted ``ses_...`` / ``sevt_...``
    ids so they cannot be treated as a Sequence we created.
    """
    try:
        return str(uuid.UUID(value))
    except ValueError:
        return None


def _message_text(content: Any) -> str:
    parts: list[str] = []
    if content is None:
        return ""
    blocks = content if isinstance(content, (list, tuple)) else [content]
    for block in blocks:
        if isinstance(block, Mapping):
            if block.get("type") == "text" and isinstance(block.get("text"), str):
                parts.append(block["text"])
        elif getattr(block, "type", None) == "text":
            text = getattr(block, "text", None)
            if isinstance(text, str):
                parts.append(text)
    return "".join(parts)


@app.post("/chat")
async def chat(request: Request, body: ChatRequest) -> Any:
    # Derive the correlation ID from something the caller already has — here a
    # session UUID off the request. A generated id would still join this run's
    # events together, but it would build a Sequence nobody goes looking for;
    # the point is that a human investigating "what did session X do" can find
    # it. `claude_managed_agents_context` only reads that id. It never mints,
    # never reads `trace_id`, and never treats Anthropic session / event ids
    # as if we created them.
    #
    # EXAMPLE ONLY: this trusts `session_id` from the request body, so a caller
    # could write to another session's Sequence and to its actor and metadata.
    # In a real service take it from the authenticated session — a signed
    # cookie, a verified token claim — never from a field the caller controls.
    session_id = _caller_owned_session_id(body.session_id)
    if session_id is None:
        return JSONResponse(
            {"error": "session_id must be a caller-owned UUID"},
            status_code=400,
        )

    derived = claude_managed_agents_context(session_id=session_id)
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
    # this route refuses to start a Managed Agents session.
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
        # Screen inbound user text yourself as well. There is no
        # `guard_inbound` helper. Core `guard()` fails open — an
        # unevaluated policy is an ALLOW with `has_failed_open()` — so this
        # route refuses to create a session on either DENY or a failed-open
        # ALLOW. `guard_events` is the adapter path below: it gates
        # `user.message` / `initial_events` **before**
        # `sessions.events.send`.
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

        agent_id, environment_id = await _ensure_agent()

        # Anthropic mints the session id (`ses_...`). Pass it to the events
        # API. Never pass it to `claude_managed_agents_context` /
        # `correlation_id=` / `session_id=` as if we created it.
        anthropic_session = await anthropic_client.beta.sessions.create(
            agent=agent_id,
            environment_id=environment_id,
        )
        anthropic_session_id = anthropic_session.id

        raw_send = anthropic_client.beta.sessions.events.send

        # Inbound: wrap `sessions.events.send` so `user.message` is gated
        # **before** the original send runs. Wrapping `sessions.create`
        # gates `initial_events` the same way. Non-`user.message` events
        # (`user.custom_tool_result`, `user.interrupt`,
        # `user.tool_confirmation`, …) pass through. There is no
        # `guard_inbound`.
        send = guard_events(
            guard=guard_client,
            send=raw_send,
            action="chat.inbound",
            actor=session_id,
            inputs=lambda args: {
                "content": server_input.string(str(args.get("prompt", "")))
            },
            rules=lambda args: (
                detect_injection(str(args.get("prompt", ""))),
                detect_sensitive_info(str(args.get("prompt", ""))),
            ),
            metadata=security_metadata(
                user=session_id,
                agent="email-agent",
                workflow="chat",
            ),
            session_id=session_id,
            on_guard_error="deny",
        )

        # On `agent.custom_tool_use` Guard runs **before** `send_email`.
        # On DENY the original does not run and the helper sends a real
        # `user.custom_tool_result` (`is_error` is a schema field — use
        # it; do not invent one). On ALLOW, `send_email` runs and this
        # route sends the success result. Fail closed: if policy cannot
        # be evaluated at all, the tool does not run. This is the one
        # place Arcjet diverges from its platform-wide fail-open
        # convention. Pass "allow" to opt out — but note an evaluated
        # DENY still blocks either way.
        #
        # Default `always_allow` cannot gate Anthropic-cloud bash / read
        # / write or `web_search` / `web_fetch`. Those are not on this
        # agent. `always_ask` / `user.tool_confirmation` is HITL, not
        # the deny path.
        handle_send_email = guard_custom_tool(
            guard=guard_client,
            run=send_email,
            action="email.sent",
            actor=session_id,
            inputs=lambda args: {
                "recipient": server_input.string(str(args.get("to", ""))),
                "body": server_input.string(str(args.get("body", ""))),
            },
            rules=lambda args: (
                detect_injection(str(args.get("body", ""))),
                # Sensitive info DENIES; it does not redact. If this
                # trips, the tool does not run and nothing is rewritten
                # on the way through.
                detect_sensitive_info(str(args.get("body", ""))),
                detect_sensitive_info(str(args.get("to", ""))),
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

        reply_parts: list[str] = []
        # Anthropic delivers only events emitted after the stream is
        # open. Open first, send `user.message` (and later tool results)
        # while it is open, then iterate. Handle `agent.custom_tool_use`
        # on the same connection so a DENY `user.custom_tool_result` is
        # not sent into a gap.
        tool_rounds = 0
        finished = False
        terminated = False
        interrupted = False
        async with anthropic_client.beta.sessions.events.stream(
            session_id=anthropic_session_id,
        ) as stream:
            try:
                await send(
                    anthropic_session_id,
                    events=[
                        {
                            "type": "user.message",
                            "content": [{"type": "text", "text": body.message}],
                        }
                    ],
                )
            except ArcjetDeniedError:
                logger.warning("arcjet denied inbound user.message")
                return JSONResponse({"error": "denied by policy"}, status_code=403)
            except ArcjetUnavailableError:
                logger.error(
                    "arcjet inbound policy could not be evaluated; failing closed"
                )
                return JSONResponse({"error": "policy unavailable"}, status_code=503)

            async for event in stream:
                event_type = _event_field(event, "type")
                if event_type == "agent.message":
                    reply_parts.append(_message_text(_event_field(event, "content")))
                elif event_type == "agent.custom_tool_use":
                    tool_rounds += 1
                    if tool_rounds > MAX_TOOL_ROUNDS:
                        logger.error(
                            "managed agents session hit tool-round cap; interrupting"
                        )
                        await raw_send(
                            anthropic_session_id,
                            events=[{"type": "user.interrupt"}],
                        )
                        interrupted = True
                        break
                    # Pass the real events API as `send`. On DENY the
                    # helper uses it to post `user.custom_tool_result`
                    # and returns None — do not run the tool, do not
                    # invent fields. `event.id` is Anthropic's
                    # `sevt_...`: use it only as
                    # `custom_tool_use_id`, never as correlation.
                    result = await handle_send_email(
                        event,
                        send=raw_send,
                        session_id=anthropic_session_id,
                    )
                    if result is not None:
                        await raw_send(
                            anthropic_session_id,
                            events=[
                                {
                                    "type": "user.custom_tool_result",
                                    "custom_tool_use_id": _event_field(event, "id"),
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": str(result),
                                        }
                                    ],
                                    "is_error": False,
                                }
                            ],
                        )
                elif event_type == "session.status_idle":
                    # Waiting for a custom-tool result is also idle.
                    # Only `end_turn` means the turn is done.
                    if _stop_reason_type(event) == "end_turn":
                        finished = True
                        break
                elif event_type == "session.error":
                    logger.error(
                        "managed agents session error: %s",
                        _event_field(event, "error"),
                    )
                    terminated = True
                    break
                elif event_type == "session.status_terminated":
                    terminated = True
                    break

        if not finished and not terminated and not interrupted:
            logger.error("managed agents session ended without end_turn; interrupting")
            try:
                await raw_send(
                    anthropic_session_id,
                    events=[{"type": "user.interrupt"}],
                )
            except APIError:
                logger.warning(
                    "failed to interrupt managed agents session %s",
                    anthropic_session_id,
                    exc_info=True,
                )

        await guard_client.flush()

    return {"reply": "".join(reply_parts), "session_id": session_id}
