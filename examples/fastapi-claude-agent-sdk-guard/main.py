"""A guarded Claude Agent SDK agent behind a FastAPI entrypoint.

Every Arcjet decision this file produces lands on one Sequence, because they
all share one caller-owned UUID: `protect()` on the route, `guard_hooks`
inbound / PreToolUse, and `guard_tool` on the authored `@tool`. The id comes
from the request, is passed through `claude_agent_context` /
`policy.session_id`, and is never minted here.
"""

import logging
import os
import uuid
from contextlib import asynccontextmanager
from typing import Any

from claude_agent_sdk import (
    ClaudeAgentOptions,
    ResultMessage,
    create_sdk_mcp_server,
    query,
    tool,
)
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
from arcjet.guard.claude_agent_sdk import (
    claude_agent_context,
    guard_hooks,
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

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
if not ANTHROPIC_API_KEY:
    raise RuntimeError(
        "ANTHROPIC_API_KEY is required. Get one at https://console.anthropic.com"
    )

# Request-path client. FastAPI and `query()` are async, so this route is
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

MCP_SERVER = "support"


@tool("send_email", "Send an email to a recipient", {"to": str, "body": str})
async def send_email(args: dict[str, Any]) -> dict[str, Any]:
    to = str(args.get("to", ""))
    logger.info("sending email to %s", to)
    return {"content": [{"type": "text", "text": f"Email sent to {to}"}]}


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


def _caller_owned_session_id(value: str) -> str | None:
    """Return *value* if it is already a UUID. Never mint a replacement."""
    try:
        uuid.UUID(value)
    except ValueError:
        return None
    return value


@app.post("/chat")
async def chat(request: Request, body: ChatRequest) -> Any:
    # Derive the correlation ID from something the caller already has — here a
    # session UUID off the request. A generated id would still join this run's
    # events together, but it would build a Sequence nobody goes looking for;
    # the point is that a human investigating "what did session X do" can find
    # it. `claude_agent_context` only reads that id. It never mints, never
    # reads `trace_id`, and never constructs a session just for an id.
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

    derived = claude_agent_context(session_id=session_id)
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
    # this route refuses to start `query()`.
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
        # `query()` on either DENY or a failed-open ALLOW. `guard_hooks`
        # `inbound=` is the adapter UserPromptSubmit path below; this
        # `guard()` call is how the FastAPI examples combine inbound
        # screening with `protect()` so a denied prompt never reaches Claude.
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
        # run. The deny is a returned MCP tool result — do not throw (the
        # SDK swallows into `str(e)`). Do not set `structuredContent`
        # (`create_sdk_mcp_server` drops it). Fail closed: if policy cannot
        # be evaluated at all, the tool does not run. This is the one place
        # Arcjet diverges from its platform-wide fail-open convention.
        # Pass "allow" to opt out — but note an evaluated DENY still blocks
        # either way.
        #
        # The authored handler has no `extra.session_id`. Pass the same
        # caller-owned UUID you give `ClaudeAgentOptions.session_id`.
        guarded_send_email = guard_tool(
            guard=guard_client,
            tool=send_email,
            action="email.sent",
            actor=session_id,
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

        # `PreToolUse` fires for every tool, including the wrapped one.
        # List the wrapper in `exclude` as `{"server": ..., "name": ...}`
        # so it matches `mcp__{server}__{name}` exactly and is not
        # double-gated. A bare authored name is not an exclude match.
        #
        # `can_use_tool` / `permissionDecision: "ask"` are HITL, not
        # policy. This example does not set `can_use_tool` and never
        # returns `"ask"`. `permissionDecision: "deny"` is the only deny
        # that still runs under `allowed_tools` / `bypassPermissions`.
        hooks = guard_hooks(
            guard=guard_client,
            action=lambda hook: f"{hook.get('tool_name', 'tool')}.invoked",
            actor=session_id,
            inputs=lambda args: {
                key: server_input.string(str(value)) for key, value in args.items()
            },
            rules=lambda args: (
                detect_injection(body.message),
                detect_sensitive_info(
                    " ".join(str(value) for value in args.values()) or body.message
                ),
            ),
            metadata=security_metadata(
                user=session_id,
                agent="email-agent",
                workflow="chat",
            ),
            session_id=session_id,
            on_guard_error="deny",
            exclude=[{"server": MCP_SERVER, "name": "send_email"}],
            inbound={
                "action": "chat.inbound",
                "actor": session_id,
                "inputs": lambda args: {
                    "content": server_input.string(
                        str(args.get("prompt", body.message))
                    )
                },
                "rules": (
                    detect_injection(body.message),
                    detect_sensitive_info(body.message),
                ),
                "metadata": security_metadata(
                    user=session_id,
                    agent="email-agent",
                    workflow="chat",
                ),
            },
        )

        server = create_sdk_mcp_server(
            name=MCP_SERVER,
            tools=[guarded_send_email],
        )

        options = ClaudeAgentOptions(
            system_prompt=(
                "You always use the send_email tool to fulfill a request. "
                "You never skip the tool to answer in text alone. "
                "Call send_email exactly once. If the tool is blocked, do "
                "not call it again; explain that security blocked it."
            ),
            mcp_servers={MCP_SERVER: server},
            # Built-ins stay available so `PreToolUse` can deny an unwrapped
            # tool. `dontAsk` is not a policy gate — it only avoids a HITL
            # pause in this server. Arcjet deny is `permissionDecision:
            # "deny"` from `guard_hooks`, or the `guard_tool` envelope.
            tools=["Read"],
            allowed_tools=[
                f"mcp__{MCP_SERVER}__send_email",
                "Read",
            ],
            permission_mode="dontAsk",
            hooks=hooks,
            session_id=session_id,
            max_turns=8,
            strict_mcp_config=True,
        )

        reply = ""
        async for message in query(prompt=body.message, options=options):
            if isinstance(message, ResultMessage) and message.result is not None:
                reply = message.result
        await guard_client.flush()

    return {"reply": reply, "session_id": session_id}
