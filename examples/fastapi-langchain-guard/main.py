"""A guarded LangChain agent behind a FastAPI entrypoint.

Every Arcjet decision and capture this file produces lands on one Sequence,
because they all share one correlation ID: the request opens a sequence, the
agent and its guarded tool inherit it ambiently, and the background worker is
handed it explicitly because context does not cross that boundary.
"""

import logging
import os
from contextlib import asynccontextmanager
from typing import Any, Optional

from fastapi import BackgroundTasks, FastAPI
from fastapi.responses import JSONResponse
from langchain.agents import create_agent
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from pydantic import BaseModel
from worker import send_receipt

from arcjet.guard import (
    ArcjetDeniedError,
    ArcjetGuard,
    ArcjetUnavailableError,
    DetectPromptInjection,
    LocalDetectSensitiveInfo,
    arcjet_sequence,
    current_correlation_id,
    flush,
    launch_arcjet,
    register_arcjet,
    security_metadata,
    server_input,
)
from arcjet.guard.langchain import ArcjetCaptureHandler, ArcjetMiddleware, ToolPolicy

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

# The client the middleware evaluates through. Registering it also lets code
# with no client handle in scope call the free guard_action() and capture().
# The worker deliberately does not rely on that — see worker.py.
arcjet_client: Optional[ArcjetGuard] = None

llm = ChatOpenAI(model="gpt-4o-mini", api_key=OPENAI_API_KEY)

# Rule configuration is built once; each request binds its own input to it.
detect_injection = DetectPromptInjection()
detect_sensitive_info = LocalDetectSensitiveInfo(deny=["EMAIL", "PHONE_NUMBER"])


@tool
def get_weather(location: str) -> str:
    """Get the weather for a location.

    Args:
        location: The location to get weather for.
    """
    return f"Weather in {location}: sunny, 72F"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global arcjet_client
    arcjet_client = launch_arcjet(key=ARCJET_KEY)
    register_arcjet(arcjet_client)
    yield
    # Capture queues rather than blocking the request path, so anything still
    # in the queue is lost unless the process flushes on the way out.
    await flush()


app = FastAPI(lifespan=lifespan)


class ChatRequest(BaseModel):
    message: str
    session_id: str


@app.post("/chat")
async def chat(body: ChatRequest, background: BackgroundTasks) -> Any:
    # Derive the correlation ID from something the caller already has — here a
    # session id off the request. A generated id would still join this run's
    # events together, but it would build a Sequence nobody goes looking for;
    # the point is that a human investigating "what did session X do" can find
    # it. Everything below inherits this ambiently.
    with arcjet_sequence(correlation_id=body.session_id):
        policies = {
            "get_weather": ToolPolicy(
                # The checkpoint's name, resource.verb in the past tense. It is
                # also how the server selects remote policy, so it is worth
                # keeping stable.
                action="weather.fetched",
                rules=(
                    detect_injection(body.message),
                    # Sensitive info DENIES; it does not redact. If this
                    # trips, the tool does not run and nothing is rewritten on
                    # the way through — the value is not silently scrubbed and
                    # passed on.
                    #
                    # Bound to the inbound message, which is what a rule can be
                    # bound to today: `rules` takes already-bound inputs, so
                    # there is no way to bind one to a tool argument the agent
                    # has not produced yet. To scan an outbound value, call
                    # guard_action inside the tool body where you hold it.
                    detect_sensitive_info(body.message),
                ),
                actor=lambda _args: body.session_id,
                inputs=lambda args: {
                    "location": server_input.string(str(args.get("location", "")))
                },
                metadata=security_metadata(
                    user=body.session_id,
                    agent="weather-agent",
                    workflow="chat",
                    resource="weather-api",
                ),
            ),
        }

        if arcjet_client is None:
            raise RuntimeError("Arcjet client is unset; the lifespan never ran")
        middleware = ArcjetMiddleware(
            guard=arcjet_client,
            policies=policies,
            # Fail closed: if policy cannot be evaluated at all, the tool does
            # not run. This is the one place Arcjet diverges from its
            # platform-wide fail-open convention. Pass "allow" to opt out — but
            # note an evaluated DENY still blocks either way.
            on_guard_error="deny",
        )

        # A tool with no entry in `policies` passes through unguarded, so adding
        # this middleware cannot silently start blocking tools nobody configured.
        #
        # ArcjetMiddleware is for create_agent applications: it sees a tool
        # call's parsed, validated arguments immediately before execution. To
        # guard a bare BaseTool instead, wrap it:
        #     from arcjet.guard.langchain import guard_tool
        #     guarded = guard_tool(
        #         guard=arcjet_client, tool=get_weather, action="weather.fetched"
        #     )
        agent = create_agent(model=llm, tools=[get_weather], middleware=[middleware])

        try:
            result = await agent.ainvoke(
                {"messages": [{"role": "user", "content": body.message}]},
                # Observe-only. The handler records the chain and model
                # lifecycle onto this same Sequence; it cannot deny anything,
                # which is why enforcement lives in the middleware above.
                config={"callbacks": [ArcjetCaptureHandler()]},
            )
        except ArcjetDeniedError as exc:
            logger.warning("arcjet denied the tool call: %s", exc)
            return JSONResponse({"error": "denied by policy"}, status_code=403)
        except ArcjetUnavailableError:
            logger.error("arcjet policy could not be evaluated; failing closed")
            return JSONResponse({"error": "policy unavailable"}, status_code=503)

        reply = result["messages"][-1].content

        # The background boundary. Read the correlation ID out while it is still
        # in scope and put it in the payload, because the worker will not
        # inherit it: context does not cross a bare ThreadPoolExecutor, a
        # ProcessPoolExecutor, or a task broker. This is the whole point of the
        # file — without it the worker's decisions land on a Sequence of their
        # own and the trace splits in half.
        payload = {
            "correlation_id": current_correlation_id(),
            "session_id": body.session_id,
            "reply": reply,
        }

    # Handed off outside the sequence on purpose, so the worker stands on its
    # own exactly as it would behind a broker. FastAPI runs this after the
    # response and keeps a reference to it; a bare asyncio.create_task would
    # not, and the work could be collected mid-flight.
    #
    # In production Celery, RQ or Dramatiq takes over here, and the payload is
    # what crosses the wire.
    background.add_task(send_receipt, payload)

    return {"reply": reply, "session_id": body.session_id}
