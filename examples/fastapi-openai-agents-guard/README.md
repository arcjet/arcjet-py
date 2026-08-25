# Arcjet Python SDK Example FastAPI + OpenAI Agents Guard Application

A FastAPI server with an OpenAI Agents agent that uses Arcjet to protect the
HTTP request, screen inbound user text, and authorize one authored
`FunctionTool`.

The OpenAI Agents adapter is unpublished. This example pins
`arcjet[openai-agents]` to SHA `cafe6a6671ab7fdde1b78b59971c3fe8ca863a4d`
(arcjet-py#226). That is not a PyPI release. The extra
pulls `openai-agents>=0.19.0,<1`. See
[`/guards/openai-agents-py/`](https://docs.arcjet.com/guards/openai-agents-py/)
— not the JS page
[`/guards/openai-agents/`](https://docs.arcjet.com/guards/openai-agents/).
The runner path is async (`launch_arcjet`, not `launch_arcjet_sync`).

## Setup

Assumes running inside the devcontainer:

Copy `example.env` to `.env.local` and set your API keys:

```sh
cp example.env .env.local
# Edit .env.local and set your ARCJET_KEY and OPENAI_API_KEY
```

Then run the FastAPI application:

```sh
uv run --env-file .env.local fastapi dev main.py
```

## `POST /chat`

Sends a message to an OpenAI Agents agent that calls one authored tool
(`send_email`). The route is protected by Arcjet request rules; inbound user
text is screened with the core `guard()` call before `Runner.run`; the tool
is authorized by `guard_tool`. There is no `guard_inbound` helper.

Requires `message` and `session_id` in the JSON body — the `session_id` is the
caller-owned correlation ID on `protect()`, inbound `guard()`, and
`Runner.run(..., context={"session_id": ...})`. `openai_agents_context` reads
that context. It is never minted here, never taken from `trace_id`, and never
taken from a new `OpenAIConversationsSession()`.

```shell
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Send a short welcome email to the onboarding list.", "session_id": "sess-verify-001"}'
```

**Response:**

```json
{ "reply": "...", "session_id": "sess-verify-001" }
```

If request-path policy denies the HTTP call, the response is `403` (or `429`
for rate limiting):

```json
{ "error": "Denied", "reason": { } }
```

If inbound `guard()` denies the user text — try a prompt-injection payload in
`message` — the agent does not start and the response is `403`:

```json
{ "error": "denied by policy" }
```

If inbound policy cannot be evaluated at all, `has_failed_open()` is `True` and
the response is `503` with `{ "error": "policy unavailable" }`. Core `guard()`
fails open; the route refuses to start `Runner.run` anyway.

A tool-path deny does not become an HTTP 403. `guard_tool` prepends a
`ToolInputGuardrail` that `reject_content`s a JSON `ArcjetDenialResult`, so the
tool body does not run; the model sees the denial and the run finishes. That
is the skip-invoke path — do not `raise_exception()` (that halts the run) and
do not raise an Arcjet error from `on_invoke_tool` (the SDK
`default_tool_error_function` would swallow it).

`needs_approval` is HITL, not the deny path. This example does not wrap it and
does not mutate `RunConfig`.
`RunConfig.tool_execution.pre_approval_tool_input_guardrails=True` is an
application opt-in if you want the check before a HITL pause; Arcjet does not
set it.

## What to look for

In the Arcjet Console, search for the correlation ID (`sess-verify-001` in the
curl example above). You will see a single Sequence containing:

- The request-path `protect()` decision
- The inbound `guard()` decision on the user text
- The tool-path `ToolInputGuardrail` decision for `email.sent` (and its capture)

`guard_tool` wraps the `@function_tool` `send_email` and hands the copy to
`Agent(tools=[...])`. The original is left unwrapped. Hosted tools, MCP,
Computer / Shell / ApplyPatch, handoffs, and `Agent.as_tool()` are not on that
authored `FunctionTool` path.

The runner path is asynchronous and needs `launch_arcjet`. Do not pass the
sync `ArcjetGuardSync` client unless you have no async client.
