# Arcjet Python SDK Example FastAPI + OpenAI Agents Guard Application

A FastAPI server with an OpenAI Agents agent that uses Arcjet to protect the
HTTP request, screen inbound user text, and authorize one authored
`FunctionTool`.

The OpenAI Agents adapter shipped on main in
[arcjet-py#226](https://github.com/arcjet/arcjet-py/pull/226). This example
uses the local checkout via `[tool.uv.sources]`. The extra pulls
`openai-agents>=0.19.0,<1`. See
[`/guards/openai-agents-py/`](https://docs.arcjet.com/guards/openai-agents-py/)
— not the JS page
[`/guards/openai-agents/`](https://docs.arcjet.com/guards/openai-agents/).
The runner path is async (`launch_arcjet`, not `launch_arcjet_sync`).

An offline harness that drives the same adapter with a stub model and no
API keys still lives at
[`examples/openai-agents-guard-verify`](../openai-agents-guard-verify).

## Setup

Assumes running inside the devcontainer:

Copy `example.env` to `.env.local` and set your API keys:

```sh
cp example.env .env.local
# Edit .env.local and set your ARCJET_KEY and OPENAI_API_KEY
```

Then run the FastAPI application from this directory:

```sh
cd examples/fastapi-openai-agents-guard
uv run --env-file .env.local fastapi dev main.py
```

Verify the adapter contracts without starting a real model. Run this from
`examples/fastapi-openai-agents-guard` so `import main` resolves here:

```sh
cd examples/fastapi-openai-agents-guard
uv run python verify.py
```

The live PII scenario is opt-in. It hits the real Guard API only when both
`ARCJET_VERIFY_LIVE=1` and a real `ARCJET_KEY` are set:

```sh
ARCJET_VERIFY_LIVE=1 ARCJET_KEY=ajkey_... uv run python verify.py
```

## `POST /chat`

Sends a message to an OpenAI Agents agent that calls one authored tool
(`send_email`). The route is protected by Arcjet request rules (`protect()`
is fail-open — check deny / `is_error()`, the request-path equivalent of
`has_failed_open()`). Inbound user text is screened with the core `guard()`
call before `Runner.run` (fail-open — check DENY / `has_failed_open()`).
There is no `guard_inbound` helper. SDK `input_guardrails` on the `Agent`
are not Arcjet. The authored tool is authorized by `guard_tool`.

Requires `message` and `session_id` in the JSON body. `session_id` must be a
printable ASCII id the **app already minted** (at most 256 bytes) — it is the
caller-owned correlation ID on `protect()`, inbound `guard()`, `guard_tool`,
and `Runner.run(..., context={"session_id": ...})`. `openai_agents_context`
reads `correlation_id` then `session_id` then `conversation_id` then
`group_id`. This example writes only `session_id` so that order is visible.
It never mints one, never reads `trace_id`, and never constructs
`OpenAIConversationsSession()` just to ask it for an id.

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

If request-path policy could not be evaluated at all, `protect()` fails open
with an ERROR conclusion (`is_error()`) and the response is `503` with
`{ "error": "policy unavailable" }`.

If inbound `guard()` denies the user text — try a prompt-injection payload or
an email address in `message` — the agent does not start and the response is
`403`:

```json
{ "error": "denied by policy" }
```

If inbound policy cannot be evaluated at all, `has_failed_open()` is `True` and
the response is `503` with `{ "error": "policy unavailable" }`. Core `guard()`
fails open; the route refuses to start `Runner.run` anyway.

A tool-path deny does not become an HTTP 403. `guard_tool` prepends a
`ToolInputGuardrail` that `reject_content`s a JSON `ArcjetDenialResult` so
the handler does not run; the model sees the denial and the run finishes.
Do not `raise_exception()` (that halts the run). Do not raise an Arcjet
error from `on_invoke_tool` (the SDK `default_tool_error_function` would
swallow it into a generic string).

The recipient address is the point of `send_email`, so EMAIL on `to` is not a
tool-path rule — that would deny every real send. EMAIL in the email *body*
still denies, as does EMAIL in the inbound `message`.

`needs_approval` is HITL, not the deny path. This example never sets it.
Hosted tools, MCP, Computer / Shell / ApplyPatch, handoffs, and
`Agent.as_tool()` are not on the authored `FunctionTool` path.

## What to look for

In the Arcjet Console, search for the correlation ID (`sess-verify-001` in the
curl example above). You will see a single Sequence containing:

- The request-path `protect()` decision
- The inbound `guard()` decision on the user text
- The authored-tool `guard_tool` decision for `email.sent` (and its capture)

`guard_tool` wraps the `@function_tool` `send_email` and hands the copy to
`Agent(tools=[...])`. The original is left unwrapped. A second `guard_tool`
on the same copy is a brand-skip so Guard is not called twice.

The runner path is asynchronous and needs `launch_arcjet`. Do not pass the
sync `ArcjetGuardSync` client unless you have no async client.
