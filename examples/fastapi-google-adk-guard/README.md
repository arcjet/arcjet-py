# Arcjet Python SDK Example FastAPI + Google ADK Guard Application

A FastAPI server with a Google ADK `LlmAgent` that uses Arcjet to protect the
HTTP request, screen inbound user text, and authorize one authored tool via
`LlmAgent.before_tool_callback`.

This example depends on the published PyPI extra `arcjet[google-adk]`
(`pip install "arcjet[google-adk]"`). The extra pulls
`google-adk>=2.0.0,<3`. See
[`/guards/google-adk-py/`](https://docs.arcjet.com/guards/google-adk-py/)
— not the JS page
[`/guards/google-adk/`](https://docs.arcjet.com/guards/google-adk/).
This is not JS `@arcjet/guard/google-adk/v2` (plugin only, no `guardTool`).
The runner path is async (`launch_arcjet`, not `launch_arcjet_sync`).

## Setup

Assumes running inside the devcontainer:

Copy `example.env` to `.env.local` and set your API keys:

```sh
cp example.env .env.local
# Edit .env.local and set your ARCJET_KEY and GEMINI_API_KEY
```

Then run the FastAPI application from this directory:

```sh
cd examples/fastapi-google-adk-guard
uv run --env-file .env.local fastapi dev main.py
```

Verify the adapter contracts without starting Gemini. Run this from
`examples/fastapi-google-adk-guard` so `import main` resolves here:

```sh
cd examples/fastapi-google-adk-guard
uv run python verify.py
```

`verify.py` exercises adapter contracts with an in-memory Guard client. It
does not call Gemini or the live Decide API. For a runnable shop that
drives a real ADK `InMemoryRunner` (no Gemini key), see
`examples/fastapi-google-adk-shop`.

## `POST /chat`

Sends a message to a Google ADK agent that calls one authored tool
(`send_email`). The route is protected by Arcjet request rules (`protect()`
is fail-open — check deny / `is_error()`, the request-path equivalent of
`has_failed_open()`). Inbound user text is screened with the core `guard()`
call before `runner.run_async` (fail-open — check DENY / `has_failed_open()`).
There is no `guard_inbound` helper. The authored tool is authorized by
`guard_tool` as `LlmAgent.before_tool_callback`. Do not also attach
`guard_plugin` to the same tools.

Requires `message` and `session_id` in the JSON body. `session_id` must be a
printable ASCII id the **app already minted** (at most 256 bytes) — it is the
caller-owned correlation ID on `protect()`, inbound `guard()`, `guard_tool`,
and `runner.run_async(..., session_id=...)`. `google_adk_context` reads
`correlationId` then `sessionId` then `conversationId`. This example writes
only `sessionId` so that order is visible. It never mints one, never reads
`trace_id`, never reads an ADK-generated `invocation_id`, and never reads
`toolContext.sessionId` or `session.id`.

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
fails open; the route refuses to start `run_async` anyway.

A tool-path deny does not become an HTTP 403. `guard_tool` returns a skip
dict with `arcjetDenied` so the handler does not run; the model sees the
denial and the run finishes. Do not throw. Do not return `{}` (falsy in
ADK's callback chain, so the tool would run). Do not call
`request_confirmation`.

The recipient address is the point of `send_email`, so EMAIL on `to` is not a
tool-path rule — that would deny every real send. EMAIL in the email *body*
still denies, as does EMAIL in the inbound `message`.

`request_confirmation` / `require_confirmation` are HITL, not the deny path.
This example never calls them. `SecurityPlugin` is not the Arcjet gate.

## What to look for

In the Arcjet Console, search for the correlation ID (`sess-verify-001` in the
curl example above). You will see a single Sequence containing:

- The request-path `protect()` decision
- The inbound `guard()` decision on the user text
- The authored-tool `guard_tool` decision for `email.sent` (and its capture)

`guard_tool` is attached as `LlmAgent.before_tool_callback`. It is not a
`FunctionTool` wrap. `guard_plugin` is the Runner-wide alternative — put it
first on `plugins=` and do not also attach `guard_tool` to the same tools.

The runner path is asynchronous and needs `launch_arcjet`. Do not pass the
sync `ArcjetGuardSync` client unless you have no async client.
