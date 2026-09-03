# Arcjet Python SDK Example FastAPI + Google ADK Guard Application

A FastAPI server with a **Python Google ADK** (`google-adk` 2.x) agent that
uses Arcjet to protect the HTTP request, screen inbound user text, authorize
one authored tool via `LlmAgent.before_tool_callback`, and deny an unwrapped
tool via a Runner plugin.

This is **not** JS `@google/adk` / `@arcjet/guard/google-adk/v2`. See
[`/guards/google-adk-py/`](https://docs.arcjet.com/guards/google-adk-py/)
— not the JS page
[`/guards/google-adk/`](https://docs.arcjet.com/guards/google-adk/).

The Google ADK adapter is unpublished. This example pins
`arcjet[google-adk]` to SHA `679423c9f5f6db2ad3ca573088faabd862a8587b`
(branch `david/cursor/google-adk-guard-c36e`). That is not a PyPI release. The
extra pulls `google-adk>=2.0.0,<3`. No chromadb. The runner path is async
(`launch_arcjet`, not `launch_arcjet_sync`).

## Setup

Assumes running inside the devcontainer:

Copy `example.env` to `.env.local` and set your API keys:

```sh
cp example.env .env.local
# Edit .env.local and set your ARCJET_KEY and GOOGLE_API_KEY
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

The live PII scenario is opt-in. It hits the real Guard API only when both
`ARCJET_VERIFY_LIVE=1` and a real `ARCJET_KEY` are set:

```sh
ARCJET_VERIFY_LIVE=1 ARCJET_KEY=ajkey_... uv run python verify.py
```

## `POST /chat`

Sends a message to a Google ADK `LlmAgent` that calls one authored tool
(`send_email`) and can also call an unwrapped tool (`lookup_account`). The
route is protected by Arcjet request rules (`protect()` is fail-open — check
deny / `is_error()`, the request-path equivalent of `has_failed_open()`).
Inbound user text is screened with the core `guard()` call before
`runner.run_async` (fail-open — check DENY / `has_failed_open()`). There is no
`guard_inbound` helper and no inbound plugin hook that denies with a dict.

`guard_plugin` is attached as a **Runner plugin first**
(`BasePlugin.before_tool_callback` is first-win). The authored tool also uses
`guard_tool` as `LlmAgent.before_tool_callback`. The authored `FunctionTool`
is branded (`_arcjet_guarded`) so the plugin skips it and Guard is not
double-called.

Deny is a skip-with-result dict (`arcjetDenied`). `None` allows. Never `{}` —
ADK treats an empty mapping as skip too. Fail-closed: a Guard error returns
an ERROR skip dict and the tool does not run.

Requires `message` and `session_id` in the JSON body. `session_id` must be a
printable ASCII id the **app already minted** (at most 256 bytes) — it is the
caller-owned correlation ID on `protect()`, inbound `guard()`, `guard_tool` /
`guard_plugin`, session `state={"sessionId": ...}`, and
`run_async(..., session_id=...)`. `google_adk_context` reads `correlationId`
then `sessionId` then `conversationId`. This example writes only `sessionId`
so that order is visible. It never mints one, never reads `trace_id`, never
reads an ADK-generated `invocation_id`, and never reads
`toolContext.session_id` / `session.id`.

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

A tool-path deny does not become an HTTP 403. `before_tool_callback` returns
the `{ arcjetDenied, reason, message, retryable, retryAfterSeconds? }` dict
so the original tool function does not run; the model sees the denial and
the run finishes. Do not throw (PluginManager wraps a throw as a plugin
error). Do not return `{}`.

The recipient address is the point of `send_email`, so EMAIL on `to` is not a
tool-path rule — that would deny every real send. EMAIL in the email *body*
still denies, as does EMAIL in the inbound `message`. `lookup_account` takes
an account id, not an email: a clean id can allow; an email in that id is
denied by the plugin.

`require_confirmation` / `request_confirmation` / ADK `SecurityPlugin` are
HITL, not the deny path. This example never sets or calls them.

## What to look for

In the Arcjet Console, search for the correlation ID (`sess-verify-001` in the
curl example above). You will see a single Sequence containing:

- The request-path `protect()` decision
- The inbound `guard()` decision on the user text
- The authored-tool `guard_tool` decision for `email.sent` (and its capture)
- Any Runner-plugin decision for the unwrapped `lookup_account` tool

`guard_plugin` is first on `InMemoryRunner(plugins=[...])`. `send_email` is
handed over branded so the plugin brand-skips it; `guard_tool` on
`LlmAgent.before_tool_callback` is that tool's gate. `lookup_account` is
unbranded so the plugin is its only gate.

The runner path is asynchronous and needs `launch_arcjet`. Do not pass the
sync `ArcjetGuardSync` client unless you have no async client.
