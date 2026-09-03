# Arcjet Python SDK Example FastAPI + Claude Managed Agents Guard Application

A FastAPI server with a **Claude Managed Agents** session (hosted REST+SSE,
beta `managed-agents-2026-04-01`) that uses Arcjet to protect the HTTP
request, screen inbound `user.message` / `initial_events` **before**
`sessions.events.send`, and authorize one custom tool on
`agent.custom_tool_use`.

This is **not** the Claude Agent SDK. Anthropic runs the tool loop. There
is no PreToolUse, no `guard_tool`, and no `guard_inbound`. Do not import
`arcjet.guard.claude_agent_sdk`. See
[`/guards/claude-managed-agents/`](https://docs.arcjet.com/guards/claude-managed-agents/)
— not the Claude Agent SDK page
[`/guards/claude-agent-sdk-py/`](https://docs.arcjet.com/guards/claude-agent-sdk-py/).

The Claude Managed Agents adapter is unpublished. This example pins
`arcjet[claude-managed-agents]` to SHA
`40ea4896962a90a24cdbc4cfbfc80729c096da36`. That is not a PyPI release.
The extra pulls `anthropic>=0.92.0,<2`. No chromadb. The runner path is
async (`launch_arcjet`, not `launch_arcjet_sync`).

## Setup

Assumes running inside the devcontainer:

Copy `example.env` to `.env.local` and set your API keys:

```sh
cp example.env .env.local
# Edit .env.local and set your ARCJET_KEY and ANTHROPIC_API_KEY
```

Then run the FastAPI application:

```sh
uv run --env-file .env.local fastapi dev main.py
```

Verify the adapter contracts without starting a Managed Agents session:

```sh
uv run python verify.py
```

The live PII scenario is opt-in. It hits the real Guard API only when both
`ARCJET_VERIFY_LIVE=1` and a real `ARCJET_KEY` are set:

```sh
ARCJET_VERIFY_LIVE=1 ARCJET_KEY=ajkey_... uv run python verify.py
```

## `POST /chat`

Sends a message to a Claude Managed Agents session that calls one custom
tool (`send_email`). The route is protected by Arcjet request rules
(`protect()` is fail-open — check deny / `is_error()`, the request-path
equivalent of Guard's `has_failed_open()`). Inbound user text is screened
with the core `guard()` call before the session starts (fail-open — check
DENY / `has_failed_open()`) and again by `guard_events` wrapping
`sessions.events.send` so `user.message` is gated **before** the original
send. The event stream is opened first — Anthropic only delivers events
emitted after the connection is up — then `user.message` and
`user.custom_tool_result` are sent on that connection. The custom tool is
authorized by `guard_custom_tool` on `agent.custom_tool_use`. There is no
`guard_inbound` helper. A session that hits the tool-round cap or ends
without `end_turn` is stopped with `user.interrupt`.

Default `permission_policy: always_allow` **cannot** gate Anthropic-cloud
bash / read / write, and `web_search` / `web_fetch` always run on
Anthropic. This agent lists only the custom tool. HITL `always_ask` /
`user.tool_confirmation` is not the happy path and is not set.

Requires `message` and `session_id` in the JSON body. `session_id` must be
a UUID the **app already minted** — it is the caller-owned correlation ID
on `protect()`, `claude_managed_agents_context` / `policy.session_id`, and
the Guard helpers. This example never mints one, never reads `trace_id`,
and never treats Anthropic's `ses_...` / `sevt_...` ids as if we created
them.

```shell
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Send a short welcome email to the onboarding list.", "session_id": "550e8400-e29b-41d4-a716-446655440000"}'
```

**Response:**

```json
{ "reply": "...", "session_id": "550e8400-e29b-41d4-a716-446655440000" }
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
an email address in `message` — the session does not start and the response is
`403`:

```json
{ "error": "denied by policy" }
```

If inbound policy cannot be evaluated at all, `has_failed_open()` is `True` and
the response is `503` with `{ "error": "policy unavailable" }`. Core `guard()`
fails open; the route refuses to create a session anyway. `guard_events` is
the adapter inbound path for the same prompt once `sessions.events.send` is
called (`user.message` / `initial_events`).

A tool-path deny does not become an HTTP 403. `guard_custom_tool` does not
run the tool; it sends a real `user.custom_tool_result` with `is_error: true`
and JSON `ArcjetDenialResult` text so the model sees the denial and the
session continues. `is_error` is on the events schema — use it; do not invent
a second field.

`permission_policy: always_ask` and `user.tool_confirmation` are HITL, not
the deny path. This example does not set them.

## What to look for

In the Arcjet Console, search for the correlation ID
(`550e8400-e29b-41d4-a716-446655440000` in the curl example above). You will
see a single Sequence containing:

- The request-path `protect()` decision
- The inbound `guard()` decision on the user text
- The inbound `guard_events` decision on `user.message`
- The custom-tool `guard_custom_tool` decision for `email.sent` (and its capture)

`guard_custom_tool(run=send_email)` is the hosted REST+SSE path. On
`agent.custom_tool_use` Guard runs before execute. The Anthropic session id
is used only as the events API `session_id`. The caller-owned UUID is the
Sequence id.

The runner path is asynchronous and needs `launch_arcjet`. Do not pass the
sync `ArcjetGuardSync` client unless you have no async client.
