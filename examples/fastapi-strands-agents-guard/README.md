# Arcjet Python SDK Example FastAPI + Strands Agents Guard Application

A FastAPI server with a Strands Agents agent that uses Arcjet to protect the
HTTP request, screen inbound user text, authorize one authored `@tool`, and
deny an unwrapped tool.

The Strands Agents adapter is unpublished. This example pins
`arcjet[strands-agents]` to SHA `a630806169b92757192f3f5cce2e305827b26567`
(branch `david/cursor/strands-agents-guard`). That is not a PyPI release. The
extra pulls `strands-agents>=1.11.0,<2`. See
[`/guards/strands-agents-py/`](https://docs.arcjet.com/guards/strands-agents-py/)
— not the JS page
[`/guards/strands-agents/`](https://docs.arcjet.com/guards/strands-agents/).
The runner path is async (`launch_arcjet`, not `launch_arcjet_sync`).

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

## `POST /chat`

Sends a message to a Strands Agents agent that calls one authored tool
(`send_email`) and can also call an unwrapped tool (`lookup_account`). The
route is protected by Arcjet request rules (`protect()` is fail-open — check
deny / `is_error()`, the request-path equivalent of `has_failed_open()`).
Inbound user text is screened with the core `guard()` call before
`invoke_async` (fail-open — check DENY / `has_failed_open()`). There is no
`guard_inbound` helper and no inbound hook on the Strands bus. The authored
tool is authorized by `guard_tool`. The unwrapped tool is denied on
`BeforeToolCallEvent` with `cancel_tool` (a JSON `ArcjetDenialResult` string,
or `True`). `AfterToolCallEvent` is capture-only (`strands.phase: after`).

Requires `message` and `session_id` in the JSON body. `session_id` must be an
id the **app already minted** — it is the caller-owned correlation ID on
`protect()`, inbound `guard()`, `guard_tool` / `guard_hooks`, and
`invoke_async(..., invocation_state={"correlationId": ..., "sessionId": ...})`.
`strands_agent_context` reads `correlationId` then `sessionId` then
`requestId`. This example never mints one, never reads `trace_id`, and never
constructs a `SessionManager` just to ask it for an id.

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
an email address in `message` — the agent does not start and the response is
`403`:

```json
{ "error": "denied by policy" }
```

If inbound policy cannot be evaluated at all, `has_failed_open()` is `True` and
the response is `503` with `{ "error": "policy unavailable" }`. Core `guard()`
fails open; the route refuses to start `invoke_async` anyway.

A tool-path deny does not become an HTTP 403. `guard_tool` returns a plain
`ArcjetDenialResult` dict so the handler does not run; the model sees the
denial and the run finishes. Do not throw (the SDK swallows into
`Error: {Type} - {message}`). `guard_hooks` denies the unwrapped tool with
`BeforeToolCallEvent.cancel_tool` set to the same JSON envelope.

`event.interrupt()` is HITL, not the deny path. This example never calls it.
Do not set `BeforeToolsEvent.cancel` — a batch cancel skips per-tool
`BeforeToolCallEvent` hooks, so brand-skip would not run.

## What to look for

In the Arcjet Console, search for the correlation ID
(`550e8400-e29b-41d4-a716-446655440000` in the curl example above). You will
see a single Sequence containing:

- The request-path `protect()` decision
- The inbound `guard()` decision on the user text
- The authored-tool `guard_tool` decision for `email.sent` (and its capture)
- Any `BeforeToolCallEvent` decision for the unwrapped `lookup_account` tool
- `AfterToolCallEvent` capture (`strands.phase: after`) after an allowed tool

`guard_tool` wraps the `@tool` `send_email` and hands the copy to
`Agent(tools=[...])`. The original is left unwrapped. `lookup_account` is
handed over unwrapped so `cancel_tool` is its only gate. `guard_hooks` brand-
skips the wrapped copy on the before path (`_arcjet_guarded`) so Guard is not
called twice. `AfterToolCallEvent` is not skipped by the brand.

The runner path is asynchronous and needs `launch_arcjet`. Do not pass the
sync `ArcjetGuardSync` client unless you have no async client.
