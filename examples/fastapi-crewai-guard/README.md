# Arcjet Python SDK Example FastAPI + CrewAI Guard Application

A FastAPI server with a CrewAI crew that uses Arcjet to protect the HTTP
request, screen inbound user text, and authorize the crew's tool calls.

The CrewAI adapter is unpublished. This example pins `arcjet[crewai]` to SHA
`cc7dd09260cabe3bfac7aff8fa07e085c209b1db` on `david/cursor/guard-crewai-hooks`
— not a PyPI release, and not a path to this checkout, which does not ship the
extra yet. The extra depends on `crewai>=1.15.3,<2` and requires Python
`>=3.10,<3.14`. The hook path is sync-only (`launch_arcjet_sync`).

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

Sends a message to a CrewAI crew that calls one authored tool (`Send Email`).
The route is protected by Arcjet request rules; inbound user text is screened
with the core `guard()` call before `crew.kickoff`; tool calls are authorized
by `register_arcjet_hooks`. There is no `guard_inbound` helper.

Requires `message` and `session_id` in the JSON body — the `session_id` is the
caller-owned correlation ID on both `protect()` and the hooks. It is never
taken from `crew.id` or `task.id`.

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
`message` — the crew does not start and the response is `403`:

```json
{ "error": "denied by policy" }
```

If inbound policy cannot be evaluated at all, `has_failed_open()` is `True` and
the response is `503` with `{ "error": "policy unavailable" }`. Core `guard()`
fails open; the route refuses to start the crew anyway.

A tool-path deny does not become an HTTP 403. `PRE_TOOL_CALL` raises
`HookAborted` so the tool does not run; CrewAI turns that into the agent-facing
string `Tool execution blocked by hook. Tool: {name}` and the crew finishes.
`HookAborted.reason` is telemetry only — do not treat it as the user-visible
message, and do not rewrite `tool_result` in `POST_TOOL_CALL`. That is the
deliberate default; see the fail-closed note in the repository README.

`human_input` and `Task.guardrail` are HITL / task review, not the deny path.

## What to look for

In the Arcjet Console, search for the correlation ID (`sess-verify-001` in the
curl example above). You will see a single Sequence containing:

- The request-path `protect()` decision
- The inbound `guard()` decision on the user text
- The crew's `PRE_TOOL_CALL` decision for `email.sent` (and its capture)

`policies=` is keyed `"Send Email"` and `tools=` lists the same name. CrewAI
sanitizes that to `send_email` before matching — if sanitization were skipped,
the policy would miss the tool and it would run unguarded. That is the typo
check: a reviewer can see matching is CrewAI-sanitized.

The hook path is synchronous and needs `launch_arcjet_sync`. Do not pass the
async `ArcjetGuard` client.
