# Arcjet Python SDK Example FastAPI + Claude Agent SDK Guard Application

A FastAPI server with a Claude Agent SDK agent that uses Arcjet to protect the
HTTP request, screen inbound user text, authorize one authored `@tool`, and
deny unwrapped built-ins / MCP.

The Claude Agent SDK adapter is unpublished. This example pins
`arcjet[claude-agent-sdk]` to SHA `9ea0b06a87bcee77b8df0664338c712c4668b87b`
(branch `david/cursor/claude-agent-sdk-guard-242f`). That is not a PyPI
release. The extra pulls `claude-agent-sdk>=0.2.127,<1`. See
[`/guards/claude-agent-sdk-py/`](https://docs.arcjet.com/guards/claude-agent-sdk-py/)
— not the JS page
[`/guards/claude-agent-sdk/`](https://docs.arcjet.com/guards/claude-agent-sdk/).
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

Sends a message to a Claude Agent SDK agent that calls one authored tool
(`send_email`). The route is protected by Arcjet request rules (`protect()` is
fail-open — check deny / `is_error()`). Inbound user text is screened with the
core `guard()` call before `query()` (fail-open — check DENY /
`has_failed_open()`) and again on `UserPromptSubmit` via
`guard_hooks(..., inbound=...)` (`{decision: "block"}`). The authored tool is
authorized by `guard_tool`. Unwrapped built-ins / MCP are denied on
`PreToolUse` with `permissionDecision: "deny"`. There is no `guard_inbound`
helper.

Requires `message` and `session_id` in the JSON body. `session_id` must be a
UUID the **app already minted** — it is the caller-owned correlation ID on
`protect()`, `claude_agent_context` / `policy.session_id`, and
`ClaudeAgentOptions.session_id`. This example never mints one, never reads
`trace_id`, and never constructs a session just to ask it for an id.

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

If inbound `guard()` denies the user text — try a prompt-injection payload in
`message` — the agent does not start and the response is `403`:

```json
{ "error": "denied by policy" }
```

If inbound policy cannot be evaluated at all, `has_failed_open()` is `True` and
the response is `503` with `{ "error": "policy unavailable" }`. Core `guard()`
fails open; the route refuses to start `query()` anyway. `guard_hooks`
`inbound=` is the adapter `UserPromptSubmit` path (`{decision: "block"}`) for
the same prompt once the run starts.

A tool-path deny does not become an HTTP 403. `guard_tool` returns the MCP tool
result `{content:[{type:"text", text: <json ArcjetDenialResult>}], is_error: True}`
so the handler does not run; the model sees the denial and the run finishes.
Do not throw (the SDK swallows into `str(e)`). Do not set `structuredContent`
(`create_sdk_mcp_server` drops it).

`can_use_tool` and `permissionDecision: "ask"` are HITL, not the deny path.
This example does not set `can_use_tool` and never returns `"ask"`.

## What to look for

In the Arcjet Console, search for the correlation ID
(`550e8400-e29b-41d4-a716-446655440000` in the curl example above). You will
see a single Sequence containing:

- The request-path `protect()` decision
- The inbound `guard()` decision on the user text
- The inbound `UserPromptSubmit` decision from `guard_hooks(..., inbound=...)`
- The authored-tool `guard_tool` decision for `email.sent` (and its capture)
- Any `PreToolUse` decision for an unwrapped built-in / MCP tool

`guard_tool` wraps the `@tool` `send_email` and hands the copy to
`create_sdk_mcp_server`. The original is left unwrapped. `guard_hooks` lists
that wrapper in `exclude` as `{"server": "support", "name": "send_email"}` so
`PreToolUse` does not double-gate `mcp__support__send_email`. `Read` is left
unwrapped so `PreToolUse` `permissionDecision: "deny"` is the gate for a
built-in.

The runner path is asynchronous and needs `launch_arcjet`. Do not pass the
sync `ArcjetGuardSync` client unless you have no async client.
