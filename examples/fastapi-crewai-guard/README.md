# Arcjet Python SDK Example FastAPI + CrewAI Guard Application

A FastAPI server with a CrewAI crew that uses Arcjet to protect the HTTP
request, screen inbound user text, and authorize the crew's tool calls.

There is no `arcjet[crewai]` extra. This example installs `crewai>=1.15.3,<2`
itself (Python `>=3.10,<3.14`) and uses the local checkout via
`[tool.uv.sources]`. The hook path is sync-only (`launch_arcjet_sync`).

> [!NOTE]
> CrewAI installs `chromadb`, which has an unpatched critical RCE
> ([CVE-2026-45829](https://nvd.nist.gov/vuln/detail/CVE-2026-45829)). The
> exposed surface is ChromaDB's **Python FastAPI server**. CrewAI's own memory
> uses an embedded client and starts no server. This example does not commit
> a `uv.lock` so that CVE is not pinned into the repository.

## Setup

Assumes running inside the devcontainer:

Copy `example.env` to `.env.local` and set your API keys:

```sh
cp example.env .env.local
# Edit .env.local and set your ARCJET_KEY and OPENAI_API_KEY
```

Then run the FastAPI application from this directory:

```sh
cd examples/fastapi-crewai-guard
uv run --env-file .env.local fastapi dev main.py
```

Verify the adapter contracts without starting a crew. Run this from
`examples/fastapi-crewai-guard` so `import main` resolves here:

```sh
cd examples/fastapi-crewai-guard
uv run python verify.py
```

The live PII scenario is opt-in. It hits the real Guard API only when both
`ARCJET_VERIFY_LIVE=1` and a real `ARCJET_KEY` are set:

```sh
ARCJET_VERIFY_LIVE=1 ARCJET_KEY=ajkey_... uv run python verify.py
```

## `POST /chat`

Sends a message to a CrewAI crew that calls one authored tool (`Send Email`)
and can also call an unwrapped tool (`Lookup Account`). The route is
protected by Arcjet request rules (`protect()` is fail-open — check deny /
`is_error()`). Inbound user text is screened with the core `guard()` call
before `crew.kickoff` (fail-open — check DENY / `has_failed_open()`). There
is no `guard_inbound` helper. Tool calls are authorized by
`register_arcjet_hooks`. A deny raises `HookAborted(reason, source="arcjet")`
so the tool does not run. CrewAI swallows every other exception.

Requires `message` and `session_id` in the JSON body. `session_id` must be a
printable ASCII id the **app already minted** (at most 256 bytes) — it is the
caller-owned correlation ID on `protect()`, inbound `guard()`, and the hooks.
This example never mints one, and never reads `crew.id` / `task.id` /
`agent.id`.

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
an email address in `message` — the crew does not start and the response is
`403`:

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
message. `POST_TOOL_CALL` is not registered.

The recipient address is the point of `Send Email`, so EMAIL on `to` is not a
tool-path local rule — that would deny every real send. EMAIL in the inbound
`message` or in the tool `body` still denies. `Lookup Account` takes an account
id, not an email: a clean id can allow; an email in that id is denied by the
hook.

### Production note

This example registers `register_arcjet_hooks` on every request so it can bind
that request's correlation id and inbound text. CrewAI's hook registry is
process-global, so a real service should register once at startup and pass
per-request context through `correlation_id`, closures, or request-scoped
config — not register/unregister around every `kickoff`. The `_hooks_lock`
here serializes concurrent chats; that is fine for a demo, not for throughput.

`human_input` and `Task.guardrail` are HITL / task review, not the deny path.

If you call a CrewAI `BaseTool` yourself (not through a crew), wrap it with
`guard_tool` — `BaseTool.run` never dispatches `PRE_TOOL_CALL`. That path
raises `ArcjetDeniedError` / `ArcjetUnavailableError`. Give the crew the
wrapped *copy* so the hook brand-skips it; the original is left unwrapped on
purpose.

## What to look for

In the Arcjet Console, search for the correlation ID (`sess-verify-001` in the
curl example above). You will see a single Sequence containing:

- The request-path `protect()` decision
- The inbound `guard()` decision on the user text
- The crew's `PRE_TOOL_CALL` decision for `email.sent` (and its capture)
- Any hook decision for the unwrapped `lookup_account` tool

`tools=` lists `"Send Email"` and `"Lookup Account"`, and the `action=`
resolver uses `sanitize_tool_name` so `Send Email` becomes `send_email` before
matching — if sanitization were skipped, `email.sent` would miss the tool and
it would run unguarded. That is the typo check: a reviewer can see matching
is CrewAI-sanitized.

The hook path is synchronous and needs `launch_arcjet_sync`. Do not pass the
async `ArcjetGuard` client unless you have no sync client — an async client
is refused at registration.
