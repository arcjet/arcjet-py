# Arcjet Python SDK Example FastAPI + LangChain Guard Application

A FastAPI server with a LangChain agent that uses Arcjet Guard to protect agent tool calls and background actions, detecting prompt injection and sensitive data.

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

Sends a message to a LangChain agent that uses guarded tool calls and background actions. The agent is protected by Arcjet Guard with prompt injection detection and sensitive information blocking.

Requires `message` and `session_id` in the JSON body — the `session_id` is used as the correlation ID across the request boundary.

```shell
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What is the weather?", "session_id": "sess-verify-001"}'
```

**Response:**

```json
{ "reply": "...", "session_id": "sess-verify-001" }
```

If policy denies the tool call — try a prompt-injection payload in `message` —
the tool does not run and the response is `403`:

```json
{ "error": "denied by policy" }
```

If policy cannot be evaluated at all, the checkpoint fails closed and the
response is `503` with `{ "error": "policy unavailable" }`. That is the
deliberate default; see the fail-closed note in the repository README.

## What to look for

In the Arcjet Console, search for the correlation ID (`sess-verify-001` in the curl example above). You will see a single Sequence containing:

- The agent's guarded tool checkpoint (decision outcome and captures)
- The chain/model lifecycle captures from the LangChain callbacks
- The background worker's `receipt.sent` decision and its capture — all sharing the same `correlation_id`

This demonstrates that a correlation ID can be carried across a boundary that
`contextvars` do not cross — here the request handing work to a background task,
and in production a message broker — and resumed on the far side, landing every
decision and capture on the same Sequence. The worker holds its own synchronous
client for the same reason a broker's worker would: it is a separate execution
context that inherits nothing.
