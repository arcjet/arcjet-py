# Refund desk — FastAPI + Google ADK Guard

A shop-style FastAPI service that issues refunds through a real Google ADK
`InMemoryRunner`. A scripted `BaseLlm` always calls `issue_refund`, so this
runs without a Gemini key.

`guard_plugin` is first on the Runner. Do not also attach `guard_tool`.
The caller-owned Sequence id is written only to ADK session state as
`sessionId`. `google_adk_context` reads ADK's dict-like `State` (it is not
a `Mapping`). Wrap-time `session_id=` is omitted on purpose.

Inbound user text (`reason`) is screened with core `guard()` before the
runner starts. Refunds over $500 (`50000` cents) are denied by a local
custom rule. An email address in `reason` is denied as sensitive info.

## Setup

```sh
cp example.env .env.local
# Edit .env.local and set ARCJET_KEY
cd examples/fastapi-google-adk-shop
uv run --env-file .env.local fastapi dev main.py
```

Verify without Gemini. Runner scenarios use an in-memory Guard client.
With a real `ARCJET_KEY`, live `POST /refund` scenarios run too:

```sh
cd examples/fastapi-google-adk-shop
uv run python verify.py
```

## `POST /refund`

```shell
curl -X POST http://localhost:8000/refund \
  -H "Content-Type: application/json" \
  -d '{"session_id":"sess-shop-001","user_id":"user-42","order_id":"ord-100","amount_cents":1500,"reason":"arrived damaged"}'
```

A refund over $500 is accepted by HTTP and denied on the tool path — the
handler does not run; the model sees a skip dict with `arcjetDenied`.
