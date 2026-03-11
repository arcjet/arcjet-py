# Arcjet Python SDK Example Flask + LangChain Application

A Flask server with a LangChain-powered chat endpoint, protected by Arcjet AI
app abuse protection (rate limiting, bot detection, and shield rules).

## Setup

Assumes running inside the devcontainer:

Copy `example.env` to `.env.local` and set your API keys:

```sh
cp example.env .env.local
# Edit .env.local and set your ARCJET_KEY and OPENAI_API_KEY
```

Then run the Flask application:

```sh
uv run --env-file .env.local python main.py
```

## `POST /chat`

Sends a message to a LangChain chat chain backed by OpenAI and returns the
reply. Protected by Arcjet AI app abuse rules (rate limit, bot detection, and
shield rules).


```shell
curl -X POST http://localhost:5000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What is the capital of France?"}'
```

**Response:**

```json
{ "reply": "The capital of France is Paris." }
```
