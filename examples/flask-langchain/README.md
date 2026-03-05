# Arcjet Python SDK Example Flask + LangChain Application

A Flask server with a LangChain-powered chat endpoint, protected by Arcjet AI
app abuse protection (rate limiting, bot detection, and shield rules).

## Setup

Assumes running inside the devcontainer:

```shell
# Export your Arcjet API key
export ARCJET_KEY="ajkey_..."
export ARCJET_ENV=development

# Export your OpenAI API key (used by LangChain)
export OPENAI_API_KEY="sk-..."

# Install dependencies
uv sync

# Run the Flask application
uv run python main.py
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
