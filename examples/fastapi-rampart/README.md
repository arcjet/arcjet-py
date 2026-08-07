# Arcjet Python SDK — Rampart sensitive info detection example

This FastAPI example uses the on-device [Rampart](https://huggingface.co/nationaldesignstudio/rampart)
NER model backend (`arcjet[sensitive-info-rampart]`) to detect names, addresses,
and government/financial identifiers in addition to the four types the default
WebAssembly engine detects. Everything runs locally — no data leaves your
environment.

## Setup

Assumes running inside the devcontainer.

Copy `example.env` to `.env.local` and set your Arcjet API key:

```sh
cp example.env .env.local
# Edit .env.local and set your ARCJET_KEY
```

Then run the FastAPI application:

```sh
uv run --env-file .env.local fastapi dev
```

The first request loads the bundled ~15&nbsp;MB ONNX model into memory; it is
reused for every subsequent request.

## Try it

```sh
# Allowed — no sensitive info
curl "http://localhost:8000/?message=hello%20there"

# Denied — contains a name, email, and SSN
curl "http://localhost:8000/?message=My%20name%20is%20Alex%20Rivera,%20SSN%20472-81-0094,%20alex@example.com"
```
