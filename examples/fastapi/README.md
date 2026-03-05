# Arcjet Python SDK Example FastAPI Application

## Setup

Assumes running inside the devcontainer:

Copy `example.env` to `.env.local` and set your Arcjet API key:

```sh
cp example.env .env.local
# Edit .env and set your ARCJET_KEY
```

Then run the FastAPI application:

```sh
uv run --env-file .env.local fastapi dev
```
