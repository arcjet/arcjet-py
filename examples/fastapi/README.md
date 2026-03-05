# Arcjet Python SDK Example FastAPI Application

## Setup

Assumes running inside the devcontainer.

Copy `example.env` to `.env` and set your Arcjet API key:

```sh
cp example.env .env
# Edit .env and set your ARCJET_KEY
```

Then run the FastAPI application:

```sh
uv run --env-file .env fastapi dev
```
