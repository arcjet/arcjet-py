# Arcjet Python SDK Example Flask Application

## Setup

Assumes running inside the devcontainer:

Copy `example.env` to `.env.local` and set your Arcjet API key:

```sh
cp example.env .env.local
# Edit .env.local and set your ARCJET_KEY
```

Then run the Flask application:

```sh
uv run --env-file .env.local python main.py
```
