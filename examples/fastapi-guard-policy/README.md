# Arcjet Guard remote policy with FastAPI

This example evaluates the remotely configured `email` policy with two typed
inputs: a server-visible recipient and a body that remains in local SDK memory.

## Run

```sh
cp example.env .env.local
# Set ARCJET_KEY in .env.local
uv run --env-file .env.local fastapi dev --host 0.0.0.0
```

Open <http://localhost:8000>. The form displays the overall decision and the
results of both remote-policy rules.
