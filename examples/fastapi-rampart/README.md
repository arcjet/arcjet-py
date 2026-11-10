# Arcjet Python SDK — Rampart sensitive info detection example

This FastAPI example uses the on-device [Rampart](https://huggingface.co/nationaldesignstudio/rampart)
NER model backend (`arcjet[sensitive-info-rampart]`) to detect names, addresses,
contact details, and government/financial identifiers. Everything runs
locally — no data leaves your environment.

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

## Long text and PHI

The backend scans up to `max_input_chars` characters (100,000 by default). A
longer message is denied with `413` without being scanned, so nothing past the
limit gets through. If Arcjet can't complete the check, the route returns `503`
instead of accepting unscreened text.

For longer text, or to detect PHI such as medical record numbers, send the text
as a `SERVER` input to the server-side sensitive information detector in an
[agent guard policy](https://docs.arcjet.com/guards/remote-policies#detectors).
On-device detection doesn't detect the PHI types.
