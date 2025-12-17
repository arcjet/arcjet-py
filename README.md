<a href="https://arcjet.com" target="_arcjet-home"> <picture> <source
  media="(prefers-color-scheme: dark)"
    srcset="https://arcjet.com/logo/arcjet-dark-lockup-voyage-horizontal.svg">
<img src="https://arcjet.com/logo/arcjet-light-lockup-voyage-horizontal.svg"
  alt="Arcjet Logo" height="128" width="auto"> </picture> </a>

# Arcjet - Python SDK

<p>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://img.shields.io/pypi/v/arcjet?style=flat-square&label=%E2%9C%A6Aj&labelColor=000000&color=5C5866">
    <img alt="PyPI badge" src="https://img.shields.io/pypi/v/arcjet?style=flat-square&label=%E2%9C%A6Aj&labelColor=ECE6F0&color=ECE6F0">
  </picture>
</p>

[Arcjet](https://arcjet.com) helps developers protect their apps in just a few
lines of code. Bot detection. Rate limiting. Email validation. Attack
protection. A developer-first approach to security.

This is the monorepo containing various [Arcjet](https://arcjet.com) open source
packages for Python.

## Features

Arcjet security features for protecting Python apps:

- 🤖 [Bot protection](https://docs.arcjet.com/bot-protection) - manage traffic
  by automated clients and bots.
- 🛑 [Rate limiting](https://docs.arcjet.com/rate-limiting) - limit the number
  of requests a client can make.
- 🛡️ [Shield WAF](https://docs.arcjet.com/shield) - protect your application
  against common attacks.
- 📧 [Email validation](https://docs.arcjet.com/email-validation) - prevent
  users from signing up with fake email addresses.
- 📝 [Signup form protection](https://docs.arcjet.com/signup-protection) -
  combines rate limiting, bot protection, and email validation to protect your
  signup forms.

> [!NOTE]
> The Arcjet Python SDK currently doesn't support [sensitive information
> detection](https://docs.arcjet.com/sensitive-info) or [request
> filters](https://docs.arcjet.com/filters).

### Get help

[Join our Discord server](https://arcjet.com/discord) or [reach out for
support](https://docs.arcjet.com/support).

## Usage

Read the docs at [docs.arcjet.com](https://docs.arcjet.com/)

## Quick start example

This example implements Arcjet bot protection, rate limiting, email validation,
and Shield WAF in a FastAPI application. Requests from bots not in the allow
list will be blocked with a 403 Forbidden response.

The example email is invalid so an error will be returned - change the email to
see different results.

### FastAPI

An asynchronous example using FastAPI with the Arcjet async client.

```py
# main.py
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from arcjet import (
    arcjet,
    shield,
    detect_bot,
    token_bucket,
    is_spoofed_bot,
    validate_email,
    Mode,
    BotCategory,
    EmailType,
)

app = FastAPI()

aj = arcjet(
    key=os.environ["ARCJET_KEY"],
    rules=[
        shield(mode=Mode.LIVE),
        detect_bot(
            mode=Mode.LIVE, allow=[BotCategory.SEARCH_ENGINE, "OPENAI_CRAWLER_SEARCH"]
        ),
        token_bucket(mode=Mode.LIVE, refill_rate=5, interval=10, capacity=10),
        validate_email(
            mode=Mode.LIVE,
            deny=[EmailType.DISPOSABLE, EmailType.INVALID, EmailType.NO_MX_RECORDS],
        ),
    ],
)


@app.get("/")
async def hello(request: Request):
    # requested is optional; only relevant for token bucket rules (default: 1)
    # email is only required if validate_email() is configured
    decision = await aj.protect(request, requested=1, email="example@arcjet.ai")

    if decision.is_denied():
        status = 429 if decision.reason.is_rate_limit() else 403
        return JSONResponse(
            {"error": "Denied", "reason": decision.reason.to_dict()},
            status_code=status,
        )

    if decision.ip.is_hosting():
        return JSONResponse({"error": "Hosting IP blocked"}, status_code=403)

    if any(is_spoofed_bot(r) for r in decision.results):
        return JSONResponse({"error": "Spoofed bot"}, status_code=403)

    return {"message": "Hello world", "decision": decision.to_dict()}

```

### Flask

A synchronous example using Flask with the sync client.

```py
# main.py
from flask import Flask, request, jsonify
import os

from arcjet import (
  arcjet_sync,
  shield,
  detect_bot,
  token_bucket,
  validate_email,
  is_spoofed_bot,
  Mode,
  BotCategory,
  EmailType,
)

app = Flask(__name__)

aj = arcjet_sync(
    key=os.environ["ARCJET_KEY"],
    rules=[
        shield(mode=Mode.LIVE),
        detect_bot(
            mode=Mode.LIVE, allow=[BotCategory.SEARCH_ENGINE, "OPENAI_CRAWLER_SEARCH"]
        ),
        token_bucket(mode=Mode.LIVE, refill_rate=5, interval=10, capacity=10),
        validate_email(
            mode=Mode.LIVE,
            deny=[EmailType.DISPOSABLE, EmailType.INVALID, EmailType.NO_MX_RECORDS],
        ),
    ],
)

@app.route("/")
def hello():
  # requested is optional; only relevant for token bucket rules (default: 1)
  # email is only required if validate_email() is configured
  decision = aj.protect(request, requested=1, email="example@arcjet.com")

  if decision.is_denied():
    status = 429 if decision.reason.is_rate_limit() else 403
    return jsonify(error="Denied", reason=decision.reason.to_dict()), status

  if decision.ip.is_hosting():
    return jsonify(error="Hosting IP blocked"), 403

  if any(is_spoofed_bot(r) for r in decision.results):
    return jsonify(error="Spoofed bot"), 403

  return jsonify(message="Hello world", decision=decision.to_dict())

if __name__ == "__main__":
  app.run(debug=True)
```

### Custom characteristics

Each client is tracked by IP address by default. To customize client
fingerprinting you can configure custom characteristics:

```py
# main.py
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from arcjet import (
    arcjet,
    shield,
    token_bucket,
    Mode,
    BotCategory,
)

app = FastAPI()

aj = arcjet(
    key=os.environ["ARCJET_KEY"],
    rules=[
        shield(mode=Mode.LIVE),
        token_bucket(
            mode=Mode.LIVE,
            refill_rate=5,
            interval=10,
            capacity=10,
            # track clients by userId characteristic
            characteristics=["userId"],
        ),
    ],
)


@app.get("/")
async def hello(request: Request):
    decision = await aj.protect(
      # pass userId characteristic for this request
        request, requested=1, characteristics={"userId": "user-1234"}
    )

    if decision.is_denied():
        status = 429 if decision.reason.is_rate_limit() else 403
        return JSONResponse(
            {"error": "Denied", "reason": decision.reason.to_dict()},
            status_code=status,
        )

    return {"message": "Hello world", "decision": decision.to_dict()}

```

### Trusted proxies

When your app runs behind one or more reverse proxies or a load balancer, pass
their IPs or CIDR ranges so Arcjet can correctly resolve the real client IP from
`X-Forwarded-For` and similar headers.

```py
from arcjet import arcjet

aj = arcjet(
    key=os.environ["ARCJET_KEY"],
    rules=[...],
    proxies=["10.0.0.0/8", "192.168.0.1"],
)
```

Only globally routable IPs are accepted for client identification; private,
loopback, link-local, and addresses matching `proxies` are ignored during IP
extraction.

### Logging

Enable debug logging to troubleshoot issues with Arcjet integration.

```py
import logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(name)s %(message)s"
)
```

Arcjet logging can be controlled directly by setting the `ARCJET_LOG_LEVEL`
environment variable e.g. `export ARCJET_LOG_LEVEL=debug`.

## Tests

Run the unit tests locally with uv and pytest:

```bash
uv run pytest -q
```

- Tests stub the Decide API protobufs and clients, so no network access is required.
- Set `ARCJET_LOG_LEVEL=debug` to see detailed debug logs during development.

## Support

This repository follows the [Arcjet Support
Policy](https://docs.arcjet.com/support).

## Security

This repository follows the [Arcjet Security
Policy](https://docs.arcjet.com/security).

## Compatibility

Packages maintained in this repository are compatible with Python 3.10 and
above.

## License

Licensed under the [Apache License, Version
2.0](http://www.apache.org/licenses/LICENSE-2.0).
