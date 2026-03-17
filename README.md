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
  by automated clients and bots, with [verification and
  categorization](https://docs.arcjet.com/bot-protection/identifying-bots).
- 🛑 [Rate limiting](https://docs.arcjet.com/rate-limiting) - limit the number
  of requests a client can make.
- 🛡️ [Shield WAF](https://docs.arcjet.com/shield) - protect your application
  against common attacks.
- 📧 [Email validation](https://docs.arcjet.com/email-validation) - prevent
  users from signing up with fake email addresses.
- 📝 [Signup form protection](https://docs.arcjet.com/signup-protection) -
  combines rate limiting, bot protection, and email validation to protect your
  signup forms.
- 🔍 [Sensitive information
  detection](https://docs.arcjet.com/sensitive-info) - detect and block PII
  (emails, phone numbers, credit cards) in request content.
- 🔎 [Request filters](https://docs.arcjet.com/filters) - filter requests using
  expression-based rules against request properties.

### Get help

[Join our Discord server](https://arcjet.com/discord) or [reach out for
support](https://docs.arcjet.com/support).

## Installation

Install [from PyPI](https://pypi.org/project/arcjet/) with
[uv](https://docs.astral.sh/uv/):

```shell
# With a uv project
uv add arcjet

# With an existing pip managed project
uv pip install arcjet
```

Or with pip:

```shell
pip install arcjet
```

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
    Mode,
    BotCategory,
)

app = FastAPI()

arcjet_key = os.getenv("ARCJET_KEY")
if not arcjet_key:
    raise RuntimeError(
        "ARCJET_KEY is required. Get one at https://app.arcjet.com")

aj = arcjet(
    key=arcjet_key,  # Get your key from https://app.arcjet.com
    rules=[
        # Shield protects your app from common attacks e.g. SQL injection
        shield(mode=Mode.LIVE),
        # Create a bot detection rule
        detect_bot(
            mode=Mode.LIVE, allow=[
                BotCategory.SEARCH_ENGINE,  # Google, Bing, etc
                # Uncomment to allow these other common bot categories
                # See the full list at https://docs.arcjet.com/bot-protection/identifying-bots
                # BotCategory.MONITOR, # Uptime monitoring services
                # BotCategory.PREVIEW, # Link previews e.g. Slack, Discord
            ]
        ),
        # Create a token bucket rate limit. Other algorithms are supported
        token_bucket(
            # Tracked by IP address by default, but this can be customized
            # See https://docs.arcjet.com/fingerprints
            # characteristics=["ip.src"],
            mode=Mode.LIVE,
            refill_rate=5,  # Refill 5 tokens per interval
            interval=10,  # Refill every 10 seconds
            capacity=10,  # Bucket capacity of 10 tokens
        ),
    ],
)


@app.get("/")
async def hello(request: Request):
    # Call protect() to evaluate the request against the rules
    decision = await aj.protect(
        request, requested=5  # Deduct 5 tokens from the bucket
    )

    # Handle denied requests
    if decision.is_denied():
        status = 429 if decision.reason_v2.type == "RATE_LIMIT" else 403
        return JSONResponse(
            {"error": "Denied", "reason": decision.reason_v2},
            status_code=status,
        )

    # Check IP metadata (VPNs, hosting, geolocation, etc)
    if decision.ip.is_hosting():
        # Requests from hosting IPs are likely from bots, so they can usually be
        # blocked. However, consider your use case - if this is an API endpoint
        # then hosting IPs might be legitimate.
        # https://docs.arcjet.com/blueprints/vpn-proxy-detection

        return JSONResponse(
            {"error": "Denied from hosting IP"},
            status_code=403,
        )

    ip = decision.ip_details
    if ip and ip.city and ip.country_name:
        print(f"Request from {ip.city}, {ip.country_name}")

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

arcjet_key = os.getenv("ARCJET_KEY")
if not arcjet_key:
    raise RuntimeError(
        "ARCJET_KEY is required. Get one at https://app.arcjet.com")

aj = arcjet_sync(
    key=arcjet_key,
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
        status = 429 if decision.reason_v2.type == "RATE_LIMIT" else 403
        return jsonify(error="Denied", reason=decision.reason_v2), status

    if decision.ip.is_hosting():
        return jsonify(error="Hosting IP blocked"), 403

    ip = decision.ip_details
    if ip and ip.city and ip.country_name:
        print(f"Request from {ip.city}, {ip.country_name}")

    if any(is_spoofed_bot(r) for r in decision.results):
        return jsonify(error="Spoofed bot"), 403

    return jsonify(message="Hello world", decision=decision.to_dict())

if __name__ == "__main__":
    app.run(debug=True)
```

## Identifying bots

Arcjet allows you to configure a list of bots to allow or deny. To construct the
list, you can [specify individual
bots](https://github.com/arcjet/arcjet-js/blob/main/protocol/well-known-bots.ts#L4)
and/or use
[categories](https://docs.arcjet.com/bot-protection/identifying-bots#bot-categories)
to allow or deny all
bots in a category.

If you specify a list of bots to allow, then all other bots will be denied. An
empty allow list means all bots are denied. The opposite applies for deny lists,
if you specify bots to deny then all other bots will be allowed.

### Bot categories

Bots can be configured by
[category](https://docs.arcjet.com/bot-protection/identifying-bots#bot-categories)
and/or by [specific bot
name](https://github.com/arcjet/arcjet-js/blob/main/protocol/well-known-bots.ts#L4).
For example, to
allow all search engines and OpenAI crawler bots, but deny all other bots:

```py
from arcjet import arcjet, Mode, BotCategory, detect_bot

aj = arcjet(
    key=arcjet_key,
    rules=[
        detect_bot(
            mode=Mode.LIVE, 
            allow=[
                BotCategory.SEARCH_ENGINE, 
                "OPENAI_CRAWLER_SEARCH",
            ]
        ),
    ],
)
```

The identifiers on the bot list are generated from a [collection of known
bots](https://github.com/arcjet/well-known-bots) which includes details of their
owner and any variations.

If a bot is detected but cannot be identified as a known bot, it will be labeled
as `UNKNOWN_BOT`. This is separate from the `CATEGORY:UNKNOWN` category, which
is for bots that cannot be classified into any category but can still be
identified as a specific bot. You can see a list of these named, but
unclassified bots in the bot list.

Detections returned as `UNKNOWN_BOT` happen if the bot is new or hides itself.
It’s a bot with no name. Arcjet uses various techniques to detect these bots,
including analyzing request patterns and tracking IP addresses.

## Custom characteristics

Each client is tracked by IP address by default. To customize client
fingerprinting you can configure custom characteristics:

```py
# main.py
from flask import Flask, request, jsonify
import os
import logging

from arcjet import (
    arcjet_sync,
    shield,
    detect_bot,
    token_bucket,
    Mode,
    BotCategory,
    EmailType,
)

app = Flask(__name__)

arcjet_key = os.getenv("ARCJET_KEY")
if not arcjet_key:
    raise RuntimeError(
        "ARCJET_KEY is required. Get one at https://app.arcjet.com")

aj = arcjet_sync(
    key=arcjet_key,  # Get your key from https://app.arcjet.com
    rules=[
        # Shield protects your app from common attacks e.g. SQL injection
        shield(mode=Mode.LIVE),
        # Create a bot detection rule
        detect_bot(
            mode=Mode.LIVE,
            allow=[
                BotCategory.SEARCH_ENGINE,  # Google, Bing, etc
                # Uncomment to allow these other common bot categories
                # See the full list at https://docs.arcjet.com/bot-protection/identifying-bots
                # BotCategory.MONITOR, # Uptime monitoring services
                # BotCategory.PREVIEW, # Link previews e.g. Slack, Discord
            ],
        ),
        # Create a token bucket rate limit. Other algorithms are supported
        token_bucket(
            # Pass a custom characteristics to track requests
            characteristics=["userId"],
            mode=Mode.LIVE,
            refill_rate=5,  # Refill 5 tokens per interval
            interval=10,  # Refill every 10 seconds
            capacity=10,  # Bucket capacity of 10 tokens
        ),
    ],
)


@app.route("/")
def hello():
     # Replace with actual user ID from the user session
    userId = "your_user_id"

    # Call protect() to evaluate the request against the rules
    decision = aj.protect(
        request,
        # Deduct 5 tokens from the bucket
        requested=5,
        # Identify the user to track the limit against
        characteristics={"userId": userId},
    )

    # Handle denied requests
    if decision.is_denied():
        status = 429 if decision.reason_v2.type == "RATE_LIMIT" else 403
        return jsonify(error="Denied", reason=decision.reason_v2), status

    # Check IP metadata (VPNs, hosting, geolocation, etc)
    if decision.ip.is_hosting():
        # Requests from hosting IPs are likely from bots, so they can usually be
        # blocked. However, consider your use case - if this is an API endpoint
        # then hosting IPs might be legitimate.
        # https://docs.arcjet.com/blueprints/vpn-proxy-detection

        return jsonify(error="Hosting IP blocked"), 403

    ip = decision.ip_details
    if ip and ip.city and ip.country_name:
        app.logger.info("Request from %s, %s", ip.city, ip.country_name)

    return jsonify(message="Hello world", decision=decision.to_dict())


if __name__ == "__main__":
    app.run(debug=True)


```

## Sensitive information detection

Detect and optionally block sensitive information (PII) in request content such
as email addresses, phone numbers, IP addresses, and credit card numbers.

```py
from arcjet import arcjet, detect_sensitive_info, SensitiveInfoEntityType, Mode

aj = arcjet(
    key=arcjet_key,
    rules=[
        detect_sensitive_info(
            mode=Mode.LIVE,
            deny=[
                SensitiveInfoEntityType.EMAIL,
                SensitiveInfoEntityType.CREDIT_CARD_NUMBER,
            ],
        ),
    ],
)

# Pass the content to scan on each protect() call
decision = await aj.protect(request, sensitive_info_value="User input to scan")
```

You can also provide a custom detect callback to supplement the built-in
detectors:

```py
def my_detect(tokens: list[str]) -> list[str | None]:
    return ["CUSTOM_PII" if "secret" in t.lower() else None for t in tokens]

rules = [
    detect_sensitive_info(
        mode=Mode.LIVE,
        deny=["CUSTOM_PII"],
        detect=my_detect,
    ),
]
```

## Request filters

Filter requests using
[expression-based rules](https://docs.arcjet.com/filters/reference#expression-language)
against request properties (IP, headers, path, method, etc.).

```py
from arcjet import arcjet, filter_request, Mode

aj = arcjet(
    key=arcjet_key,
    rules=[
        filter_request(
            mode=Mode.LIVE,
            deny=['ip.src == "1.2.3.4"'],
        ),
    ],
)
```

You can also pass local fields for use in filter expressions:

```py
decision = await aj.protect(
    request,
    filter_local={"userId": current_user.id},
)
```

These are then available as `local.userId` in expressions.

## Trusted proxies

When your app runs behind one or more reverse proxies or a load balancer, pass
their IPs or CIDR ranges so Arcjet can correctly resolve the real client IP from
`X-Forwarded-For` and similar headers.

```py
from arcjet import arcjet

aj = arcjet(
    key=arcjet_key,
    rules=[...],
    proxies=["10.0.0.0/8", "192.168.0.1"],
)
```

Only globally routable IPs are accepted for client identification; private,
loopback, link-local, and addresses matching `proxies` are ignored during IP
extraction.

## Overriding automatic IP detection

By default, Arcjet automatically detects the client IP from the request using
 `X-Forwarded-For`. We recommend leaving this enabled in most cases and
configuring trusted proxies as needed (see above).

> [!WARNING]
> Disabling automatic IP detection is not recommended unless you have
> written your own IP detection logic that considers the correct parsing of IP
> headers. Accepting client IPs from untrusted sources can expose your
> application to IP spoofing attacks. See the [MDN
> documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For)
> for further guidance.

To disable automatic IP detection (for example, if you have your own custom
logic to extract the client IP), set `disable_automatic_ip_detection=True` when
creating the Arcjet client, and then provide the `ip_src` parameter to
`.protect(...)`.

```py
from arcjet import arcjet
aj = arcjet(
    key=arcjet_key,
    rules=[...],
    disable_automatic_ip_detection=True,
)

# ...

decision = await aj.protect(
    request,
    ip_src="8.8.8.8",  # provide the client IP here
)
```

## Logging

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

## Accessing decision details

Arcjet returns per-rule `rule_results` and a top-level `decision.reason_v2`. To
make a simple decision about allowing or denying a request you can check 
`if decision.is_denied():`. For more details, inspect the rule results.

### Getting bot detection details

To find out which bots were detected (if any):

```py
if decision.reason_v2.type == "BOT":
   denied = decision.reason_v2.denied

   print("Denied bots:", ", ".join(denied) if denied else "none")
```

### Verified vs spoofed bots

Bots claiming to be certain well-known bots (e.g. Googlebot) are verified by
checking their IP address against the known IP ranges for that bot. If a bot
claims to be a certain bot but fails verification, it is labeled as a spoofed
bot. You can check for spoofed bots with the `is_spoofed_bot()` helper:

```py
from arcjet import is_spoofed_bot

# ... after calling aj.protect() and getting a decision

if any(is_spoofed_bot(r) for r in decision.results):
    return jsonify(error="Spoofed bot"), 403
```

The decision reason will also indicate whether a bot was verified or spoofed:

```py
if decision.reason_v2.type == "BOT":
    print("Spoofed:", decision.reason_v2.spoofed)
    print("Verified:", decision.reason_v2.verified)

    # Example policy decisions
    if decision.reason_v2.spoofed:
        return jsonify(error="Spoofed bot"), 403

    if decision.reason_v2.verified:
        print("Known bot verified by Arcjet")
```

If you want to inspect bot results at the per-rule level, iterate through
`decision.results` and read `reason.spoofed` / `reason.verified` on BOT reasons:

```py
for result in decision.results:
    reason = result.reason
    if reason.type != "BOT":
        continue

    if reason.spoofed:
        return jsonify(error="Spoofed bot"), 403

    if reason.verified:
        print("Verified bot traffic")
```

## IP analysis

Arcjet returns an `ip_details` object as part of a `Decision` from
`aj.protect(...)`. There are several ways to inspect that data:

1. high-level helpers for common reputation checks.
2. typed fields via `Decision.ip_details`.
3. raw fields via `Decision.to_dict()`.

### IP analysis helpers

For common checks (is this IP a VPN, proxy, Tor exit node, or a hosting
provider) use the `IpInfo` helpers exposed at `decision.ip`:

```py
# high level booleans
if decision.ip.is_hosting():
    # likely a cloud / hosting provider — often suspicious for bots
    do_block()

if decision.ip.is_vpn() or decision.ip.is_proxy() or decision.ip.is_tor():
    # treat according to your policy
    do_something_else()
```

### IP analysis fields

Use `decision.ip_details` for typed field access:

```py
ip = decision.ip_details
if ip:
    lat = ip.latitude
    lon = ip.longitude
    asn = ip.asn
    asn_name = ip.asn_name
    service = ip.service  # str | None
else:
    # ip details not present
```

`Decision.to_dict()` also includes `ip_details` as a raw dictionary shape.

These are the available fields, although not all may be present for every IP:

- Geolocation: `latitude`, `longitude`, `accuracy_radius`, `timezone`,
  `postal_code`, `city`, `region`, `country`, `country_name`, `continent`,
  `continent_name`
- ASN / network: `asn`, `asn_name`, `asn_domain`, `asn_type` (isp, hosting,
  business, education), `asn_country`
- Reputation / service: service name (when present) and boolean indicators for
    `is_vpn`, `is_proxy`, `is_tor`, `is_hosting`, `is_relay`

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
