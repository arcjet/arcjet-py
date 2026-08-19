<a href="https://arcjet.com" target="_arcjet-home"> <picture> <source
  media="(prefers-color-scheme: dark)"
    srcset="https://arcjet.com/logo/arcjet-dark-lockup-voyage-horizontal.svg">
<img src="https://arcjet.com/logo/arcjet-light-lockup-voyage-horizontal.svg"
  alt="Arcjet Logo" height="128" width="auto"> </picture> </a>

# arcjet

<p>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://img.shields.io/pypi/v/arcjet?style=flat-square&label=%E2%9C%A6Aj&labelColor=000000&color=5C5866">
    <img alt="PyPI badge" src="https://img.shields.io/pypi/v/arcjet?style=flat-square&label=%E2%9C%A6Aj&labelColor=ECE6F0&color=ECE6F0">
  </picture>
</p>

[Arcjet](https://arcjet.com) is the runtime security platform that ships in your AI code. Detect prompt injection, authorize agent tool calls, redact sensitive data, and block bots and abuse. Real-time security building blocks you call inside your app, before an action happens.

This is the Python SDK for [Arcjet](https://arcjet.com) — use `arcjet` /
`arcjet_sync` for **request protection** (FastAPI, Flask, Django route handlers)
and `arcjet.guard` for **guard protection** (AI agent tool calls, MCP servers,
background jobs).

## Why Arcjet?

Your app's AI features and agents take real actions, calling tools, reading data, hitting APIs. Arcjet runs inside that code and lets you enforce security on each action in real time, then audit what happened.

## Getting started

### Install the Arcjet CLI

The CLI is used to log in, manage site keys, and install protection skills.

**Homebrew (macOS and Linux):**

```sh
brew install arcjet/tap/arcjet
```

**npx (Node.js)** — run any command without installing:

```sh
npx @arcjet/cli <command>
```

**Or [download a binary](https://github.com/arcjet/arcjet-cli/releases)** for
macOS (Apple Silicon, Intel), Linux (x86_64, arm64), and Windows (x86_64,
arm64).

> Examples below use the `arcjet` binary. If you installed via npx, replace
> `arcjet` with `npx @arcjet/cli`.

### Quick setup with an AI agent

1. Log in with the CLI:
   ```sh
   arcjet auth login
   ```
2. Install the Arcjet skill:
   ```sh
   npx skills add arcjet/skills
   ```
3. Tell your agent what to protect — it handles the rest.

### Manual setup

1. **Log in** with the CLI (or at [`app.arcjet.com`](https://app.arcjet.com)):
   ```sh
   arcjet auth login
   ```
2. `pip install arcjet` (or `uv add arcjet`)
3. **Get your site key:**
   ```sh
   arcjet sites get-key
   ```
   Or copy it from the [Arcjet dashboard](https://app.arcjet.com).
4. Set `ARCJET_KEY=ajkey_yourkey` in `.env`
5. Protect a route — see the [AI protection example](#quick-start) or
   individual [feature examples](#features) below.

### Get help

[Join our Discord server](https://arcjet.com/discord) or [reach out for
support](https://docs.arcjet.com/support).

- [Documentation](https://docs.arcjet.com) — full reference and guides
- [Examples](https://github.com/arcjet/arcjet-py/tree/main/examples) — FastAPI
  and Flask example apps, including LangChain integration
- [Blueprints](https://docs.arcjet.com/blueprints) — recipes for common security
  patterns

## Quick start

> **Note:** Examples below use FastAPI (async). For Flask and other sync
> frameworks, use `arcjet_sync` instead of `arcjet`. The API is identical — see
> [Async vs. sync client](#async-vs-sync-client).

Protect an AI chat endpoint with prompt injection detection, token budget rate
limiting, and bot protection:

```py
# main.py
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from arcjet import (
    arcjet,        # async client — use arcjet_sync for Flask and other sync frameworks
    detect_bot,
    detect_prompt_injection,
    detect_sensitive_info,
    shield,
    token_bucket,
    Mode,
    SensitiveInfoEntityType,
)

app = FastAPI()

arcjet_key = os.getenv("ARCJET_KEY")
if not arcjet_key:
    raise RuntimeError(
        "ARCJET_KEY is required. Get one with: arcjet sites get-key"
        " or from https://app.arcjet.com"
    )

# Create a single Arcjet instance and reuse it across requests.
# Use arcjet_sync instead if you are using Flask or another sync framework.
aj = arcjet(
    key=arcjet_key,
    rules=[
        # Detect and block prompt injection attacks in user messages
        detect_prompt_injection(mode=Mode.LIVE),
        # Block sensitive data (e.g. credit cards, PII) from reaching your LLM
        detect_sensitive_info(
            mode=Mode.LIVE,
            deny=[
                SensitiveInfoEntityType.CREDIT_CARD_NUMBER,
                SensitiveInfoEntityType.EMAIL,
                SensitiveInfoEntityType.PHONE_NUMBER,
            ],
        ),
        # Rate limit by token budget — refill 100 tokens every 60 seconds
        token_bucket(
            characteristics=["userId"],
            mode=Mode.LIVE,
            refill_rate=100,
            interval=60,
            capacity=1000,
        ),
        # Block automated clients and scrapers from your AI endpoints
        detect_bot(
            mode=Mode.LIVE,
            allow=[],  # empty = block all bots
        ),
        # Protect against common web attacks (SQLi, XSS, etc.)
        shield(mode=Mode.LIVE),
    ],
)


class ChatRequest(BaseModel):
    message: str


@app.post("/chat")
async def chat(request: Request, body: ChatRequest):
    userId = "user_123"  # replace with real user ID from session

    decision = await aj.protect(
        request,
        requested=5,  # tokens consumed per request
        characteristics={"userId": userId},
        detect_prompt_injection_message=body.message,  # scan for prompt injection
        sensitive_info_value=body.message,  # scan for PII
    )

    if decision.is_denied():
        status = 429 if decision.reason_v2.type == "RATE_LIMIT" else 403
        return JSONResponse({"error": "Denied"}, status_code=status)

    # Safe to pass body.message to your LLM
    return {"reply": "..."}
```

## Features

| Feature | Request (`arcjet`) | Guard (`arcjet.guard`) |
| --- | :---: | :---: |
| Rate Limiting | ✅ | ✅ |
| Prompt Injection Detection | ✅ | ✅ |
| Content Moderation | — | ✅ |
| Sensitive Information Detection | ✅ | ✅ |
| Bot Protection | ✅ | — |
| Shield WAF | ✅ | — |
| Email Validation | ✅ | — |
| Request Filters | ✅ | — |
| IP Analysis | ✅ | — |
| Custom Rules | — | ✅ |
| Capture (visibility events) | — | ✅ |

- 🔒 [Prompt Injection Detection](#prompt-injection-detection) — detect and block
  prompt injection attacks before they reach your LLM.
- 🚫 [Content Moderation](#content-moderation) — detect harmful content in Guard
  tool-call and job inputs.
- 🤖 [Bot Protection](#bot-protection) — stop scrapers, credential stuffers, and
  AI crawlers from abusing your endpoints.
- 🛑 [Rate Limiting](#rate-limiting) — token bucket, fixed window, and sliding
  window algorithms; model AI token budgets per user.
- 🕵️ [Sensitive Information Detection](#sensitive-information-detection) — block
  PII, credit cards, and custom patterns from entering your AI pipeline.
- 🛡️ [Shield WAF](#shield-waf) — protect against SQL injection, XSS, and other
  common web attacks.
- 📧 [Email Validation](#email-validation) — block disposable, invalid, and
  undeliverable addresses at signup.
- 📝 [Signup Form Protection](https://docs.arcjet.com/signup-protection) —
  combines bot protection, email validation, and rate limiting to protect your
  signup forms.
- 🎯 [Request Filters](#request-filters) — expression-based rules on IP, path,
  headers, and custom fields.
- 🌐 [IP Analysis](#ip-analysis) — geolocation, ASN, VPN, proxy, Tor, and hosting
  detection included with every request.
- 🧩 [Arcjet Guard](#arcjet-guard) — lower-level API for AI agent tool calls and
  background tasks where there is no HTTP request.

### Which features do I need?

| If your app has...            | Recommended features                                                          |
| ----------------------------- | ----------------------------------------------------------------------------- |
| LLM / AI chat endpoints       | Prompt injection + sensitive info + token bucket rate limit + bot protection + shield |
| AI agent tool calls           | [Arcjet Guard](#arcjet-guard) — rate limiting + prompt injection + content moderation + sensitive info + custom rules |
| Public API                    | Rate limiting + bot protection + shield                                       |
| Signup / login forms          | Email validation + bot protection + rate limiting (or [signup protection](https://docs.arcjet.com/signup-protection)) |
| Internal / admin routes       | Shield + request filters (country, VPN/proxy blocking)                        |
| Any web application           | Shield + bot protection (good baseline for all apps)                          |

All features can be combined in a single Arcjet instance. Rules are evaluated
together — if **any** rule denies the request, `decision.is_denied()` returns
`True`. Use `Mode.DRY_RUN` on individual rules to test them before enforcing.

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

## Prompt injection detection

Detect and block prompt injection attacks — attempts by users to hijack your
LLM's behavior through crafted input — before they reach your model.

### FastAPI

```py
from arcjet import arcjet, detect_prompt_injection, Mode

aj = arcjet(
    key=arcjet_key,
    rules=[
        detect_prompt_injection(mode=Mode.LIVE),
    ],
)

@app.post("/chat")
async def chat(request: Request, body: ChatRequest):
    decision = await aj.protect(
        request,
        detect_prompt_injection_message=body.message,
    )

    if decision.is_denied():
        return JSONResponse({"error": "Prompt injection detected"}, status_code=403)

    # safe to pass body.message to your LLM
```

### Flask

```py
from arcjet import arcjet_sync, detect_prompt_injection, Mode

aj = arcjet_sync(
    key=arcjet_key,
    rules=[
        detect_prompt_injection(mode=Mode.LIVE),
    ],
)

@app.route("/chat", methods=["POST"])
def chat():
    body = request.get_json()
    decision = aj.protect(request, detect_prompt_injection_message=body["message"])

    if decision.is_denied():
        return jsonify(error="Prompt injection detected"), 403

    # safe to pass body["message"] to your LLM
```

You can tune the detection sensitivity with the `threshold` parameter (0.0–1.0,
default 0.5). Higher values require stronger signals to trigger a denial,
reducing false positives but potentially missing subtle attacks:

```py
detect_prompt_injection(mode=Mode.LIVE, threshold=0.8)
```

See the [Prompt Injection docs](https://docs.arcjet.com/prompt-injection) for
more details.

## Bot protection

Manage traffic from automated clients. Block scrapers, credential stuffers, and
AI crawlers, while allowing legitimate bots like search engines and monitors.

### FastAPI

```py
from arcjet import arcjet, detect_bot, Mode, BotCategory

aj = arcjet(
    key=arcjet_key,
    rules=[
        detect_bot(
            mode=Mode.LIVE,
            allow=[
                BotCategory.SEARCH_ENGINE,  # Google, Bing, etc.
                # BotCategory.MONITOR,      # Uptime monitoring
                # BotCategory.PREVIEW,      # Link previews (Slack, Discord)
                # "OPENAI_CRAWLER_SEARCH",  # Allow OpenAI crawler
            ],
        ),
    ],
)

@app.get("/")
async def index(request: Request):
    decision = await aj.protect(request)

    if decision.is_denied():
        return JSONResponse({"error": "Bot detected"}, status_code=403)

    return {"message": "Hello world"}
```

### Flask

```py
from arcjet import arcjet_sync, detect_bot, is_spoofed_bot, Mode, BotCategory

aj = arcjet_sync(
    key=arcjet_key,
    rules=[
        detect_bot(mode=Mode.LIVE, allow=[BotCategory.SEARCH_ENGINE]),
    ],
)

@app.route("/")
def index():
    decision = aj.protect(request)

    if decision.is_denied():
        return jsonify(error="Bot detected"), 403

    if any(is_spoofed_bot(r) for r in decision.results):
        return jsonify(error="Spoofed bot"), 403

    return jsonify(message="Hello world")
```

### Bot categories

Configure rules using [categories](https://docs.arcjet.com/bot-protection/identifying-bots#bot-categories)
or [specific bot identifiers](https://github.com/arcjet/well-known-bots):

```py
detect_bot(
    mode=Mode.LIVE,
    allow=[
        BotCategory.SEARCH_ENGINE,
        "OPENAI_CRAWLER_SEARCH",
    ],
)
```

Available categories: `ACADEMIC`, `ADVERTISING`, `AI`, `AMAZON`,
`ARCHIVE`, `BOTNET`, `FEEDFETCHER`, `GOOGLE`, `META`, `MICROSOFT`,
`MONITOR`, `OPTIMIZER`, `PREVIEW`, `PROGRAMMATIC`, `SEARCH_ENGINE`,
`SLACK`, `SOCIAL`, `TOOL`, `UNKNOWN`, `VERCEL`, `YAHOO`. Use
`BotCategory.<NAME>` in Python or pass the string directly. You can also
allow or deny [specific bots by name](https://arcjet.com/bot-list).

If you specify an allow list, all other bots are denied. An empty allow list
blocks all bots. The reverse applies for deny lists.

### Verified vs. spoofed bots

Bots claiming to be well-known crawlers (e.g. Googlebot) are verified against
their known IP ranges. Use `is_spoofed_bot()` to check:

```py
from arcjet import is_spoofed_bot

if any(is_spoofed_bot(r) for r in decision.results):
    return jsonify(error="Spoofed bot"), 403
```

See the [Bot Protection docs](https://docs.arcjet.com/bot-protection) for
more details.

## Rate limiting

Limit request rates per IP, user, or any custom characteristic. Arcjet supports
token bucket, fixed window, and sliding window algorithms. Token buckets are
ideal for controlling AI token budgets — set `capacity` to the max tokens a user
can spend, `refill_rate` to how many tokens are restored per `interval`, and
deduct tokens per request via `requested` in `protect()`. The `interval` accepts
seconds as a number. Use `characteristics` to track limits per user instead of
per IP.

### Token bucket (recommended for AI)

Rate limits track by IP address by default. To track per user, declare the key
name in `characteristics` on the rule, then pass the actual value in
`protect()`:

```py
from arcjet import arcjet, token_bucket, Mode

aj = arcjet(
    key=arcjet_key,
    rules=[
        token_bucket(
            characteristics=["userId"],  # or ["ip.src"] for IP-based
            mode=Mode.LIVE,
            refill_rate=100,   # tokens added per interval
            interval=60,       # interval in seconds
            capacity=1000,     # maximum tokens per bucket
        ),
    ],
)

@app.post("/chat")
async def chat(request: Request):
    decision = await aj.protect(
        request,
        requested=5,  # tokens consumed by this request
        characteristics={"userId": "user_123"},
    )

    if decision.is_denied():
        return JSONResponse({"error": "Rate limited"}, status_code=429)
```

### Fixed window

```py
from arcjet import arcjet, fixed_window, Mode

aj = arcjet(
    key=arcjet_key,
    rules=[
        fixed_window(mode=Mode.LIVE, window=60, max=100),
    ],
)
```

### Sliding window

```py
from arcjet import arcjet, sliding_window, Mode

aj = arcjet(
    key=arcjet_key,
    rules=[
        sliding_window(mode=Mode.LIVE, interval=60, max=100),
    ],
)
```

See the [Rate Limiting docs](https://docs.arcjet.com/rate-limiting) for more
details.

## Sensitive information detection

Detect and block PII in request content before it reaches your LLM or data
store. The default (local WebAssembly) backend detects `EMAIL`, `PHONE_NUMBER`,
`IP_ADDRESS`, and `CREDIT_CARD_NUMBER`. You can provide a custom `detect`
callback for additional patterns, or the optional on-device Rampart `backend`
(see below) for names, addresses, and government/financial identifiers.

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

# Pass the content to scan with each protect() call
decision = await aj.protect(request, sensitive_info_value="User input to scan")
```

You can supplement built-in detectors with a custom `detect` callback:

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

### On-device Rampart backend (more entity types)

The default backend detects the four types above. To detect names, addresses,
and government/financial identifiers, install the optional
`arcjet[sensitive-info-rampart]` extra and pass its `backend` to the rule. It
runs the on-device [Rampart](https://huggingface.co/nationaldesignstudio/rampart)
NER model entirely locally, so no data leaves your environment:

```sh
pip install "arcjet[sensitive-info-rampart]"
```

```py
from arcjet import arcjet, detect_sensitive_info, Mode
from arcjet_sensitive_info_rampart import rampart

aj = arcjet(
    key=arcjet_key,
    rules=[
        detect_sensitive_info(
            mode=Mode.LIVE,
            deny=["EMAIL", "GIVEN_NAME", "SURNAME", "STREET_NAME", "SSN"],
            backend=rampart(),
        ),
    ],
)
```

The backend adds these entity types: `GIVEN_NAME`, `SURNAME`, `SSN`, `URL`,
`TAX_ID`, `BANK_ACCOUNT`, `ROUTING_NUMBER`, `GOVERNMENT_ID`, `PASSPORT`,
`DRIVERS_LICENSE`, `BUILDING_NUMBER`, `STREET_NAME`, `SECONDARY_ADDRESS`,
`CITY`, `STATE`, `ZIP_CODE`. Listing one of these **without** a supporting
`backend` (or a custom `detect` function) raises, since the default engine can
never match it. The bundled model loads once on first use and is reused for
every request. See the
[`arcjet-sensitive-info-rampart` README](./sensitive-info-rampart/README.md) and
the [`examples/fastapi-rampart`](./examples/fastapi-rampart) example.

See the [Sensitive Information docs](https://docs.arcjet.com/sensitive-info) for
more details.

## Shield WAF

Protect against common web attacks including SQL injection, XSS, path
traversal, and other OWASP Top 10 threats. No additional configuration
needed — Shield analyzes request patterns automatically.

```py
from arcjet import arcjet, shield, Mode

aj = arcjet(
    key=arcjet_key,
    rules=[
        shield(mode=Mode.LIVE),
    ],
)
```

See the [Shield docs](https://docs.arcjet.com/shield) for more details.

## Email validation

Prevent users from signing up with disposable, invalid, or undeliverable email
addresses. Deny types: `DISPOSABLE`, `FREE`, `INVALID`, `NO_MX_RECORDS`,
`NO_GRAVATAR`.

```py
from arcjet import arcjet, validate_email, EmailType, Mode

aj = arcjet(
    key=arcjet_key,
    rules=[
        validate_email(
            mode=Mode.LIVE,
            deny=[
                EmailType.DISPOSABLE,
                EmailType.INVALID,
                EmailType.NO_MX_RECORDS,
            ],
        ),
    ],
)

# Pass the email with each protect() call
decision = await aj.protect(request, email="user@example.com")
```

See the [Email Validation docs](https://docs.arcjet.com/email-validation) for
more details.

## Request filters

Filter requests using expression-based rules against request properties (IP
address, headers, path, HTTP method, and custom local fields).

### Block by country

Restrict access to specific countries — useful for licensing, compliance, or
regional rollouts. The `allow` list denies all countries not listed:

```py
from arcjet import arcjet, filter_request, Mode

aj = arcjet(
    key=arcjet_key,
    rules=[
        # Allow only US traffic — all other countries are denied
        filter_request(
            mode=Mode.LIVE,
            allow=['ip.src.country eq "US"'],
        ),
    ],
)

@app.get("/")
async def index(request: Request):
    decision = await aj.protect(request)

    if decision.is_denied():
        return JSONResponse({"error": "Access restricted in your region"}, status_code=403)
```

To restrict to a specific state or province, combine country and region:

```py
filter_request(
    mode=Mode.LIVE,
    # Allow only California — useful for state-level compliance e.g. CCPA testing
    allow=['ip.src.country eq "US" and ip.src.region eq "California"'],
)
```

### Block VPN and proxy traffic

Prevent anonymized traffic from accessing sensitive endpoints — useful for
fraud prevention, enforcing geo-restrictions, and reducing abuse:

```py
from arcjet import arcjet, filter_request, Mode

aj = arcjet(
    key=arcjet_key,
    rules=[
        filter_request(
            mode=Mode.LIVE,
            deny=[
                "ip.src.vpn",    # VPN services
                "ip.src.proxy",  # Open proxies
                "ip.src.tor",    # Tor exit nodes
            ],
        ),
    ],
)
```

For cases where you want to allow some anonymized traffic (e.g. Apple Private
Relay) but still log or handle it differently, use `decision.ip` helpers after
calling `protect()`:

```py
decision = await aj.protect(request)

if decision.ip.is_vpn() or decision.ip.is_tor():
    return JSONResponse({"error": "VPN traffic not allowed"}, status_code=403)

ip = decision.ip_details
if ip and ip.is_relay:
    # Privacy relay (e.g. Apple Private Relay) — lower risk than a VPN
    pass  # allow through with custom handling
```

### Custom local fields

Pass arbitrary values from your application for use in filter expressions:

```py
decision = await aj.protect(
    request,
    filter_local={"userId": current_user.id, "plan": current_user.plan},
)
```

These are then available as `local.userId` and `local.plan` in expressions:

```py
filter_request(
    mode=Mode.LIVE,
    deny=['local.plan eq "free" and ip.src.country ne "US"'],
)
```

See the [Request Filters docs](https://docs.arcjet.com/filters),
[IP Geolocation blueprint](https://docs.arcjet.com/blueprints/ip-geolocation),
and [VPN/Proxy Detection blueprint](https://docs.arcjet.com/blueprints/vpn-proxy-detection)
for more details.

## IP analysis

Arcjet returns IP metadata with every decision — no extra API calls needed.

```py
# High-level helpers
if decision.ip.is_hosting():
    # likely a cloud/hosting provider — often suspicious for bots
    return JSONResponse({"error": "Hosting IP blocked"}, status_code=403)

if decision.ip.is_vpn() or decision.ip.is_proxy() or decision.ip.is_tor():
    # apply your policy for anonymized traffic
    pass

# Typed field access
ip = decision.ip_details
if ip:
    print(ip.city, ip.country_name)   # geolocation
    print(ip.asn, ip.asn_name)        # ASN / network
    print(ip.is_vpn, ip.is_hosting)   # reputation
    if ip.threat:                     # optional threat intelligence
        threat = ip.threat
        print(threat.risk_level, threat.confidence, threat.reputation)
        print(threat.is_safe, threat.network_types, threat.activities)
        print(threat.entities, threat.entity_name, threat.service)
```

Available fields include geolocation (`latitude`, `longitude`, `city`,
`region`, `country`, `continent`), network (`asn`, `asn_name`, `asn_domain`,
`asn_type`, `asn_country`), and reputation (`is_vpn`, `is_proxy`, `is_tor`,
`is_hosting`, `is_relay`). Threat intelligence provides `risk_level`,
`confidence`, `reputation`, `is_safe`, `network_types`, `activities`,
`entities`, `entity_name`, and `service`.

`decision.ip_details` and its `threat` field are optional because metadata or
threat intelligence may not be available for every IP.

## LangChain example

Arcjet works with any Python code, including LangChain agents and chains. In this
example, we protect a LangChain agent's chat endpoint with Arcjet to prevent
prompt injection, block bots, prevent sensitive data leakage, and enforce token
budgets before invoking the agent.

### FastAPI + LangChain

```py
from arcjet import arcjet, detect_bot, detect_prompt_injection, detect_sensitive_info, token_bucket, Mode, SensitiveInfoEntityType

aj = arcjet(
    key=arcjet_key,
    rules=[
        detect_prompt_injection(mode=Mode.LIVE),
        detect_sensitive_info(
            mode=Mode.LIVE,
            deny=[
                SensitiveInfoEntityType.EMAIL,
                SensitiveInfoEntityType.CREDIT_CARD_NUMBER,
                SensitiveInfoEntityType.PHONE_NUMBER,
            ],
        ),
        detect_bot(mode=Mode.LIVE, allow=["CURL"]),
        token_bucket(characteristics=["userId"], mode=Mode.LIVE, refill_rate=5, interval=10, capacity=10),
    ],
)

@app.post("/chat")
async def chat(request: Request, body: ChatRequest):
    decision = await aj.protect(
        request,
        requested=5,
        characteristics={"userId": "user_123"},
        detect_prompt_injection_message=body.message,  # scan for prompt injection
        sensitive_info_value=body.message,  # scan for PII before sending to LLM
    )

    if decision.is_denied():
        status = 429 if decision.reason_v2.type == "RATE_LIMIT" else 403
        return JSONResponse({"error": "Denied"}, status_code=status)

    reply = await chain.ainvoke({"message": body.message})
    return {"reply": reply}
```

### Flask + LangChain

```py
from arcjet import arcjet_sync, detect_bot, detect_prompt_injection, detect_sensitive_info, token_bucket, Mode, SensitiveInfoEntityType

aj = arcjet_sync(
    key=arcjet_key,
    rules=[
        detect_prompt_injection(mode=Mode.LIVE),
        detect_sensitive_info(
            mode=Mode.LIVE,
            deny=[
                SensitiveInfoEntityType.EMAIL,
                SensitiveInfoEntityType.CREDIT_CARD_NUMBER,
                SensitiveInfoEntityType.PHONE_NUMBER,
            ],
        ),
        detect_bot(mode=Mode.LIVE, allow=["CURL"]),
        token_bucket(characteristics=["userId"], mode=Mode.LIVE, refill_rate=5, interval=10, capacity=10),
    ],
)

@app.post("/chat")
def chat():
    body = request.get_json()
    message = body.get("message", "") if body else ""

    decision = aj.protect(
        request,
        requested=5,
        characteristics={"userId": "user_123"},
        detect_prompt_injection_message=message,  # scan for prompt injection
        sensitive_info_value=message,  # scan for PII before sending to LLM
    )

    if decision.is_denied():
        status = 429 if decision.reason_v2.type == "RATE_LIMIT" else 403
        return jsonify(error="Denied"), status

    reply = chain.invoke({"message": message})
    return jsonify(reply=reply)
```

## Arcjet Guard

`arcjet.guard` is a lower-level API designed for AI agent tool calls and
background tasks where there is no HTTP request object. It gives you
fine-grained, per-call control over rate limiting, prompt injection detection,
content moderation, sensitive information detection, and custom rules.

### How it differs from `arcjet` / `arcjet_sync`

| | `arcjet` / `arcjet_sync` | `arcjet.guard` |
| --- | --- | --- |
| **Designed for** | HTTP request protection | AI agent tool calls, background jobs |
| **Request object** | Required (`protect(request, ...)`) | Not needed |
| **Rule binding** | Rules configured once, input via `protect()` kwargs | Rules configured as classes, called with input per invocation |
| **Rate limit key** | IP or `characteristics` dict | Explicit `key` string (SHA-256 hashed before sending) |
| **Custom rules** | Not supported | `LocalCustomRule` with typed config/input/data |

### Installation

`arcjet.guard` is included in the `arcjet` package — no extra install required.

### Quick start

```py
import os
from arcjet.guard import (
    launch_arcjet,       # async — use launch_arcjet_sync for sync frameworks
    TokenBucket,
    DetectPromptInjection,
    ModerateContent,
    LocalDetectSensitiveInfo,
)

arcjet_key = os.getenv("ARCJET_KEY")
if not arcjet_key:
    raise RuntimeError("ARCJET_KEY is required")

# Create a single guard client and reuse it.
aj = launch_arcjet(key=arcjet_key)

# Configure rules once at startup
user_limit = TokenBucket(
    refill_rate=100,
    interval_seconds=60,
    max_tokens=1000,
)
prompt_scan = DetectPromptInjection()
moderate = ModerateContent()
sensitive = LocalDetectSensitiveInfo(deny=["EMAIL", "CREDIT_CARD_NUMBER"])

# At call time, bind input and guard
async def handle_tool_call(user_id: str, message: str):
    decision = await aj.guard(
        label="tools.weather",
        rules=[
            user_limit(key=user_id, requested=5),
            prompt_scan(message),
            moderate(message),
            sensitive(message),
        ],
    )

    if decision.conclusion == "DENY":
        raise RuntimeError(f"Blocked: {decision.reason}")

    if decision.has_failed_open():
        raise RuntimeError("Guard unavailable; refusing to run the tool")

    # Allowed by a fully evaluated policy; safe to proceed.
```

### Remotely configured policy inputs

Map application values explicitly as server-visible or local. Server inputs are
evaluated and retained as policy evidence. Local strings remain in SDK memory;
only a correlation digest and local-rule attestation are sent.

```py
from arcjet.guard import local_input, server_input

decision = await aj.guard(
    label="email.sent",
    actor=user_id,
    inputs={
        "recipient": server_input.string(to),
        "subject": local_input.string(subject),
        "content": server_input.string(body),
    },
)

print(decision.policy_evaluation, decision.policy_results)
```

Rules are optional. Passing no rules (or ``rules=[]``) still calls Guard and
sends the label, actor, and policy inputs, so a remotely configured policy can
protect the action. An empty rules list does not mean “allow without checking.”
When a local input triggers an enforced remote-policy rule, the SDK omits raw
and server-exposed policy inputs and sends only privacy-safe local evidence to
Guard. Guard records and returns the final decision and decision ID.

### LangChain tool checkpoints

Install the optional integration with `pip install "arcjet[langchain]"`, then
wrap a tool immediately before execution:

```py
from arcjet.guard import local_input, server_input
from arcjet.guard.langchain import guard_tool

guarded_send_email = guard_tool(
    guard=aj,
    tool=send_email_tool,
    action="email.sent",
    on_guard_error="deny",  # default — blocks if Guard is unavailable
    actor=lambda config: config["configurable"]["user_id"],
    inputs=lambda arguments, _config: {
        "recipient": server_input.string(arguments["to"]),
        "subject": local_input.string(arguments["subject"]),
        "content": server_input.string(arguments["body"]),
    },
)
```

The guarded tool advertises the same schema as the tool it wraps and delegates
to it, so the model is told what it would have been told without the guard.
Every way of calling the tool is a checkpoint — `invoke()`, `ainvoke()`,
`run()`, `arun()`, streaming and batching, and the tool's own `func` — and each
call is evaluated exactly once. LangChain normalizes a call before the
checkpoint reads it, so a policy resolver sees the config the tool runs with,
including one a chain passed down without the caller re-threading it.

The guarded tool is an instance of the wrapped tool's class, so application code
and LangChain itself keep taking the same branch when they check a tool's
concrete type. It is a generated subclass, created once per tool class and kept
for the life of the process: a tool class that hooks `__init_subclass__` to
register or validate its subclasses sees that subclass once, at the first
`guard_tool()` call for it, and a registry keyed by class name gains an entry
for it. A trace still shows the tool's own `name`; it is `repr()` and the class
name that show `ArcjetGuarded<ClassName>`.

A tool that keeps its own state under one of the names the guard uses for its
own — `_arcjet_state` — is refused by `guard_tool()`,
because a guarded tool is an instance of the tool's class and there is nowhere
else for either to live. Rename the tool's attribute.

A blocked call is reported to the tool's callbacks the way LangChain reports the
outcome: a denial the tool's `handle_tool_error` converts is a run that ends
with the handled content, and anything else is a start followed by an error. So
a blocked call appears on a trace rather than leaving a gap, and a handled
denial is not counted as a failure. What the handler returns is formatted by
LangChain's own code, so a denial reaches the model shaped exactly as the tool's
own error would have been.

If a resolver fails, Guard still sees the call — the decision is made without
that input rather than not made at all — and `on_guard_error` decides whether
the call may run.

Configure the tool before you guard it. The guarded tool carries a copy of the
tool's state, but the wrapped tool is what executes, so anything you change on
the guarded tool afterwards does not reach the call — `callbacks`, `tags`,
`handle_tool_error`, `args_schema`, `response_format`, and any other field. A
blocked call is reported from the wrapped tool too, so allowed and blocked
calls agree with each other.

The same applies to a method: if the tool's class has a helper that configures
it — `bind_user()`, say — calling that on the guarded tool sets the value on
the guarded tool, and the wrapped tool still runs without it. Call it before
guarding, or call it on the tool you still hold.

`response_format` is worth calling out because ignoring it does more than
nothing: a tool that returns `(content, artifact)` runs with the wrapped tool's
format, so the tuple is JSON-encoded into the message content and the artifact
is dropped.

`args_schema` follows that same rule, which matters if you want to hide an
argument from the model. Narrow the tool **before** you guard it, so the
wrapped tool parses against the narrow schema and the hidden argument is
discarded rather than reaching the tool body. Narrowing the guarded tool
instead changes nothing at all, because every schema question is answered by
the tool it wraps.

```py
class PublicEmailArgs(BaseModel):
    to: str  # `internal_note` is deliberately absent

send_email_tool.args_schema = PublicEmailArgs  # narrow first, then guard
guarded_send_email = guard_tool(
    guard=aj, tool=send_email_tool, action="email.sent"
)
```

Note that "discarded" is not "rejected": pydantic ignores an unknown field by
default, so a caller that sends `internal_note` anyway gets a successful call
with the field dropped, not an error. To reject it, give the narrow schema
`model_config = ConfigDict(extra="forbid")`, or bind a rule to the argument.

Narrow before guarding for the same reason you configure before guarding:
changing the wrapped tool's schema afterwards leaves the two disagreeing about
what to advertise, for a tool built with `Tool(...)` and no schema of its own.

> [!WARNING]
> Pickle executes arbitrary code as it loads. Load a pickled tool only from a
> source you control — your own worker queue or process pool — and never from a
> user, a network peer, or shared storage anyone else can write to. A guarded
> tool is not a safe transport format for untrusted input, and the checkpoint
> does not protect the load: the code runs before any rule does.

A guarded tool can be pickled if the tool it wraps can and its resolvers can,
which is what sending tools to a worker process needs. Fields set on the
guarded tool survive the round trip. Resolvers are pickled as you gave them, so
a lambda or a closure makes the tool unpicklable — use a module-level function
if the tool has to cross a process boundary. The client is not pickled with it
— it cannot cross a process boundary, and pickling it would write your site key
into whatever the pickle is stored in — so call `register_arcjet()` in the
receiving process before loading the tool.

The core `guard()` API and the LangChain helper have intentionally different
defaults when evaluation is unavailable:

| API | Default when Guard is unavailable | How to change it |
| --- | --- | --- |
| `guard()` (core) | Allow (fail open), with `has_failed_open()` returning `True` | Gate manually on `has_failed_open()` |
| `guard_tool()` | Block (fail closed) | Set `on_guard_error="allow"` |

For `guard_tool()`, unavailable means either that the pre-execution checkpoint
raised while resolving the actor or policy inputs, or calling Guard, or that
Guard returned an `ALLOW` decision whose
`has_failed_open()` is `True`. The latter can result from a deadline, response
parse failure, local rule failure, missing decision, or server-returned rule
error—not only an Arcjet Cloud outage.

With the default `on_guard_error="deny"`, the wrapped tool does not execute and
`ArcjetToolUnavailableError` is raised. This is distinct from
`ArcjetToolDeniedError`, which represents a real `DENY` decision and carries
that decision. Handle an unavailable evaluation as an operational failure that
may warrant alerting or retrying; do not treat it as a policy denial. Set
`on_guard_error="allow"` only at call sites where availability matters more
than enforcement, such as a read-only lookup.

### Sync usage

For Flask, Django, or other sync frameworks, use `launch_arcjet_sync`:

```py
from arcjet.guard import launch_arcjet_sync, TokenBucket

aj = launch_arcjet_sync(key=arcjet_key)
user_limit = TokenBucket(refill_rate=10, interval_seconds=60, max_tokens=100)

def handle_tool_call(user_id: str):
    decision = aj.guard(
        label="tools.weather",
        rules=[user_limit(key=user_id)],
    )

    if decision.conclusion == "DENY":
        raise RuntimeError("Rate limited")

    if decision.has_failed_open():
        raise RuntimeError("Guard unavailable; refusing to run the tool")
```

### Rate limiting

Token bucket, fixed window, and sliding window algorithms are available.
Configure the rule once, then call it with a `key` (and optional `requested`
token count) for each invocation:

#### Token bucket

```py
from arcjet.guard import TokenBucket

user_limit = TokenBucket(
    refill_rate=100,      # tokens added per interval
    interval_seconds=60,  # seconds between refills
    max_tokens=1000,      # maximum bucket capacity
)

# At call time:
decision = await aj.guard(
    label="tools.weather",
    rules=[user_limit(key=user_id, requested=5)],
)
```

#### Fixed window

```py
from arcjet.guard import FixedWindow

team_limit = FixedWindow(
    max_requests=1000,
    window_seconds=3600,
)

decision = await aj.guard(
    label="api.search",
    rules=[team_limit(key=team_id)],
)
```

#### Sliding window

```py
from arcjet.guard import SlidingWindow

api_limit = SlidingWindow(
    max_requests=500,
    interval_seconds=60,
)

decision = await aj.guard(
    label="api.query",
    rules=[api_limit(key=user_id)],
)
```

### Prompt injection detection

```py
from arcjet.guard import DetectPromptInjection

prompt_scan = DetectPromptInjection()

decision = await aj.guard(
    label="tools.weather",
    rules=[prompt_scan(user_message)],
)

if decision.conclusion == "DENY":
    print("Prompt injection detected")

result = prompt_scan.result(decision)
if result and result.billing:
    print(result.billing.unit, result.billing.count)
```

Guard billing is optional. Prompt injection usage is reported in `tokens`,
while content moderation usage is reported in `text_units` (text chunks), so
always inspect `billing.unit` rather than assuming the unit.

### Content moderation

```py
from arcjet.guard import ModerateContent

moderate = ModerateContent()

decision = await aj.guard(
    label="tools.chat",
    rules=[moderate(user_message)],
)

if decision.conclusion == "DENY":
    print("Harmful content detected")

result = moderate.result(decision)
if result:
    print(result.detected)
    if result.billing:
        print(result.billing.unit, result.billing.count)
```

`experimental_ModerateContent` remains as a deprecated alias for
`ModerateContent`.

The result reports `detected` and optional `billing` only — not per-category
scores.

### Sensitive information detection

Detects PII locally — the raw text never leaves the SDK. The default backend
detects `EMAIL`, `PHONE_NUMBER`, `IP_ADDRESS`, `CREDIT_CARD_NUMBER`.

```py
from arcjet.guard import LocalDetectSensitiveInfo

sensitive = LocalDetectSensitiveInfo(
    deny=["EMAIL", "CREDIT_CARD_NUMBER"],
)

decision = await aj.guard(
    label="tools.send_email",
    rules=[sensitive(user_input)],
)
```

For additional entity types (names, addresses, SSN, etc.), install
`arcjet[sensitive-info-rampart]` and pass the on-device Rampart `backend`:

```py
from arcjet.guard import LocalDetectSensitiveInfo
from arcjet_sensitive_info_rampart import rampart

sensitive = LocalDetectSensitiveInfo(deny=["GIVEN_NAME", "SSN"], backend=rampart())
```

Listing a backend-only type without a supporting `backend` raises.

### Custom rules

Define typed custom rules that run locally. Subclass `LocalCustomRule` and
override `evaluate` (sync) or `evaluate_async` (async):

```py
from typing import TypedDict
from arcjet.guard import LocalCustomRule, CustomEvaluateResult

class TopicConfig(TypedDict):
    blocked_topic: str

class TopicInput(TypedDict):
    topic: str

class TopicData(TypedDict):
    matched: str

class TopicBlockRule(LocalCustomRule[TopicConfig, TopicInput, TopicData]):
    def evaluate(
        self,
        config: TopicConfig,
        input: TopicInput,
    ) -> CustomEvaluateResult:
        if input["topic"] == config["blocked_topic"]:
            return CustomEvaluateResult(
                conclusion="DENY",
                data={"matched": input["topic"]},
            )
        return CustomEvaluateResult(conclusion="ALLOW")

rule = TopicBlockRule(config={"blocked_topic": "weapons"})
inp = rule(data={"topic": user_topic})
decision = await aj.guard(rules=[inp], label="content")

# Access typed result
r = inp.result(decision)
if r and r.conclusion == "DENY":
    print(f"Blocked topic: {r.data['matched']}")
```

### Per-rule results

Both the configured rule and the bound input provide typed result accessors:

```py
user_limit = TokenBucket(refill_rate=10, interval_seconds=60, max_tokens=100)
inp = user_limit(key=user_id, requested=5)

decision = await aj.guard(label="tools.weather", rules=[inp])

# From the bound input (matches exact invocation)
r = inp.result(decision)
if r:
    print(r.remaining_tokens, r.max_tokens)

# From the configured rule (matches all invocations of this rule)
r = user_limit.result(decision)

# Check only denied results
denied = inp.denied_result(decision)
if denied:
    print(f"Rate limited — resets at {denied.reset_at_unix_seconds}")
```

### Decision API

```py
decision = await aj.guard(label="tools.weather", rules=[...])

# Layer 1: conclusion and reason
decision.conclusion   # "ALLOW" or "DENY"
decision.reason       # "RATE_LIMIT", "PROMPT_INJECTION", "MODERATE_CONTENT", "SENSITIVE_INFO", "CUSTOM", "ERROR", etc.

# Layer 2: error/warning detection
decision.has_failed_open()  # True if ALLOW only because a rule/decision could not be processed (fail-closed gate)
decision.error_results()  # Results that errored (rules or the decision that could not be processed)
decision.warnings           # Decision-level diagnostics (e.g. an invalid metadata key that was stripped)

# Layer 3: per-rule results (see "Per-rule results" above)
for result in decision.results:
    print(result.type, result.conclusion)
```

### `guard()` parameter reference

| Parameter   | Type                      | Description |
| ----------- | ------------------------- | ----------- |
| `rules`     | `Sequence[RuleWithInput]` | Bound SDK rule inputs (optional; defaults to empty for policy-only calls) |
| `label`     | `str`                     | Label identifying this guard call (required) |
| `actor`     | `str \| None`             | Actor used by remote policy selection/evaluation |
| `inputs`    | `PolicyInputMap \| None`  | Typed server-visible or local remote-policy inputs |
| `metadata`  | `Metadata \| None`        | Structured metadata — see [Metadata](#metadata) |
| `correlation_id` | `str \| None`       | Opaque id correlating this call with other `guard()`/`protect()` calls |

### Metadata

`guard()`, `protect()`, and every guard rule accept `metadata`: a mapping of
string keys to **any JSON-serializable value**, including nested objects and
arrays. It is attached to the decision for correlation and analytics.

```py
decision = await aj.guard(
    label="tools.weather",
    rules=[user_limit(key=user_id)],
    metadata={
        "user": {"id": user_id, "plan": "pro"},
        "tool_name": "get_weather",
        "duration_ms": 160,
        "success": True,
    },
)
```

Each top-level value is JSON-encoded by the SDK and stored verbatim, so exact
integers and value formatting survive. Server-enforced limits:

| Limit                    | Value    | Over the limit          |
| ------------------------ | -------- | ----------------------- |
| Top-level keys           | 128      | Extra keys dropped      |
| Serialized bytes / value | 4 KiB    | That key dropped        |
| Nesting depth / value    | 10       | That key dropped        |
| Key names                | letters, digits, `-`, `.`, `_` | That key dropped |

Nothing here can fail a call or change a decision — metadata is excluded from
fingerprinting and from the decision cache key. Every dropped key is reported:
server-side drops arrive on `decision.warnings`, one per key. Keys the SDK itself
could not encode (a `datetime`, a set, `NaN`, a circular reference) are collected
into a single warning naming them all, added to `decision.warnings` and reported
to the server. For `protect()`, which has no warnings channel on its `Decision`,
that warning is logged at `WARNING` instead.

Metadata is untrusted and is not redacted — do not put secrets or PII in it.

Some limits are the SDK's own, not the server's. The SDK drops keys once one
request's metadata exceeds 768 KiB in total (keys plus JSON-encoded values,
counted before compression). That ceiling sits well above anything the server
would accept — its own caps allow roughly 512 KiB in a single map — and exists
only so oversized metadata cannot push a request past the 1 MiB protocol limit,
where it would be rejected outright and fail open.

Two behaviours differ between the Python and JavaScript SDKs:

- **Integer precision.** Python integers are arbitrary-precision and are sent
  verbatim, so a value past 2^53 survives exactly. The JavaScript SDK cannot do
  this — its numbers are IEEE-754 doubles before they reach the wire — so send
  such values as strings if both SDKs must agree.
- **Objects with a `toJSON()` method**, including JavaScript `Date`, are
  serialized by that method in the JS SDK. Python has no equivalent protocol, so
  a `datetime` (or any other non-JSON type) is dropped with a warning. Convert
  explicitly — `datetime.isoformat()` — if both SDKs must agree.

Rule-level metadata is merged with `guard()`-level metadata shallowly: a
duplicate key's whole value is replaced, never deep-merged.


### DRY_RUN mode

All guard rules accept a `mode` parameter. Use `"DRY_RUN"` to evaluate rules
without blocking:

```py
user_limit = TokenBucket(
    refill_rate=10,
    interval_seconds=60,
    max_tokens=100,
    mode="DRY_RUN",
)
```

### Recording what happened with `capture()`

`guard()` decides whether something is allowed. `capture()` records that it
happened. Use it for the actions you want to see in a security trace but do not
want to gate — a refund issued, a document exported, a tool call completed.

```py
decision = await aj.guard(label="refund", rules=[inp])
if decision.conclusion == "ALLOW":
    refund_id = issue_refund(...)

    aj.capture(
        action="refund.issued",
        correlation_id=workflow_id,   # ties this to other calls in the workflow
        decision_id=decision.id,      # ties it to the decision above
        metadata={"amount_cents": 4999, "invoice": {"id": "inv_123"}},
    )
```

`capture()` returns immediately and is not awaited, even on the async client.
Events are queued and sent in the background, batched together.

It is **best-effort and never affects a decision**:

- It never raises. A bad field is dropped and the rest of the event is sent; an
  event with no usable `action` is dropped entirely.
- Under sustained load or a failing backend, events are dropped rather than
  slowing your request down. A failed send is never retried.
- Nothing is dropped silently. Drops are reported through the `arcjet` logger
  with a stable code — `AJ3001` (queue full), `AJ3002` (send failed), `AJ3003`
  (flush deadline). The `arcjet` logger is already at `WARNING`, so you only
  need to attach a handler to see them.

  Repeats of the same code are coalesced for a minute and the suppressed count
  is reported with the next line for that code, or by the next `flush()`. A
  burst that ends without either will under-report its total — the figure is a
  count of events seen, not a guaranteed total.

  Pass your own logger to receive **every** diagnostic uncoalesced, which is what
  you need to keep a metric of dropped events:

  ```py
  aj = launch_arcjet_sync(key=arcjet_key, logger=my_logger)
  ```

  Each record carries `code` and `count` attributes alongside the message, so a
  handler can route or count on them without parsing text.

Do not put secrets or PII in `metadata`; it is stored as untrusted data.

#### Delivering events before shutdown

Delivery is asynchronous, so events queued as your process exits may never be
sent — the sync worker is a daemon thread and will not hold the interpreter
open. Call `flush()` at a shutdown point:

```py
# Async (FastAPI lifespan, or any async teardown)
await aj.flush()

# Sync (Flask teardown, atexit, or the end of a script)
arcjet_sync_guard.flush()
```

`flush()` waits up to `timeout_ms` (default 1000) for the events outstanding
when you called it. On expiry, queued events are dropped and a request already
on the wire is abandoned — not cancelled, so it may still arrive, and nothing
will tell you either way. Both are counted in the `AJ3003` report.

Events captured *while* a flush is waiting are not its responsibility and
survive its deadline, so calling `flush()` per request in a concurrent server
cannot discard another request's telemetry.

There is no `close()`: a client holds no connection of its own to release, so
flushing is the only shutdown step that changes what gets delivered.

### Registering a client (optional)

Passing the client explicitly is the recommended path, and everything above does
exactly that. Registration is a shortcut for the case it cannot cover: code too
deep in an application to be handed a client, where `capture()` is often most
useful.

`launch_arcjet()` never touches global state. Registering is always a separate,
explicit call:

```python
# wherever your application starts up
import os

from arcjet.guard import launch_arcjet, register_arcjet

register_arcjet(launch_arcjet(key=os.environ["ARCJET_KEY"]))
```

`capture()` is then importable on its own and reaches the registered client:

```python
# deep in application code — nothing was passed down here
from arcjet.guard import capture


async def refund(invoice_id: str) -> None:
    await issue_refund(invoice_id)
    capture(action="refund.issued", metadata={"invoice": invoice_id})
```

#### Sync and async

`capture()` is one function for both client flavors, because it queues and
returns on each of them. `guard()` and `flush()` cannot be, so they come in
pairs matching `launch_arcjet` / `launch_arcjet_sync`:

| Registered client | Guard | Flush |
| --- | --- | --- |
| `launch_arcjet()` | `await guard(...)` | `await flush()` |
| `launch_arcjet_sync()` | `guard_sync(...)` | `flush_sync()` |

Registration accepts either and does not record which, so calling the wrong one
is not something a type checker can catch. It fails open and reports `AJ3007` on
the registered client's logger.

#### What happens with nothing registered

`guard()` and `guard_sync()` return a fail-open `ALLOW` carrying an error
result, so a caller that inspects the decision can see that no policy ran. They
do not raise.

```python
decision = await guard([limit(key=user_id)], label="refund")

if decision.has_failed_open():
    # No rule was evaluated. Treat this as "policy did not run", not as a pass.
    ...
```

`capture()` drops the event silently, and the `flush()` variants return.
Nothing is logged: the client that would have carried a logger is the thing
that is missing, so the only available sink would be an unconfigurable warning
on a request path.

#### Registering twice, and unregistering

Registration is guarded. A second client does not displace the first — the
attempt is reported as `AJ3004` on the **incumbent's** logger, so a library or a
stray second `launch_arcjet()` cannot quietly redirect an application's
telemetry to a different key. Registering the client that is already registered
is a silent no-op.

`unregister_arcjet()` takes no argument and clears whatever is there. The cost
is that anything calling it clears the application's client and every free call
afterwards fails open, so **libraries should not call it** — they take a client
explicitly. That is a convention, not something the SDK enforces.

The registration is a module-level global, so it is visible from every thread
and every event loop. It is deliberately *not* a `contextvars.ContextVar`: a
context variable set at startup is invisible inside worker threads, which is
exactly how Flask, Django and other WSGI servers run request handlers, so
registration would appear to work in development and silently do nothing in
production.

### Testing

`arcjet.guard.testing` registers an in-memory client that records calls and
talks to nothing:

```python
from arcjet.guard import capture
from arcjet.guard.testing import register_test_client


async def test_refund_captures_an_event():
    with register_test_client() as arcjet:
        await refund("inv_1")

        assert arcjet.captures[0].action == "refund.issued"
```

The `with` block unregisters the client on the way out, including when the test
fails part-way through. Note the `await`: the capture happens wherever the code
under test reaches it, so a test that forgets to await an async function asserts
before the event exists.

Usually this belongs in a fixture:

```python
import pytest
from arcjet.guard.testing import register_test_client


@pytest.fixture
def arcjet():
    with register_test_client() as client:
        yield client
```

`register_test_client()` raises if a client is already registered, which
surfaces a leak from an earlier test rather than letting this one assert against
the wrong recorder. `unregister()` is also available for teardown that cannot
use `with`, and only clears the registration if it is still this client.

Each recorded capture goes through the same validation and metadata encoding as
a real `capture()`, so a call the real client would drop is not recorded here
either, and anything the SDK rewrote is on `capture.warnings`. Recording itself
is synchronous — once the code under test reaches `capture()`, the event is
there with no flushing or waiting.

The test client answers both `guard()` and `guard_sync()`, so it does not care
which flavor your application uses. It records the call and returns a fail-open
`ALLOW`, because no rule actually ran. It is not a mock server and does not let
you stub per-rule verdicts.

`guard_tool()` accepts it too — it identifies a client by the shape of its
`guard()`, not by its class. Because the recorder answers a fail-open decision,
pass `on_guard_error="allow"` unless the test is asserting the denial.

## Best practices

### Single-instance pattern

Create one Arcjet client at startup and reuse it across all requests:

```py
# Good — one instance, created once at startup
aj = arcjet(key=arcjet_key, rules=[...])

# Bad — new instance per request wastes resources
@app.get("/")
async def index(request: Request):
    aj = arcjet(key=arcjet_key, rules=[...])  # don't do this
```

### DRY_RUN mode for testing

Use `Mode.DRY_RUN` to test rules without blocking traffic. Decisions are logged
but requests are allowed through:

```py
aj = arcjet(
    key=arcjet_key,
    rules=[
        detect_bot(mode=Mode.DRY_RUN, allow=[]),
        token_bucket(mode=Mode.DRY_RUN, refill_rate=5, interval=10, capacity=10),
    ],
)
```

### Proxy configuration

When running behind a load balancer or reverse proxy, configure trusted IPs so
Arcjet resolves the real client IP from `X-Forwarded-For`:

```py
aj = arcjet(
    key=arcjet_key,
    rules=[...],
    proxies=["10.0.0.0/8", "192.168.0.1"],
)
```

### Outbound HTTP proxy

If your environment requires outbound requests to the Arcjet API to go through a
forward proxy (e.g. Squid), set the standard proxy environment variables. The
SDK honors them automatically — no code changes required:

```sh
export HTTPS_PROXY="http://proxy.example.com:3128"
# Optional: comma-separated hosts that should bypass the proxy
export NO_PROXY="decide.arcjet.com,localhost"
```

`HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` are all supported (the lower-case
variants work too). Because the Arcjet API is reached over HTTPS, `HTTPS_PROXY`
is the relevant variable for proxying Arcjet traffic. `NO_PROXY` accepts a
comma-separated list of hostnames to bypass, or `*` to disable proxying
entirely. Since Arcjet is reached by hostname, list the hostname (e.g.
`decide.arcjet.com`) to bypass it.

### Async vs. sync client

Use `arcjet` (async) with FastAPI and other async frameworks. Use `arcjet_sync`
with Flask and other sync frameworks:

```py
from arcjet import arcjet, arcjet_sync

# Async — for FastAPI, Starlette, etc.
aj_async = arcjet(key=arcjet_key, rules=[...])
decision = await aj_async.protect(request)

# Sync — for Flask, Django, etc.
aj_sync = arcjet_sync(key=arcjet_key, rules=[...])
decision = aj_sync.protect(request)
```

### `protect()` parameter reference

All parameters are optional keyword arguments passed alongside the `request`:

| Parameter                          | Type              | Used by                  |
| ---------------------------------- | ----------------- | ------------------------ |
| `requested`                        | `int`             | Token bucket rate limit  |
| `characteristics`                  | `dict[str, Any]`  | Rate limiting (pass values for keys declared in rule config) |
| `detect_prompt_injection_message`  | `str`             | Prompt injection detection |
| `sensitive_info_value`             | `str`             | Sensitive info detection |
| `email`                            | `str`             | Email validation         |
| `filter_local`                     | `dict[str, str]`  | Request filters (`local.*` fields) |
| `metadata`                         | `Metadata`        | Structured metadata — see [Metadata](#metadata) |
| `correlation_id`                   | `str`             | Opaque id correlating this call with other `protect()`/`guard()` calls |
| `ip_src`                           | `str`             | Manual IP override (advanced) |

### Decision response

```py
decision = await aj.protect(request)

# Top-level checks
decision.is_denied()     # True if any rule denied the request
decision.is_allowed()    # True if all rules allowed the request
decision.is_error()      # True if Arcjet encountered an error (fails open)

# reason_v2.type values: "BOT", "RATE_LIMIT", "SHIELD", "EMAIL", "ERROR", "FILTER"
if decision.reason_v2.type == "RATE_LIMIT":
    print(decision.reason_v2.remaining)  # tokens/requests remaining
elif decision.reason_v2.type == "BOT":
    print(decision.reason_v2.denied)     # list of denied bot names
    print(decision.reason_v2.spoofed)    # list of spoofed bot names

# Per-rule results (for granular handling)
for result in decision.results:
    print(result.reason_v2.type, result.is_denied())
```

### Error handling

Arcjet is designed to fail open — if the service is unavailable, requests are
allowed through. Check for errors explicitly if your use case requires it:

```py
decision = await aj.protect(request)

if decision.is_error():
    # Arcjet service error — fail open or apply fallback policy
    pass
elif decision.is_denied():
    return JSONResponse({"error": "Denied"}, status_code=403)
```

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
