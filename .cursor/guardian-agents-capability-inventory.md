# Arcjet Python SDK — Guardian Agents capability inventory

**Scope:** This is a read-only inventory of what the public Python SDK repository
(`https://github.com/arcjet/arcjet-py`) actually implements. It does **not**
change product behavior.

**Not in this repo:** Arcjet Console / dashboard / cloud policy editor
(`app.arcjet.com`), the Decide/Guard backend, and other language SDKs. Those are
referenced as remote dependencies. Gartner “in-market” scoring for a *vendor*
may include cloud product; this report scores **this SDK**. Features that exist
only in Console are marked **Absent here** (cloud-dependent), not invented.

**Version inspected:** `arcjet` `0.10.0b1` (`pyproject.toml`). Latest git tag on
this tree: `v0.10.0b1`. Prior stable tag: `v0.9.0`.

**Date:** 2026-08-13.

---

## A) What this repo ships

A Python 3.10+ security SDK (`pip install arcjet` / `uv add arcjet`) with two
public surfaces:

| Surface | Factories | Purpose |
| --- | --- | --- |
| Request protection | `arcjet()` / `arcjet_sync()` | HTTP request `protect()` for FastAPI, Flask, Django, ASGI |
| Guard protection | `launch_arcjet()` / `launch_arcjet_sync()` | Non-HTTP `guard()` for agent tool calls, background jobs; optional `capture()` |

**Package extras:**

- `arcjet[langchain]` — `arcjet.guard.langchain.guard_tool`
- `arcjet[sensitive-info-rampart]` — workspace package `arcjet-sensitive-info-rampart==0.10.0b1` (on-device Rampart NER)

**Not shipped as first-class products in this repo:**

- Agent catalog, agent maps, ownership registry, lineage graph
- Tamper-evident / append-only audit log
- AI agent posture management
- MCP server SDK or MCP protocol adapter
- Django example app or framework middleware
- User-facing PII redaction API (detect/block only)
- Dedicated “tool authorization” primitive (authorization is composed from Guard policy + input constraints + app wrapping)

README marketing copy says “authorize agent tool calls, redact sensitive data”
and mentions MCP servers. The implemented SDK **detects/blocks** sensitive info
and **gates** tool calls via `guard()` / remote policy. It does **not** redact
caller text, and it has **no MCP-specific API**.

---

## B) Architecture (Guard vs request; in-process vs remote)

Two parallel clients talk to two Decide protocol versions:

```
Application
├── HTTP route (FastAPI / Flask / Django / ASGI)
│     arcjet() / arcjet_sync()
│       protect(request, ...)
│         1. coerce_request_context()
│         2. in-memory DENY cache (remote DENYs only)
│         3. local WASM (bot, email, sensitive info, filter) → LIVE DENY short-circuit
│         4. remote Decide v1alpha1 Decide RPC
│         5. fire-and-forget Report RPC on cache hit / local DENY
│
└── Tool call / job / LangChain tool (no HTTP object required)
      launch_arcjet() / launch_arcjet_sync()
        guard(label, rules?, actor?, inputs?)
          1. GetGuardPolicy (cached ~5 min) if local policy inputs present
          2. local sensitive-info (WASM or Rampart); custom rules at bind time
          3. remote Decide v2 Guard RPC
        capture(action, ...)  → batched, best-effort, never affects decisions
```

### Request path (`src/arcjet/_client.py`)

- **Transport:** Connect-RPC `Decide` + `Report` on `proto.decide.v1alpha1`
  (`src/arcjet/proto/decide/v1alpha1/decide_connect.py`).
- **Default URL:** `https://decide.arcjet.com` (or `https://fly.decide.arcjet.com`
  when `FLY_APP_NAME` is set). Override: `ARCJET_BASE_URL` / `base_url=`.
- **Timeouts:** 500 ms production, 1000 ms development; **minimum 1000 ms** if
  `detect_prompt_injection` is configured (`_default_timeout_ms`).
- **Fail-open:** `fail_open=True` by default — transport errors become ERROR
  decisions, not exceptions.
- **Local WASM** (`src/arcjet/_local.py`): bot, email, sensitive info, request
  filters. LIVE DENY short-circuits and sends a redacted Report so the
  dashboard still sees the event.
- **Always remote (no local evaluator in this SDK):** Shield WAF, rate limits
  (token/fixed/sliding), prompt injection.
- **Cache:** `DecisionCache` (`src/arcjet/_cache.py`) stores **DENY only** with
  TTL > 0. Comment: “matching JS SDK semantics.” Local DENYs bypass this cache
  (AGENTS.md known limitation).

### Guard path (`src/arcjet/guard/_client.py`)

- **Transport:** Connect-RPC `Guard`, `GetGuardPolicy`, `Capture` on
  `proto.decide.v2` (`src/arcjet/guard/proto/decide/v2/decide_connect.py`).
- **Default timeout:** 1000 ms. Fail-open ALLOW with `has_failed_open()` on
  transport/parse errors (core `guard()`); LangChain `guard_tool` fails closed
  by default.
- **Does not require an HTTP request.** Label is required. Rules are optional;
  empty rules still call Guard so a remotely configured policy can apply.
- **Local:** `LocalDetectSensitiveInfo` (raw text stays in-process; SHA-256
  sent); `LocalCustomRule` (evaluate at bind time). Remote policy can project
  local sensitive-info rules onto `local_input` strings.
- **Remote:** rate limits, prompt injection, experimental content moderation,
  input-constraint policy rules.
- **No HTTP-only rules on Guard:** no Shield, bots, email, request filters, IP
  analysis.

### In-process WASM (`src/arcjet/_analyze/`)

Bundled component: `src/arcjet/_analyze/wasm/arcjet_analyze_js_req.component.wasm`.

Exports actually wrapped (`_component.py`):

| Export | Used by shipping request/Guard path? |
| --- | --- |
| `detect-bot` | Yes — request local bot eval |
| `is-valid-email` | Yes — request local email eval |
| `detect-sensitive-info` | Yes — request + Guard local PII |
| `match-filters` | Yes — request local filters |
| `validate-characteristics` | Tests / WASM suite |
| `generate-fingerprint` | **Tests only** — request fingerprinting is server-side |

Lazy singleton with a process lock; permanent load failures latch; transient
errors retry (`_local.py`).

### Sensitive-info backends

Default: WASM (EMAIL, PHONE_NUMBER, IP_ADDRESS, CREDIT_CARD_NUMBER).
Optional: Rampart ONNX NER in-process (`sensitive-info-rampart/`). Custom
`detect` callback on the **request** rule only.

---

## C) Capability inventory with file pointers

### C.1 Public API — request

| Symbol | File |
| --- | --- |
| `arcjet`, `arcjet_sync`, `Arcjet`, `ArcjetSync` | `src/arcjet/__init__.py`, `src/arcjet/_client.py` |
| `protect()` kwargs | `requested`, `characteristics`, `email`, `sensitive_info_value`, `detect_prompt_injection_message`, `extra`, `metadata`, `filter_local`, `correlation_id`, `ip_src` |
| Framework coercion | `src/arcjet/_context.py` — ASGI/Starlette/FastAPI, Flask/Werkzeug, Django `HttpRequest` (duck-typed). **No** middleware, **no** Django example. |
| `Decision`, `RuleResult`, `is_spoofed_bot` | `src/arcjet/_decision.py` |
| `reason_v2` types | `src/arcjet/_dataclasses.py` — BOT, EMAIL, ERROR, FILTER, PROMPT_INJECTION, RATE_LIMIT, SENSITIVE_INFO, SHIELD |
| IP helpers | `decision.ip` / `decision.ip_details` / `ThreatIntelligence` |

There is **no** `with_rule` / per-call extra-rule API on the request client.

### C.2 Public API — Guard

| Symbol | File |
| --- | --- |
| `launch_arcjet`, `launch_arcjet_sync`, `ArcjetGuard`, `ArcjetGuardSync` | `src/arcjet/guard/__init__.py`, `src/arcjet/guard/_client.py` |
| `guard(rules, *, label, actor, inputs, metadata, correlation_id)` | same |
| `capture()`, `flush()` | `_client.py`, `_capture.py`, `_delivery.py` |
| Optional process-global registry | `src/arcjet/guard/_registry.py` — `register_arcjet`, free `guard`/`guard_sync`/`capture`/`flush` |
| Test client | `src/arcjet/guard/testing.py` — records calls; **cannot stub verdicts** |
| LangChain | `src/arcjet/guard/langchain.py` — `guard_tool`, `ArcjetToolDeniedError`, `ArcjetToolUnavailableError` |
| Policy inputs | `src/arcjet/guard/_policy_input.py` — `server_input.*`, `local_input.string` |

### C.3 Request rules / primitives

All builders: `src/arcjet/_rules.py`.

| Primitive | Builder | Local WASM? | Remote Decide? | Notes |
| --- | --- | --- | --- | --- |
| Shield WAF | `shield()` | No | Yes | SQLi/XSS/CSRF-style; no extra config |
| Bots | `detect_bot(allow=/deny=)` | Yes | Yes (if local allows) | Categories + named bots; `is_spoofed_bot()` |
| Token bucket | `token_bucket()` | No | Yes | `requested` cost; characteristics |
| Fixed window | `fixed_window()` | No | Yes | |
| Sliding window | `sliding_window()` | No | Yes | |
| Email | `validate_email()` | Yes | Yes | DISPOSABLE, FREE, INVALID, NO_MX_RECORDS, NO_GRAVATAR |
| Sensitive info | `detect_sensitive_info()` | Yes | Fallback if WASM missing | Detect/deny; offsets in `IdentifiedEntity`; optional `detect` callback + `backend` |
| Prompt injection | `detect_prompt_injection()` | No | Yes | Message sent **unredacted** on Decide; redacted on Report. `threshold`/`score` **deprecated** |
| Request filters | `filter_request()` | Yes | Yes | Expression language; `filter_local` redacted on wire |
| Custom rules | — | — | — | **Not on request path** (README table) |

Modes: `Mode.LIVE` / `Mode.DRY_RUN` (`src/arcjet/_enums.py`). DRY_RUN: per-rule
can be DENY but overall `is_denied()` is False.

### C.4 Guard rules / primitives

| Primitive | Class | Where it runs | File |
| --- | --- | --- | --- |
| Token bucket | `TokenBucket` | Remote (key SHA-256 hashed client-side) | `guard/_rules/_rate_limit.py` |
| Fixed window | `FixedWindow` | Remote | same |
| Sliding window | `SlidingWindow` | Remote | same |
| Prompt injection | `DetectPromptInjection` | Remote (full `input_text` on wire) | `guard/_rules/_prompt_injection.py` |
| Sensitive info | `LocalDetectSensitiveInfo` | Local; hash + result on wire | `guard/_rules/_sensitive_info.py` |
| Custom | `LocalCustomRule` | Local at bind; result maps on wire | `guard/_rules/_custom.py` |
| Content moderation | `experimental_ModerateContent` | Remote, **not wired server-side**; currently error/fail-open | `guard/_rules/_moderate_content.py` |
| Input constraints | *(no SDK builder)* | Remote policy only | result type in `guard/_types.py` |

Guard **does not** implement Shield, bots, email, filters, or IP analysis.

### C.5 Logging, decisions, “audit”

- Stdlib logger `arcjet` (`src/arcjet/_logging.py`), default WARNING via
  `ARCJET_LOG_LEVEL`. NullHandler; library does not configure app logging.
- Request `Decision.id` for dashboard correlation (`_decision.py`).
- Guard `Decision.id` is a TypeID with prefix `gdec`.
- `correlation_id` links `protect()` / `guard()` / `capture()` in one workflow.
- `metadata` is untrusted JSON for analytics; **not** redacted; excluded from
  fingerprinting and cache keys.
- Capture is **best-effort**: drops on full queue / send failure / flush
  timeout (`AJ3001`–`AJ3003`). Not a durable audit log. Comment in
  `_capture.py`: a future span path may set `source="otlp"`; **not implemented**.
- Local DENY Report redacts `sensitiveInfoValue`, `filterLocal`, and
  `detectPromptInjectionMessage`.

### C.6 Examples in this repo

| Path | What it actually does |
| --- | --- |
| `examples/fastapi/` | HTTP `protect()`: shield, bots, sensitive info, token bucket |
| `examples/flask/` | Same, sync |
| `examples/fastapi-langchain/` | HTTP chat chain + request `protect()` (not Guard, not `guard_tool`) |
| `examples/flask-langchain/` | Same, sync |
| `examples/fastapi-rampart/` | Request sensitive-info with Rampart backend |
| `examples/fastapi-guard-policy/` | LangChain agent; `guard_tool` on `send_email`; remote policy label `email.sent`; actor + server/local inputs |

**Absent examples:** MCP server, Django app, FastAPI/Flask middleware, Guard-only
background job without HTTP.

### C.7 Beta vs GA

| Item | Status in this repo |
| --- | --- |
| Package version | **`0.10.0b1` (beta)** |
| Last stable tag | `v0.9.0` |
| `experimental_ModerateContent` | Explicitly experimental; “no moderation model is wired up server-side yet” (`guard/__init__.py`) |
| Prompt injection `threshold` / `score` | Deprecated |
| `Decision.has_error()` (Guard) | Deprecated |
| Request `Reason` wrapper | Deprecated; use `reason_v2` |

---

## D) Mapping to Gartner Market Guide for Guardian Agents (G00836388)

Legend: **Native** = this SDK implements the capability in-process or via its
documented remote Decide/Guard APIs. **Partial** = related primitives exist but
do not cover the Gartner item. **Absent** = not implemented in this repo.

Gartner’s in-market bar requires **native coverage of all three mandatory
categories**. Scoring below is of **this SDK**, not the whole Arcjet vendor
cloud.

### D.1 Mandatory 1 — AI visibility and traceability

**Overall for this SDK: Partial (does not natively cover the category).**

| Sub-item | Rating | Evidence |
| --- | --- | --- |
| Agent catalog | **Absent** | No inventory, registration, or discovery of agents. `label` is a per-call slug, not a catalog. |
| Maps | **Absent** | No topology, communication map, or tool-graph visualization in the SDK. |
| Ownership + lineage | **Partial** | `actor` (string) on `guard()`; `correlation_id` across protect/guard/capture; `metadata`. No owner directory, no data/agent lineage graph. Policy evidence retained **server-side** for `server_input` values (`_policy_input.py`). |
| Tamper-evident audit trails | **Absent** | Capture is droppable and unsigned (`_capture.py`, `_delivery.py`). Decision IDs exist; no hash chain, signature, or WORM log in this SDK. Dashboard persistence is cloud, not this repo. |

What *is* present (runtime telemetry, not Gartner “visibility platform”):

- Guard `capture(action, correlation_id, decision_id, metadata)` — visibility
  events that never gate (`README.md`, `_capture.py`).
- Request Report RPC so local/cache DENYs appear in the dashboard (`_client.py`).
- Per-rule results + `reason` / `reason_v2`.
- LangChain example prints aggregate conclusion and denying rules
  (`examples/fastapi-guard-policy/`).

### D.2 Mandatory 2 — Continuous assurances (AI agent posture management)

**Overall: Absent.**

| Sub-item | Rating | Evidence |
| --- | --- | --- |
| AI agent posture management | **Absent** | No agent inventory health, misconfiguration scan, drift detection, privilege posture, or continuous control assessment of agents. Remote policy fetch (`GetGuardPolicy`, 5‑minute cache in `_remote_policy.py`) is **policy distribution**, not posture management. `Mode.DRY_RUN` is rule observation, not AAPM. |

### D.3 Mandatory 3 — Runtime inspection and enforcement

**Overall: Partial.** This is the category the SDK actually targets (inline
allow/deny before an action). It does not natively cover all three Gartner
sub-capabilities.

| Sub-item | Rating | Evidence |
| --- | --- | --- |
| Agent alignment | **Partial** | Prompt injection (request + Guard, remote). Remote policy input constraints (allow/deny strings, length, list membership, email-domain match). Custom local rules. Experimental content moderation is **not functional**. No dedicated alignment/goal-consistency engine. |
| Anomaly detection | **Partial** | Bot detection, Shield WAF, rate limits, IP threat intel (`ThreatIntelligence` on request decisions). These are abuse/WAF signals, not agent-behavior anomaly models (no baseline of “normal agent tool sequences”). |
| Runtime adaptation | **Partial / effectively Absent as Gartner means it** | LIVE vs DRY_RUN is static config. Policy refresh ~5 min and `refresh_required`. Fail-open vs LangChain fail-closed. No runtime policy mutation, no automatic privilege drop, no adaptive isolation based on detected drift. |

**Automatic blocking (runtime enforcement) is Native** for rules in LIVE mode:
`decision.is_denied()` / `decision.conclusion == "DENY"`. That is one common
feature, not the whole mandatory category.

### D.4 Common features

| Feature | Rating | Evidence |
| --- | --- | --- |
| Identity discovery | **Partial** | Request: client IP, bot identity/spoofing, ASN/geo/VPN/proxy/Tor/hosting. Guard: caller-supplied `actor` string. No agent/workload identity catalog or IdP discovery. |
| Data mapping / lineage | **Partial** | Named policy inputs; `local_input` digest; `correlation_id`; capture `decision_id`. No data-flow map or lineage store in the SDK. Sensitive-info **offsets** on request `IdentifiedEntity`; Guard public result lists entity **types** only (`RuleResultSensitiveInfo`). |
| Security testing | **Absent** (as a product) | `Mode.DRY_RUN`, `arcjet.guard.testing` (records calls, **does not simulate verdicts**). No agent red-team, prompt-attack corpus, or control-validation suite shipped as a feature. Repo unit/integration tests are engineering tests, not a customer security-testing product. |
| Risk / control validation | **Partial** | DRY_RUN; per-rule conclusions; `has_failed_open()`; policy `status` (`NOT_CONFIGURED` / `APPLIED` / `INCOMPLETE` / `UNAVAILABLE`). No control library, risk register, or attestation workflow. |
| Compliance reporting | **Absent** | No SOC2/ISO/NIST mapping, evidence export, or report generators in this SDK. Dashboard is out of repo. |
| Automatic blocking | **Native** | LIVE DENY on request `protect()` and Guard `guard()` / `guard_tool`. |
| Autoremediation | **Absent** | No revoke, quarantine, rotate, disable-agent, or auto-patch. Application must interpret DENY. |
| Continuous compliance | **Absent** | No continuous control monitoring against a compliance framework. |

---

## E) Agent / MCP / tool-call surface in detail

### E.1 What works without HTTP

`arcjet.guard` is the non-HTTP API. `guard()` requires `label` (server-validated
slug). It does **not** accept a request object. Rate-limit identity is an
explicit `key` string (hashed). This is the intended path for “AI agent tool
calls, MCP servers, background jobs” (README).

There is **no MCP protocol implementation**: no MCP SDK extra, no MCP example,
no MCP types. An MCP server author would call `guard()` around tool handlers
manually.

### E.2 Tool-call authorization (what exists)

Not a named `authorize_tool()` API. Authorization is composed:

1. **Application wraps the tool** and calls `aj.guard(...)` before side effects
   (README Guard quick start).
2. **LangChain `guard_tool`** (`src/arcjet/guard/langchain.py`): pre-execution
   checkpoint. Default `on_guard_error="deny"` (fail closed). Real DENY →
   `ArcjetToolDeniedError`; unavailable eval → `ArcjetToolUnavailableError`.
   Preserves tool schema; delegates `invoke`/`ainvoke`.
3. **Remote Guard policy** (`_remote_policy.py`): `GetGuardPolicy` by `label`;
   capabilities advertised: `guard-policy-v1`, `local-sensitive-info-v1`.
   Inputs: `server_input` (string/bool/int/number/string_list — evaluated and
   retained as evidence) vs `local_input.string` (stays in SDK; SHA-256 digest
   on wire).
4. **Input constraints** (server policy results, no local builder):
   `ALLOWED_STRING_VALUES`, `DENIED_STRING_VALUES`, `STRING_LENGTH`,
   `STRING_LIST_MEMBERSHIP`, with `EXACT` / `EMAIL_DOMAIN` match operators
   (`RuleResultInputConstraint`). Example policy in
   `examples/fastapi-guard-policy/README.md`: recipient must be in
   `allowed_recipients`.
5. **Actor** used for remote policy selection; example maps a trusted client ID
   server-side (browser cannot supply actor).

If Guard is unavailable, core `guard()` **allows** (inspect `has_failed_open()`).
`guard_tool` **blocks** unless `on_guard_error="allow"`.

### E.3 Prompt injection behavior

| Path | Input | Where evaluated | What is sent remotely |
| --- | --- | --- | --- |
| Request | `detect_prompt_injection_message=` | **Remote only** | Full message on Decide; redacted to `<redacted>` on Report |
| Guard rule | `DetectPromptInjection()(text)` | **Remote only** | Full `input_text` in GuardRuleSubmission |
| Remote policy | `server_input.string` named in Console | **Server** | Full string as policy evidence |

- Request `threshold` (0.0–1.0, default 0.5) is **deprecated**.
- `PromptInjectionReason.injection_detected` + deprecated `score`.
- Guard result: conclusion + optional `Billing` (`unit` typically `"tokens"`).
- Not local WASM. Timeout floor 1s on request client when the rule is configured.
- Example `fastapi-guard-policy` treats PI as one layer; membership + sensitive
  info are deterministic backstops because model behavior is nondeterministic.

### E.4 Sensitive info detect vs redact

**Detect and optionally DENY. No public redact API.**

- Default WASM: EMAIL, PHONE_NUMBER, IP_ADDRESS, CREDIT_CARD_NUMBER.
- Rampart extra: names, addresses, SSN, tax/bank/gov IDs, URL, etc.
  (`src/arcjet/_sensitive_info_backend.py`, `sensitive-info-rampart/README.md`).
- Request: `sensitive_info_value` evaluated locally; raw value **never** sent
  (placeholder `<redacted>`). Results include `start`/`end` offsets
  (`IdentifiedEntity`) so an app *could* redact itself — the SDK does not.
- Guard: raw text never leaves the SDK; SHA-256 + detected types. Public
  `RuleResultSensitiveInfo` has `detected_entity_types`, not offsets.
- Custom entity types: request `detect=` callback yes; Guard “custom entity
  types are not supported — use a custom rule” (`guard/_types.py`).
- README headline “redact sensitive data” is **not** implemented as a feature.
  Internal redaction is only of fields on the Decide/Report wire.
- Rampart README mentions mirroring Rampart’s “deterministic redaction layer”
  as **recognizers**, not an SDK redact function.

### E.5 Policy-only Guard calls

Passing `rules=[]` still calls Guard with label, actor, and inputs. Empty rules
does **not** mean allow-without-checking. If a local `local_input` triggers an
enforced remote sensitive-info DENY, the SDK sanitizes the request (omits raw
and server-exposed inputs, sends local evidence) and can return a local DENY
with empty `decision.id` if the server does not echo a decision
(`_make_local_policy_denial`).

### E.6 LangChain specifically

- HTTP examples (`examples/fastapi-langchain`, `flask-langchain`): protect the
  **chat HTTP endpoint** with request rules. They do not wrap tools.
- Guard integration: optional extra; `guard_tool` only.
- `examples/fastapi-guard-policy`: one unguarded read tool + one guarded
  `send_email` tool. That is the only in-repo agent-tool authorization demo.

---

## F) Gaps vs Gartner in-market bar; Python vs JS

### F.1 In-market bar (this SDK)

Gartner counts a vendor in-market only if they **natively** cover **all three**
mandatory categories. On **this repository’s facts**:

| Mandatory category | SDK coverage | Meets “native ALL of category”? |
| --- | --- | --- |
| 1. Visibility & traceability (catalog, maps, ownership+lineage, tamper-evident audit) | Capture + decision IDs + correlation; **no** catalog/maps/tamper-evidence | **No** |
| 2. Continuous assurances / agent posture management | **Absent** | **No** |
| 3. Runtime inspection & enforcement (alignment, anomaly, adaptation) | Strong **inline allow/deny**; partial alignment (PI + constraints); weak anomaly/adaptation | **No** (partial only) |

**This Python SDK, by itself, does not meet Gartner’s in-market bar.** It is a
runtime enforcement SDK (plus best-effort visibility events) that an
application must invoke. Category 1 catalog/maps/audit-integrity and category 2
posture management are not implemented here. Whether Arcjet-the-vendor meets
the bar depends on Console/cloud products **outside this repo** and is not
claimed here.

Largest SDK gaps vs the three mandatory categories:

1. No agent catalog or maps.
2. No tamper-evident audit (capture is lossy by design).
3. No AI agent posture management.
4. No agent-behavior anomaly detection or runtime adaptation beyond static
   LIVE/DRY_RUN and periodic policy pull.
5. No MCP-native integration despite README mentioning MCP servers.
6. “Redact” and “authorize tool calls” are marketing; implementation is
   detect/deny and policy/input-constraint gating.

Largest gaps vs common features: autoremediation, compliance reporting,
continuous compliance, security testing product, identity discovery of agents.

### F.2 Python vs JS — only what this repo states

Do **not** treat this as a full JS SDK audit. Comments/tests in *this* repo:

**Intentional parity (Python matches JS):**

- Bot allow-over-deny (`_local.py`).
- Cache DENY-only (`_client.py`).
- Wire redaction of local-only fields (`_context.py`).
- Metadata escape set (`_metadata.py`).
- Capture warning code `AJ1001` and drop message text (`_capture.py`).
- Diagnostic code registry shared across SDKs (`_diagnostics.py`); `AJ3005`
  retired in JS before release.
- Rampart recognizers/entities/tests ported from `arcjet-js`.
- Filter WASM tests aligned with `arcjet-js/analyze`.
- Cache tests ported from `arcjet-js`.

**Documented differences (README Metadata section):**

- Python ints are arbitrary-precision and sent verbatim past 2^53; JS numbers
  are IEEE-754 — send as strings if both SDKs must agree.
- JS `toJSON()` (including `Date`) serializes; Python drops non-JSON types
  (e.g. `datetime`) with a warning. Convert with `isoformat()`.

**Python-only failure mode (not in JS):**

- Dual async/sync Guard clients + a single global registration.
  `CLIENT_FLAVOR_MISMATCH` (`AJ3007`) if `guard()` vs `guard_sync()` does not
  match the registered client (`_registry.py`, `tests/unit/guard/test_registry.py`:
  “The failure mode Python has and JavaScript does not”).

**Not evidenced in this repo as a Python gap vs JS:**

- Request custom rules (README: custom rules are Guard-only here).
- MCP helpers, redact API, middleware, agent catalog — not described as
  “JS has it, Python doesn’t.” They are simply **Absent here**.

**WASM fingerprint:** `generate-fingerprint` is tested but unused by
`protect()`/`guard()`; fingerprinting is described as server-side. Not a
documented JS-parity gap.

### F.3 Python SDK known limitations (AGENTS.md / code)

- Local evaluation timing is not captured (remote Decide logs timing).
- Local DENY decisions are not stored in `DecisionCache`.
- WASM binary is copied from `arcjet/arcjet-analyze` and bindings regenerated
  with `uv run python -m tools.witgen`.
- `experimental_ModerateContent` fail-open until a server model exists.
- Capture may be lost on process exit unless `flush()` is called; daemon
  thread will not keep the interpreter alive.

---

## Appendix — File index

| Area | Paths |
| --- | --- |
| Public request API | `src/arcjet/__init__.py`, `_client.py`, `_rules.py`, `_decision.py`, `_context.py`, `_dataclasses.py` |
| Public Guard API | `src/arcjet/guard/__init__.py`, `_client.py`, `_types.py`, `_policy_input.py`, `_registry.py`, `langchain.py`, `testing.py` |
| Guard rules | `src/arcjet/guard/_rules/` |
| Local WASM | `src/arcjet/_local.py`, `_analyze/`, `guard/_local.py` |
| Remote policy | `src/arcjet/guard/_remote_policy.py` |
| Capture | `src/arcjet/guard/_capture.py`, `_delivery.py`, `_diagnostics.py` |
| Rampart extra | `sensitive-info-rampart/` |
| Protos | `src/arcjet/proto/decide/v1alpha1/`, `src/arcjet/guard/proto/decide/v2/` |
| Docs | `README.md`, `AGENTS.md`, `docs/WASMTIME.md`, `docs/WITGEN.md` |
| Examples | `examples/fastapi/`, `flask/`, `fastapi-langchain/`, `flask-langchain/`, `fastapi-rampart/`, `fastapi-guard-policy/` |
