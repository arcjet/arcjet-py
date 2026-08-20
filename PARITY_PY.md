# Arcjet SDK parity review — changes required in `arcjet-py`

**Reviewed:** 2026-08-20
**Scope:** Core SDK only — HTTP `protect()`, Guard, local WASM evaluation, decision
cache, metadata. Framework integrations (FastAPI/Flask/Django coercion, LangChain)
are explicitly out of scope.

**Sources compared:**

| SDK | Repo | Commit |
| --- | --- | --- |
| Python | `arcjet/arcjet-py` | `eef50a1ddee709efab855f5de738892cf5a68964` |
| JavaScript | `arcjet/arcjet-js` (v1.10.0) | `0099fb76e9229fa0b5922f938f4f1ce2e1033ce1` |
| Go | `arcjet/arcjet-go` (v0.1.0) | `8726757 01dadb4988ffcf4576f7e8571c9ac8dd8` |

Every item below was verified against source in all three repos, not inferred from
documentation. Items are ordered by risk × blast radius.

---

## Summary

| # | Priority | Change | Type |
| --- | --- | --- | --- |
| 1 | P0 | Cache hits return a stale, shared, mutable decision | Correctness bug |
| 2 | P0 | Require an explicit `mode` instead of defaulting to `LIVE` | Cross-SDK divergence |
| 3 | P1 | `detect_bot` accepts both `allow` and `deny`, and accepts neither | Silent misconfiguration |
| 4 | P1 | Local rules evaluate in declaration order, not priority order | Privacy / divergence |
| 5 | P1 | `is_spoofed_bot` ignores `DRY_RUN` rule state | Silent misconfiguration |
| 6 | P1 | Timeout policy differs from JS | Divergence |
| 7 | P2 | No `with_rule` | Missing API |
| 8 | P2 | No `protect_signup` | Missing API |
| 9 | P2 | No `arcjet.redact` package | Missing API |
| 10 | P2 | No `is_verified_bot` / `is_missing_user_agent` / rate-limit header helper | Missing API |
| 11 | P3 | Remove deprecated prompt-injection `threshold` | Cleanup |
| 12 | P3 | Document Guard `ARCJET_KEY` policy | Cleanup |

---

## P0 — correctness

### 1. Cache hits return a stale, shared, mutable decision

**Where:** `src/arcjet/_client.py` — cache-hit block in `Arcjet.protect()` (~L632-706)
and the mirrored block in `ArcjetSync.protect()` (~L1140+). `Decision.to_proto()` in
`src/arcjet/_decision.py` (~L377).

Three distinct defects in one code path.

**1a. TTL is never decremented.** The cached `Decision` is returned unmodified, so
`decision.ttl` reports the *original* TTL for the entire cache window. A decision
cached with `ttl=60` still reports `60` when served 59 seconds later.

Both other SDKs rewrite it:

- Go — `cache.go:66-72` computes `remaining := time.Until(entry.expiresAt)` and sets
  `cloned.Ttl = ttl`, flooring at `1`.
- JS — `arcjet/src/index.ts:2022-2040` rebuilds `ArcjetRateLimitReason` with
  `reset: ttl` taken from the live cache lookup, explicitly commented:
  *"We rebuild the `ArcjetRateLimitReason` because we need to adjust the `reset`
  based on the current time-to-live."*

**1b. Rate-limit reason fields go stale with it.** Because the whole decision is
returned as-is, `reason_v2.remaining`, `reason_v2.reset`, and `reason_v2.reset_time`
are frozen at cache-write time. `RateLimitReason`'s own docstring tells users to build
`RateLimit-Remaining` and `Retry-After` headers from exactly these fields, so a cache
hit produces a `Retry-After` that is too large by up to the full TTL.

**1c. The cached proto is mutated in place, and it is shared.**

```python
dec = cached.to_proto()          # returns self._d by reference, not a copy
dec.id = _new_local_request_id() # mutates the object still held in the cache
...
return cached                    # same object the cache holds
```

`Decision.to_proto()` returns `self._d` directly, and `DecisionCache` stores the
`Decision` wrapper, so the proto is aliased by the cache, by the returned value, and
by every previously returned value. Consequences:

- A `Decision` a caller already holds silently changes its `.id` when a later request
  hits the same cache entry.
- Concurrent requests hitting the same key race on one mutable protobuf. `DecisionCache`
  guards the dict with an `RLock`, but nothing guards the object it hands out.

**Fix:** on a cache hit, deep-copy the proto, rewrite `ttl` to the remaining lifetime,
recompute rate-limit `remaining` / `reset` / `reset_time` against that remaining
lifetime, and assign the fresh `lreq_…` id to the copy only. Mirror `ruleCache.get`
in `arcjet-go/cache.go`.

**Why it matters:** this is a bug in any language. It produces wrong `Retry-After`
values, wrong client-visible TTLs, and a data race — none of which are visible to the
caller.

---

### 2. Require an explicit `mode` instead of defaulting to `LIVE`

**Where:** every rule factory in `src/arcjet/_rules.py` uses
`mode: Union[str, Mode] = Mode.LIVE`. Guard rules in `src/arcjet/guard/_rules/`
use `mode: Mode = "LIVE"`.

Verified defaults across all three SDKs:

| Surface | JS | Python | Go |
| --- | --- | --- | --- |
| HTTP `protect` rules | `DRY_RUN` | **`LIVE`** | `DRY_RUN` |
| Guard rules | `LIVE` | `LIVE` | **`DRY_RUN`** |

Evidence: JS coerces with `options.mode === "LIVE" ? "LIVE" : "DRY_RUN"` in every HTTP
rule builder (`arcjet/src/index.ts:1967, 2116, 2248, 2573, 2774, 2956, 3146, 3238, 3467`)
and documents `@default "LIVE"` on every Guard config in `arcjet-guard/src/types.ts`.
Go's `normalizeMode` (`types.go:23-28`) maps `""` → `ModeDryRun` for **both** surfaces.

Porting `detectBot({ allow: ["CATEGORY:SEARCH_ENGINE"] })` from JS to Python without
setting `mode` silently changes it from log-only to live blocking.

**Do not simply flip the Python default to `DRY_RUN`.** That would silently disable
enforcement for every existing Python user on upgrade — a security regression delivered
by a version bump.

**Fix:** make `mode` a required keyword argument so omitting it raises `TypeError`.
A loud break is strictly safer than a silent enforcement change in either direction.
Per `AGENTS.md`, ship it with the `breaking` label and a migration note; a
`DeprecationWarning` release before the hard requirement is a reasonable intermediate
step.

**Note on the HTTP/Guard split:** the split itself is defensible — HTTP rules land in
broad middleware where accidental blocking is costly, Guard rules are opted into at a
specific call site. The problem is Python sitting on the wrong side of the HTTP default
(and Go on the wrong side of the Guard default). Requiring the field resolves both
without choosing.

---

## P1 — silent misconfiguration

### 3. `detect_bot` accepts both `allow` and `deny`, and accepts neither

**Where:** `BotDetection.__post_init__` (`src/arcjet/_rules.py:288-309`) and the
`detect_bot()` factory (`:907`). Both validate types and reject empty strings, but
neither enforces exclusivity or presence.

Both other SDKs reject it:

- JS — `` `detectBot` options error: `allow` and `deny` cannot be provided together ``
  and `` either `allow` or `deny` must be specified `` (`arcjet/src/index.ts:2947-2951`),
  plus a compile-time discriminated union (`BotOptionsAllow | BotOptionsDeny`).
- Go — `validateBotOptions` returns `ErrAllowDenyConflict` (`rules.go:467-475`).

Python is also inconsistent with itself: `Filter.__post_init__` and
`SensitiveInfoDetection.__post_init__` both already raise on the same condition.

Silent failure modes today:

- `detect_bot()` with neither list builds a rule that allows all bots.
- `detect_bot(allow=[...], deny=[...])` is accepted, and local WASM silently prefers
  `allow` — `_local.py:181-189` documents this as defensive behavior:
  *"allow takes precedence over deny (matches JS SDK); the builder API prevents both
  being set, but we handle it defensively here."* The builder does **not** prevent it.

**Fix:** raise `ValueError` from `detect_bot()` and `BotDetection.__post_init__` when
both lists are set, and when neither is. Apply the same to `validate_email()`, which
has the same gap.

---

### 4. Local rules evaluate in declaration order, not priority order

**Where:** `_run_local_rules()` (`src/arcjet/_client.py:208-255`) iterates
`for rule in rules` in the order the caller listed them.

JS sorts by an explicit priority table before evaluating
(`arcjet/src/index.ts:1730-1738`, applied via `sortRule` at `:4036`):

```
SensitiveInfo(1) → Filter(2) → Shield(3) → RateLimit(4) → Bot(5) → Email(6) → PromptInjection(7)
```

The first LIVE DENY wins and short-circuits, so ordering decides which rule's reason,
TTL, and Report payload the caller sees. Sensitive-info-first is a privacy property,
not a micro-optimization: it should deny before another rule's path forwards the
payload.

Go has the same gap (`evaluateLocal`, `client.go:556-586`).

**Fix:** adopt the JS priority ordering in `_run_local_rules()`.

---

### 5. `is_spoofed_bot` ignores `DRY_RUN` rule state

**Where:** `src/arcjet/_decision.py:396-421`.

```python
r = result.raw.reason
if not r:
    return False
if r.WhichOneof("reason") == "bot_v2":
    return bool(r.bot_v2.spoofed)
return False
```

No check of `result.state`, so a rule running in `DRY_RUN` still reports `True`.

Both other SDKs gate on state:

- JS — `isActive(result)` requires `result.state !== "DRY_RUN"`, and the helper returns
  `undefined` (not `False`) for non-bot or dry-run results
  (`inspect/src/index.ts:34-44, 145-154`).
- Go — `anyActiveReason` skips `RuleStateDryRun`; covered by `rules_test.go:107, 125-129`.

A user staging bot detection in dry-run and gating on `is_spoofed_bot()` blocks traffic
the rule was only meant to observe — the precise failure dry-run exists to prevent.

**Fix:** skip results whose state is `RULE_STATE_DRY_RUN`. Consider matching JS's
tri-state return (`None` for "check did not apply"), though that is a breaking signature
change and could ship separately.

---

### 6. Timeout policy differs from JS

**Where:** `_DEFAULT_TIMEOUT_MS = 2000` (`src/arcjet/_client.py:155`), applied flat.

| SDK | Base | Adjustments |
| --- | --- | --- |
| JS | 500 ms prod / 1000 ms dev (`arcjet-node/src/index.ts:139`) | ×2 with an email rule; floor 1000 ms with prompt injection (`protocol/src/client.ts:118-142`) |
| Python | 2000 ms | none |
| Go | none — caller `context` only | none |

Python's own comment argues its value is the correct one:

> Sized for the slowest rules: a cold prompt-injection or content-moderation start can
> exceed the old 500ms production default, and a tight deadline fail-opens instead of
> evaluating the rule.

If that reasoning holds, JS's 500 ms base is the outlier and should move, not Python's.

**Fix:** agree one base across SDKs plus the same per-rule adjustments. Python should
additionally adopt the email ×2 and prompt-injection floor so a slow rule does not
fail open at a deadline sized for fast ones.

---

## P2 — missing API surface

### 7. No `with_rule`

JS has `withRule(rule[])` (`arcjet/src/index.ts:4011-4014`); Go has
`(*Client).WithRule` (`client.go:209-235`), which copies the client and **shares the
cache pointer** so route-specific clones do not lose cached entries.

Without it, per-route rules require constructing a whole new client — which in Python
also allocates a fresh `DecisionCache`, discarding all cached denials.

**Fix:** add `Arcjet.with_rule()` / `ArcjetSync.with_rule()` returning a copy that
shares `_cache` and recomputes `_needs_email` / `_needs_message` / `_has_token_bucket`.

### 8. No `protect_signup`

Sugar over sliding window + bot + email. JS: `protectSignup`
(`arcjet/src/index.ts:3417-3429`). Go: `ProtectSignup` (`rules.go:459-465`).
Python has no equivalent.

### 9. No `arcjet.redact`

JS ships `@arcjet/redact`; Go ships the `redact` package. Both drive the same WASM
component. Python has no redaction API — only inline `"<redacted>"` substitution for
outbound Report payloads (`_context.py:337-341`, `_client.py:258-275`).

Go's package doc already asserts the Python one exists:

> It runs the same WebAssembly component as the @arcjet/redact (JavaScript) and
> **arcjet.redact (Python)** packages, so all three SDKs redact identically.

**Fix:** build `arcjet.redact` (with `entities`, `context_window_size`, `detect`,
`replace`, and an unredact callback) or correct the Go comment.

### 10. No `is_verified_bot` / `is_missing_user_agent` / rate-limit header helper

- JS `@arcjet/inspect` exports `isSpoofedBot`, `isVerifiedBot`, `isMissingUserAgent`.
- Go exposes `Decision.IsSpoofedBot`, `IsVerifiedBot`, `IsMissingUserAgent`
  (`types.go:302-326`).
- Python exports only `is_spoofed_bot`.

Similarly, JS has `@arcjet/decorate` (`setRateLimitHeaders`) and Go has
`SetRateLimitHeaders` (`headers.go`). Python is the only SDK where emitting
`RateLimit-*` / `Retry-After` is entirely the application's job — and, per item 1,
the values it would use are currently stale on cache hits.

---

## P3 — cleanup

### 11. Remove deprecated prompt-injection `threshold`

Already deprecated in Python and JS; **removed** in Go
(`PromptInjectionOptions` has only `Mode`). The server ignores it.

The two remaining implementations also disagree on validation:

- JS rejects `threshold <= 0.0 || threshold >= 1.0` — exclusive
  (`arcjet/src/index.ts:3241-3246`).
- Python accepts `0.0 <= threshold <= 1.0` — inclusive (`_rules.py:141-145`).

So `threshold=0.0` throws in JS and passes in Python. Since the value is inert,
remove it from both rather than reconciling the ranges.

### 12. Document the Guard `ARCJET_KEY` policy

- JS Guard: documented as never reading environment variables
  (`arcjet-guard/src/index.ts:66-69`).
- Go Guard: reads `ARCJET_KEY` when `Key` is empty (`guard.go:71-74`).
- Python Guard: requires an explicit key, no env fallback
  (`guard/_client.py:974, 1029`).

Python HTTP `arcjet()` also requires an explicit key while reading `ARCJET_BASE_URL`
and `FLY_APP_NAME` — defensible, but the three-way Guard split should be a deliberate,
documented decision.

---

## Verified aligned — no action

Checked and confirmed identical; previously suspected as gaps.

- **Local deny TTL is 60s everywhere.** Python `_LOCAL_DENY_TTL_SECONDS = 60`
  (`_local.py:127`), JS `ttl: 60` (`index.ts:3040, 3536`), Go `localDeny(..., 60, ...)`
  (`local_decision.go:200, 243`).
- **Guard `requested` defaults to 1** in all three (Python
  `guard/_rules/_rate_limit.py:108, 167, 226`; JS `convert.ts:603, 616, 629`;
  Go `guard.go` `if requested <= 0 { requested = 1 }`).
- **No SDK reports on a first remote DENY** — the Decide call creates the dashboard
  entry. Only local and cached denials trigger `Report`.
- **Global characteristics apply to rate-limit rules only** in all three
  (`_apply_global_characteristics`, JS `index.ts:3830-3837`,
  Go `collectFingerprintChars`).
- **Bot categories, email types, and native sensitive-info entity types** match.
- **Prompt injection is server-side only; content moderation is Guard-only** in all three.
- **Metadata**: same 768 KiB SDK ceiling, same `AJ1017` warning code, excluded from
  fingerprint and cache key everywhere.
- **DRY_RUN local denies do not short-circuit** in any SDK.

---

## Deliberate differences — leave as-is

Language idiom, not parity bugs:

- **Integer seconds for rate-limit windows.** JS accepts duration strings (`"1h45m"`)
  because it has no duration type; Go uses `time.Duration`. Integer seconds is the
  natural Python choice. Worth documenting seconds as the canonical wire contract; not
  worth adding a string parser.
- **Dual async/sync clients** (`arcjet()` / `arcjet_sync()`). No analogue needed elsewhere.
- **`arcjet_sequence` ContextVar.** A `ContextVar` is the idiomatic Python correlation
  mechanism; Go correctly prefers explicit `CorrelationId`.
- **`fail_open` flag.** Python's flag plus `ArcjetTransportError` is reasonable; see
  `PARITY_GO.md` item 1 for the Go-side problem this contrasts with.
- **`reason` vs `reason_v2`.** Already deprecated with a migration path.
- **`disable_automatic_ip_detection` + required `ip_src`.** A stricter, defensible
  contract that neither other SDK models the same way.
