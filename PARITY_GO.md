# Arcjet SDK parity review — changes required in `arcjet-go`

**Reviewed:** 2026-08-20
**Scope:** Core SDK only — `Protect`, rules, decisions, local WASM evaluation, cache,
Guard, redact, metadata. HTTP middleware/router adapters are out of scope.

**Sources compared:**

| SDK | Repo | Commit |
| --- | --- | --- |
| Go | `arcjet/arcjet-go` (v0.1.0) | `872675701dadb4988ffcf4576f7e8571c9ac8dd8` |
| JavaScript | `arcjet/arcjet-js` (v1.10.0) | `0099fb76e9229fa0b5922f938f4f1ce2e1033ce1` |
| Python | `arcjet/arcjet-py` | `eef50a1ddee709efab855f5de738892cf5a68964` |

Every item below was verified against source in all three repos, not inferred from
documentation. Items are ordered by risk × blast radius.

---

## Summary

| # | Priority | Change | Type |
| --- | --- | --- | --- |
| 1 | P0 | `Protect` returns an unusable zero `Decision` on transport error | Footgun / internal inconsistency |
| 2 | P0 | Guard rate-limit rules default to bucket `"default"` | Wrong counter grouping |
| 3 | P0 | Guard rules default to `DRY_RUN` when `Mode` is empty | Cross-SDK divergence |
| 4 | P1 | Local rules evaluate in declaration order, not priority order | Privacy / divergence |
| 5 | P1 | No default deadline when the caller passes a context without one | Divergence |
| 6 | P2 | HTTP `SensitiveInfo` has no `ContextWindowSize` | Missing API |
| 7 | P3 | Correct the `redact` package doc's claim about Python | Doc fix |
| 8 | P3 | Document the Guard `ARCJET_KEY` policy | Cleanup |

---

## P0 — correctness

### 1. `Protect` returns an unusable zero `Decision` on transport error

**Where:** `client.go:498-501`.

```go
resp, err := c.decideClient.Decide(ctx, req)
if err != nil {
    return Decision{}, err
}
```

The zero `Decision` has `Conclusion == ""`, so **both** predicates are false:

- `IsAllowed()` → `"" == ConclusionAllow` → `false`
- `IsDenied()`  → `"" == ConclusionDeny`  → `false`

A handler written the natural way —

```go
decision, err := client.Protect(ctx, r)
if err != nil { /* log */ }
if !decision.IsAllowed() {
    http.Error(w, "Forbidden", http.StatusForbidden)
    return
}
```

— **blocks all traffic during an Arcjet outage**, the exact opposite of the fail-open
behavior promised in `doc.go`:

> Arcjet is designed to fail open: if the service is unavailable, Protect and Guard
> return an error and the caller should continue serving.

Returning an `error` is correct Go and should stay. The problem is returning an
*unusable value* alongside it.

**This is an internal inconsistency, not a language-idiom difference.** Go's own Guard
already does the right thing (`guard.go:153-155`, `:254`): on transport failure it
returns an `ALLOW` decision carrying a synthetic errored result **and** a non-nil error,
so `HasFailedOpen()` and `ErrorResults()` work for callers who ignore `err`.

For reference, the other SDKs both synthesize a decision:

- JS returns `ArcjetErrorDecision` where `isAllowed()` is `true` and `isErrored()` is
  `true` (`arcjet/src/index.ts:3988-3998`, `protocol/src/index.ts`).
- Python returns a `CONCLUSION_ERROR` decision when `fail_open=True`
  (`_client.py:807-814`).

**Fix:** return an `ERROR`-conclusion `Decision` alongside the error, mirroring
`GuardClient.Guard`. Callers who check `err` are unaffected; callers who check the
decision get sane values, and `IsErrored()` becomes meaningful on the Protect path.
Returning a populated value with a non-nil error is idiomatic when the value is
meaningful.

---

### 2. Guard rate-limit rules default to bucket `"default"`

**Where:** `guard.go:454-457` (token bucket), `:560-563` (fixed window),
`:657-660` (sliding window):

```go
bucket := opts.Bucket
if bucket == "" {
    bucket = "default"
}
```

Both other SDKs use distinct, typed defaults:

| Rule | JS / Python | Go |
| --- | --- | --- |
| Token bucket | `default-token-bucket` | `default` |
| Fixed window | `default-fixed-window` | `default` |
| Sliding window | `default-sliding-window` | `default` |

Evidence: JS `arcjet-guard/src/convert.ts:601, 614, 627`; Python
`guard/_rules/_rate_limit.py:52, 72, 92`.

Two consequences:

1. The same logical rate limit lands in a **different server-side counter** in Go than
   in JS/Python, so a polyglot deployment silently splits its limit.
2. Within Go, all three algorithms **collide in one bucket** when `Bucket` is left
   empty, so a token bucket and a fixed window on the same key share a counter.

**Fix:** use the same three default names. One line per rule; no idiom argument.

---

### 3. Guard rules default to `DRY_RUN` when `Mode` is empty

**Where:** `normalizeMode` (`types.go:23-28`) maps `""` → `ModeDryRun`, and both
`requestMode` and `guardMode` route through it, so the default applies to Guard as
well as HTTP.

Verified defaults across all three SDKs:

| Surface | JS | Python | Go |
| --- | --- | --- | --- |
| HTTP `protect` rules | `DRY_RUN` | `LIVE` | `DRY_RUN` |
| Guard rules | `LIVE` | `LIVE` | **`DRY_RUN`** |

JS documents `@default "LIVE"` on every Guard rule config
(`arcjet-guard/src/types.ts:582-584, 720-722, 846-848, 972-974, 1015-1017, 1153-1155,
1227-1229, 1389-1391`); Python uses `mode: Mode = "LIVE"` throughout
`guard/_rules/`.

A Go Guard rule constructed without `Mode` therefore **observes but never enforces**,
while the same rule in JS or Python blocks. On the HTTP side Go matches JS and is fine.

**Do not simply flip the Go Guard default to `LIVE`.** That would start blocking
traffic that existing deployments only observe — a silent behavior change delivered by
a version bump.

**Fix:** make an empty `Mode` an error for Guard rule constructors. They already return
`(*Rule, error)`, so `GuardTokenBucket`, `GuardFixedWindow`, `GuardSlidingWindow`,
`GuardPromptInjection`, `GuardModerateContent`, `GuardSensitiveInfo`, and `GuardCustom`
can reject it in `newGuardRuleBase` via `validateMode` without normalizing first. Go
cannot require a struct field, so a constructor error is the idiomatic loud signal.

Leave the HTTP `DRY_RUN` default alone, or apply the same treatment there via
`NewClient` returning an error — see `PARITY_PY.md` item 2 for the matching Python-side
change.

---

## P1 — divergence

### 4. Local rules evaluate in declaration order, not priority order

**Where:** `evaluateLocal` (`client.go:556-586`) iterates `for i, rule := range c.rules`
in the order the caller configured them.

JS sorts by an explicit priority table before evaluating
(`arcjet/src/index.ts:1730-1738`, applied via `sortRule` at `:4036`):

```
SensitiveInfo(1) → Filter(2) → Shield(3) → RateLimit(4) → Bot(5) → Email(6) → PromptInjection(7)
```

The first live DENY short-circuits (`liveDeny()`), so ordering decides which rule's
reason, TTL, and Report payload the caller sees. Sensitive-info-first is a privacy
property: it should deny before another rule's path forwards the payload.

Python has the same gap.

**Fix:** sort by the JS priority order in `evaluateLocal`. Because Go precomputes
`ruleIDs`, `fpChars`, and `builtRuleIndices` positionally at construction, sort once in
`NewClient`/`WithRule` and keep those slices aligned rather than sorting per request.

---

### 5. No default deadline when the caller's context has none

**Where:** `Protect` / `ProtectDetails` (`client.go:406, 415`) rely entirely on the
caller's `context.Context`. There is no SDK-level timeout.

| SDK | Base | Adjustments |
| --- | --- | --- |
| JS | 500 ms prod / 1000 ms dev (`arcjet-node/src/index.ts:139`) | ×2 with an email rule; floor 1000 ms with prompt injection (`protocol/src/client.ts:118-142`) |
| Python | 2000 ms (`_client.py:155`) | none |
| Go | none | none |

Deferring to `context` is idiomatic Go and should remain the primary mechanism. The gap
is the fallback: `Protect(context.Background(), r)` has no deadline at all, so a hung
Decide call stalls the handler indefinitely — whereas the same code in JS or Python
fails open on a timer.

Go already applies bounded deadlines elsewhere: `reportTimeout = 5 * time.Second`
(`client.go:26`) and `guardPolicyFetchTimeout = 2s` (`remote_policy.go`).

**Fix:** apply a default deadline when the incoming context has none
(`ctx.Deadline()` returns `ok == false`), sized to whatever base the SDKs agree on.
Never shorten a caller-supplied deadline.

---

## P2 — missing API surface

### 6. HTTP `SensitiveInfo` has no `ContextWindowSize`

**Where:** `SensitiveInfoOptions` (`rules.go:314-326`) exposes `Mode`, `Allow`, `Deny`,
and `Backend` — no context window. `Config.SensitiveInfoDetect` (`client.go:58-64`) is
client-wide.

Both other SDKs expose it per rule, defaulting to 1:

- JS — `contextWindowSize?: number`, applied as `options.contextWindowSize || 1`
  (`arcjet/src/index.ts:1528, 1636, 2688`).
- Python — `context_window_size: int | None` on `detect_sensitive_info()`
  (`_rules.py:585, 1198`).

Go already threads the value through its WASM bindings —
`SensitiveInfoConfig.ContextWindowSize *uint32`
(`internal/local/jsreq/bindings.go:173-177`) — and `redact.Options.ContextWindowSize`
uses the same mechanism (`redact/redact.go:46-48, 132-135`). Only the public HTTP rule
option is missing, so a Go `SensitiveInfoDetect` callback always receives single-token
windows and cannot implement multi-token detectors.

**Fix:** add `ContextWindowSize int` to `SensitiveInfoOptions`, defaulting to 1 when
zero or negative, matching `redact.Options`.

---

## P3 — cleanup

### 7. Correct the `redact` package doc's claim about Python

**Where:** `redact/redact.go:1-9`:

> It runs the same WebAssembly component as the @arcjet/redact (JavaScript) and
> **arcjet.redact (Python)** packages, so all three SDKs redact identically.

`arcjet.redact` does not exist. Python has no redaction API — only inline
`"<redacted>"` substitution on outbound Report payloads.

**Fix:** either drop the Python reference until `arcjet-py` ships the package
(tracked as `PARITY_PY.md` item 9), or reword to describe the shared component
without asserting a Python package.

### 8. Document the Guard `ARCJET_KEY` policy

- Go Guard reads `ARCJET_KEY` when `Key` is empty (`guard.go:71-74`).
- JS Guard is documented as **never** reading environment variables
  (`arcjet-guard/src/index.ts:66-69`).
- Python Guard requires an explicit key with no env fallback.

Go's behavior is internally consistent (`NewClient` does the same at `client.go:109-112`)
and idiomatic. The three-way split should nonetheless be a deliberate, documented
decision rather than an accident.

Related: Go implements no `ARCJET_ENV` / development mode, which both other SDKs have
(missing-IP fallback to `127.0.0.1`, `X-Arcjet-Ip` override). Given Go's explicit
`Platform` enum and `WithIPSrc`, this is a reasonable omission — worth confirming it
is intentional.

---

## Verified aligned — no action

Checked and confirmed identical; previously suspected as gaps.

- **Local deny TTL is 60s everywhere.** Go `localDeny(..., 60, ...)`
  (`local_decision.go:200, 243`), JS `ttl: 60` (`index.ts:3040, 3536`), Python
  `_LOCAL_DENY_TTL_SECONDS = 60`.
- **Per-rule cache semantics match JS.** `(ruleID, fingerprint)` key, DENY + `RUN` +
  `TTL > 0` only, TTL rewritten to remaining lifetime on read, fresh `lreq` id
  (`cache.go:46-104`). This is the reference implementation — Python is the outlier
  here, not Go.
- **Guard `requested` defaults to 1** in all three.
- **No SDK reports on a first remote DENY** — the Decide call creates the dashboard
  entry. Go's Report-on-cached-DENY matches JS.
- **Allow/deny exclusivity** is enforced for bot, email, sensitive info, and filter
  (`rules.go:467-495`) — Go and JS both enforce; Python is the gap.
- **Global characteristics apply to rate-limit fingerprints only**
  (`collectFingerprintChars`, `client.go:186-203`).
- **Prompt injection is server-side only; content moderation is Guard-only.**
- **Metadata**: same 768 KiB ceiling, excluded from fingerprint and cache key.
- **`IsSpoofedBot` / `IsVerifiedBot` / `IsMissingUserAgent`** correctly skip
  `RuleStateDryRun` (`types.go:302-326`), matching JS `@arcjet/inspect`. Python is the
  gap here.
- **Prompt-injection `threshold` already removed** — Go is ahead; JS and Python should
  follow.

---

## Deliberate differences — leave as-is

Language idiom, not parity bugs:

- **`time.Duration` for rate-limit windows.** The natural Go type. JS uses duration
  strings only because it lacks one; Python uses integer seconds. `seconds()`
  (`rules.go:497-502`) already clamps sub-second values to 1.
- **No global Guard registry / free `guard()`.** JS `registerArcjet` and Python's
  module-level registry have no clean Go equivalent; an explicit client handle is the
  better Go design.
- **No ambient correlation context.** Explicit `CorrelationId` on `GuardRequest`,
  `ProtectOptions`, and `CaptureEvent` is correct Go; Python's `ContextVar` is not
  portable here.
- **`.Key(...)` / `.Text(...)` rule binding** instead of calling the rule as a function.
- **Metadata warnings surfaced on the `Decision`** rather than logged. Go takes no
  logger; this is the right call and arguably better than JS/Python logging them.
- **`SetRateLimitHeaders`** (`headers.go`) — Go and JS have this; Python does not.
- **`ProtectDetails` / `DetailsFromRequest`** for non-`*http.Request` sources.
- **`sensitiveInfoValue` never placed on the wire** (`client.go:446-449`). Stricter
  than JS/Python, which send it and redact. Keep the stricter behavior.
- **wazero + wizer pre-initialization** for the WASM runtime.
