# Arcjet SDK parity review — changes required in `arcjet-js`

**Reviewed:** 2026-08-20
**Scope:** Core and shared packages only — `arcjet`, `@arcjet/protocol`,
`@arcjet/analyze`, `@arcjet/cache`, `@arcjet/guard`, `@arcjet/inspect`,
`@arcjet/decorate`, `@arcjet/redact`. Framework adapters (`arcjet-next`,
`arcjet-node`, `arcjet-bun`, `nosecone*`, …) are out of scope except where they own a
default the core cannot express.

**Sources compared:**

| SDK | Repo | Commit |
| --- | --- | --- |
| JavaScript | `arcjet/arcjet-js` (v1.10.0) | `0099fb76e9229fa0b5922f938f4f1ce2e1033ce1` |
| Python | `arcjet/arcjet-py` | `eef50a1ddee709efab855f5de738892cf5a68964` |
| Go | `arcjet/arcjet-go` (v0.1.0) | `872675701dadb4988ffcf4576f7e8571c9ac8dd8` |

Every item below was verified against source in all three repos, not inferred from
documentation. Items are ordered by risk × blast radius.

**JS is the reference implementation for most core behavior** — priority ordering,
per-rule caching, and allow/deny validation are all correct here and missing elsewhere.
The list below is correspondingly short.

---

## Summary

| # | Priority | Change | Type |
| --- | --- | --- | --- |
| 1 | P1 | Decide timeout base is 500 ms, below the documented cold-start cost | Fail-open risk |
| 2 | P2 | Joint decision: require an explicit `mode` rather than defaulting | Cross-SDK divergence (no JS defect) |
| 3 | P2 | Token bucket throws when `requested` is absent instead of defaulting to 1 | Divergence |
| 4 | P2 | Shield ignores rule-level `characteristics` | Missing option |
| 5 | P3 | `ArcjetDecision.ttl` is documented as milliseconds but is seconds | Doc bug |
| 6 | P3 | Remove deprecated prompt-injection `threshold` | Cleanup |
| 7 | P3 | Core `arcjet()` cannot be used standalone | Architecture note |

---

## P1

### 1. Decide timeout base is 500 ms, below the documented cold-start cost

**Where:** `arcjet-node/src/index.ts:139` —
`const timeout = options?.timeout ?? (isDevelopment(env) ? 1000 : 500);`
Adjusted by `decideTimeout` (`protocol/src/client.ts:118-142`): ×2 with an email rule,
floored at 1000 ms with a prompt-injection rule.

| SDK | Base | Adjustments |
| --- | --- | --- |
| JS | 500 ms prod / 1000 ms dev | ×2 email; floor 1000 ms prompt injection |
| Python | 2000 ms flat (`_client.py:155`) | none |
| Go | none — caller `context` only | none |

Python raised its default specifically because of this, and its comment reads as a
direct finding against the JS value:

> Sized for the slowest rules: a cold prompt-injection or content-moderation start can
> exceed the old 500ms production default, and a tight deadline fail-opens instead of
> evaluating the rule. Matches Guard's default.

If that measurement is right, a JS app with prompt injection or content moderation
fails open on cold starts where the same configuration in Python evaluates the rule.
Note the JS prompt-injection floor is 1000 ms — still half of Python's base — and there
is **no** adjustment for content moderation.

**Fix:** agree a single base across SDKs (Python's 2000 ms is the only value with a
stated rationale) and keep the per-rule adjustments. Because the timeout lives in the
adapters rather than core, this is a change across `arcjet-node`, `arcjet-bun`, and the
other adapters, or a shared default hoisted into `createRemoteClient`.

---

## P2

### 2. Joint decision: require an explicit `mode` rather than defaulting

**Where:** every HTTP rule builder coerces with
`options.mode === "LIVE" ? "LIVE" : "DRY_RUN"`
(`arcjet/src/index.ts:1967, 2116, 2248, 2573, 2774, 2956, 3146, 3238, 3467`).
Guard configs document `@default "LIVE"` (`arcjet-guard/src/types.ts`).

Verified defaults across all three SDKs:

| Surface | JS | Python | Go |
| --- | --- | --- | --- |
| HTTP `protect` rules | `DRY_RUN` | **`LIVE`** | `DRY_RUN` |
| Guard rules | `LIVE` | `LIVE` | **`DRY_RUN`** |

JS is on the majority side of both. The divergences are Python's HTTP default and Go's
Guard default, and both are addressed in their own files.

**JS input validation is sound** — worth recording, because the coercion pattern looks
lossy at a glance and is not. Every builder calls its `validate*Options` function
before coercing (`validateTokenBucketOptions:803`, `validateShieldOptions:970`,
`validateBotOptions:953`, `validateDetectPromptInjectionOptions:987`, and the
equivalents for fixed window, sliding window, email, sensitive info, and filter). Each
declares `{ key: "mode", required: false, validate: validateMode }`, and `validateMode`
(`:764-766`) throws on anything outside `{"LIVE","DRY_RUN"}`. So `mode: "live"` raises
rather than silently downgrading to dry-run. **No change needed here.**

**Cross-SDK consideration only:** if the SDKs converge on requiring an explicit `mode`
— the recommendation in `PARITY_PY.md` item 2, since flipping any default silently
changes enforcement in one direction or the other — JS would make `mode` a required
field on the rule option types. TypeScript makes this the least disruptive of the
three: a compile-time error rather than a runtime surprise, and `validateMode` already
gives the runtime backstop. Worth deciding jointly rather than per SDK; there is no
JS-only defect driving it.

---

### 3. Token bucket throws when `requested` is absent instead of defaulting to 1

**Where:** `arcjet/src/index.ts:1987-1995`:

```ts
assert(
  typeof details.extra.requested === "string",
  "TokenBucket requires `requested` to be set.",
);
```

Backed at the type level by `{ requested: number }` in the rule's props.

| SDK | HTTP token bucket | Guard token bucket |
| --- | --- | --- |
| JS | **required** — throws if absent | defaults to 1 (`convert.ts:603`) |
| Python | defaults to 1 (`_client.py:587-588`) | defaults to 1 |
| Go | omitted from `Extra` unless `> 0` (`client.go:439-441`) | defaults to 1 (`guard.go`) |

So JS is the only SDK that hard-requires it, and it is inconsistent with **its own
Guard implementation**, which defaults to 1 in the same repo.

Defaulting to 1 is the better contract: it is what all three Guard implementations
already do, it matches the common case of one unit per call, and it removes a runtime
throw from a hot path.

**Fix:** default `requested` to 1 in the HTTP token bucket rule and relax the prop type
to optional, matching Guard. Keep the type-level hint so explicit costs are still
discoverable.

### 4. Shield ignores rule-level `characteristics`

**Where:** `shield()` (`arcjet/src/index.ts:3141-3203`). `ShieldOptions` exposes only
`mode`, and the implementation carries a standing TODO:

```ts
// TODO(#1989): Prefer characteristics defined on rule once available
const localCharacteristics = context.characteristics;
```

Both other SDKs accept per-rule characteristics on Shield:

- Python — `Shield.characteristics` and `shield(characteristics=...)`
  (`_rules.py:96-118, 818`), serialized into `ShieldRule.characteristics`.
- Go — `ShieldOptions.Characteristics` (`rules.go:193-199`), serialized as
  `"characteristics"` on the `shield` wire object.

A Shield rule keyed on a custom characteristic is expressible in Python and Go but not
in JS.

**Fix:** add `characteristics` to `ShieldOptions` and use it for fingerprinting when
present, falling back to `context.characteristics` — the same precedence rate-limit
rules already use. Closes `#1989`.

---

## P3

### 5. `ArcjetDecision.ttl` is documented as milliseconds but is seconds

**Where:** `protocol/src/index.ts:1240-1243` and `:1282-1285`:

> Duration in **milliseconds** this decision should be considered valid, also known as
> time-to-live.

It is seconds. Evidence:

- `ArcjetRuleResult.ttl` is documented as *"Duration in **seconds**"*
  (`protocol/src/index.ts:716-719, 754-757`).
- The deny decision is built directly from it: `new ArcjetDenyDecision({ ttl: result.ttl, … })`
  (`arcjet/src/index.ts:3911-3915`).
- `MemoryCache` is entirely seconds-based — `nowInSeconds()`, and
  `set()` computes `expiresAt = nowInSeconds() + ttl` (`cache/src/index.ts:35-37, 64-68`).
- Local denies use `ttl: 60`, meaning 60 seconds (`arcjet/src/index.ts:3040, 3536`),
  matching Python's `_LOCAL_DENY_TTL_SECONDS = 60` and Go's `localDeny(..., 60, ...)`.

Both other SDKs document and treat decision TTL as seconds.

**Fix:** correct both doc comments to seconds. Documentation-only, but it will mislead
anyone porting between SDKs or writing a custom cache against the `Cache` interface.

### 6. Remove deprecated prompt-injection `threshold`

**Where:** `DetectPromptInjectionOptions.threshold`
(`arcjet/src/index.ts:3087-3108`), already marked `@deprecated` — *"no longer respected
by the server"* — and validated at `:3241-3246`.

Status across SDKs:

- JS — deprecated, still sent; rejects `threshold <= 0.0 || threshold >= 1.0` (**exclusive**).
- Python — deprecated, still sent; accepts `0.0 <= threshold <= 1.0` (**inclusive**).
- Go — **removed**; `PromptInjectionOptions` has only `Mode` (`rules.go:375-382`).

`threshold: 0` therefore throws in JS and is accepted in Python. Since the server
ignores the value, reconciling the ranges is wasted work.

**Fix:** remove the option in JS and Python, following Go. Also remove the paired
`ArcjetPromptInjectionReason.score`, already deprecated.

### 7. Core `arcjet()` cannot be used standalone

**Where:** `arcjet/src/index.ts:3669-3682` throws `"Log is required"` and
`"Client is required"` when `options.log` / `options.client` are absent, with a
standing TODO:

```ts
// TODO(#207): Remove this when we can default the transport so client is not required
```

Both other SDKs construct a working client from a key and rules alone
(`arcjet(key=..., rules=[...])`, `NewClient(Config{Key: ..., Rules: ...})`), supplying
their own transport, logger, and defaults.

This is a deliberate monorepo architecture choice — adapters inject transport, logging,
IP detection, and body reading — and is not a bug. It does mean the package named
`arcjet` on npm is not usable on its own, which surprises people arriving from the
Python or Go SDKs, and it prevents a plain Node script from using the core without
`@arcjet/node`.

**Fix (optional):** resolve `#207` by defaulting the transport and logger, keeping the
injection points as overrides. Lower priority than the items above; recorded so the
cross-SDK difference is deliberate rather than incidental.

---

## Verified aligned — no action

Checked and confirmed identical; previously suspected as gaps.

- **Local deny TTL is 60s everywhere.** JS `ttl: 60` (`index.ts:3040, 3536`), Python
  `_LOCAL_DENY_TTL_SECONDS = 60`, Go `localDeny(..., 60, ...)`.
- **No SDK reports on a first remote DENY** — the Decide call creates the dashboard
  entry. JS reports only on local DENY (`index.ts:3917-3920`) and error paths; Go and
  Python match, including Report on a cached DENY.
- **Global characteristics apply to rate-limit rules only** (`index.ts:3830-3837`), the
  same rule Python's `_apply_global_characteristics` and Go's `collectFingerprintChars`
  implement.
- **Redaction of `filterLocal` / `sensitiveInfoValue` for remote calls, and
  `detectPromptInjectionMessage` for Reports** (`index.ts:3719-3744`) — Python mirrors
  this exactly and cites JS as the source; Go goes further and never puts
  `sensitiveInfoValue` on the wire at all.
- **Guard `requested` defaults to 1** in all three.
- **Prompt injection is server-side only; content moderation is Guard-only.**
- **Metadata**: same 768 KiB SDK ceiling, same `AJ1017` warning code, excluded from
  fingerprint and cache key everywhere.
- **DRY_RUN local denies log and continue** rather than short-circuiting, in all three.
- **Bot categories, email types, native sensitive-info entity types, and the
  `requireTopLevelDomain: true` / `allowDomainLiteral: false` email defaults** match.

---

## JS behavior other SDKs should adopt

Recorded here so it is not lost — these are tracked as changes in `PARITY_PY.md` and
`PARITY_GO.md`.

- **Local rule priority ordering** (`index.ts:1730-1738`, `sortRule` at `:4036`).
  Sensitive info → filter → shield → rate limit → bot → email → prompt injection.
  Python and Go both evaluate in caller-declaration order, so the rule that
  short-circuits — and therefore the reason, TTL, and Report payload — differs. The
  sensitive-info-first ordering is a privacy property, not a micro-optimization.
- **Allow/deny validation.** JS enforces "exactly one of `allow`/`deny`" at both
  compile time (discriminated unions) and runtime for bot, email, sensitive info, and
  filter (`:2947-2951`, `:2763-2769`, `:2562-2568`, `:3471-3480`). Go enforces it for
  all four; **Python does not enforce it for bot or email**.
- **Per-rule caching keyed on `(ruleId, fingerprint)`**, where `ruleId` is a stable hash
  of the rule's full config via `@arcjet/stable-hash`. Go mirrors this; Python caches
  whole decisions keyed on rule class names plus characteristic values, which is both
  coarser and stale on read.
- **Rebuilding rate-limit `reset` from the live cache TTL on a cache hit**
  (`:2030-2039`). Go rewrites TTL similarly; Python returns the cached decision
  untouched, so `Retry-After` values derived from it are wrong.
- **`@arcjet/inspect` state-awareness.** `isSpoofedBot` / `isVerifiedBot` /
  `isMissingUserAgent` return `undefined` for `DRY_RUN` or non-bot results rather than
  a misleading boolean (`inspect/src/index.ts:34-44`). Go matches; Python's
  `is_spoofed_bot` does not check state and returns `True` for dry-run results.
- **`withRule`** (`:4011-4014`) and **`protectSignup`** (`:3417-3429`) — Go has both,
  Python has neither.
- **`@arcjet/decorate`** (`setRateLimitHeaders`) — Go has `SetRateLimitHeaders`,
  Python has no equivalent.
- **`@arcjet/redact`** — Go has a `redact` package, Python has none (and Go's package
  doc incorrectly claims Python ships one).
