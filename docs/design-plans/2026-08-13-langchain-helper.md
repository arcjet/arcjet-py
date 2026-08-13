# LangChain Framework Helper Design

## Summary

This design completes an existing but partial integration point: `guard_tool`
already evaluates a policy checkpoint before a LangChain tool runs, but it never
records a correlation ID or emits a capture event, so no Sequence (the joined
trace of decisions and outcomes shown in the Arcjet Console) ever forms. The work
adds a single, framework-agnostic checkpoint engine that every guarding surface
delegates to — so the same fail-closed logic and capture shape is implemented
exactly once — then builds three layers on top of it: a core layer with no
LangChain dependency (ambient correlation via `contextvars`, plus `guard_action`
for guarding arbitrary non-tool code such as background jobs), a private engine
layer that all surfaces share, and an optional LangChain adapter layer that only
translates framework-specific constructs (`RunnableConfig`, `BaseTool`,
middleware) into calls against the core engine. Because imports flow strictly one
way, a user protecting a Celery task or bare script never needs LangChain
installed at all.

The correlation ID is the mechanism that ties everything together: it is set
ambiently for a request, read back automatically by every checkpoint in that
request's path (with an explicit argument or a LangChain `RunnableConfig` value
taking precedence over the ambient value when present), and threaded across async
and background-worker boundaries via explicit export/resume helpers, since
`contextvars` do not automatically survive a thread pool or broker hop. Tool calls
can be guarded either by wrapping (`guard_tool`) or via agent middleware
(`wrap_tool_call` / `awrap_tool_call`), while a callback handler observes the
broader chain/LLM/tool lifecycle for capture only, never for policy. The plan
ships incrementally across seven phases — ambient context, core parity, the
checkpoint engine, completing `guard_tool`, middleware, the callback handler, and
finally an end-to-end FastAPI example — deliberately leaving redaction, Sequence
policy evaluation, and other framework adapters out of scope.

## Definition of Done

- `arcjet.guard.langchain` emits well-formed Sequences: every checkpoint carries a
  correlation ID and every consequential outcome is captured, so one LangChain run
  appears as a single joined Sequence on `site_id` + `correlation_id`.
- Correlation propagates idiomatically without manual threading — ambient
  `contextvars` in the core client (fulfilling the SDK design work deferred by
  [ADR 2026-07-11 OTel telemetry for Sequences][adr-otel]), with an explicit
  argument always winning over ambient.
- `guard_tool` is completed (correlation + capture) and joined by `guard_action`
  for non-tool consequential actions, both fail-closed by default with an
  `on_guard_error` opt-out.
- Tool-call guarding is reachable both by wrapping (`guard_tool`, works with LCEL
  and bare tools) and by agent middleware (`wrap_tool_call` / `awrap_tool_call`),
  the latter seeing parsed arguments immediately before execution.
- Observe-only capture across the chain/LLM/tool lifecycle via
  `BaseCallbackHandler`, never used for policy.
- Correlation survives an async/background boundary via explicit helpers.
- One end-to-end example: HTTP entrypoint → agent/chain → tool → background
  boundary → external action, producing one Sequence.
- Prompt injection and sensitive info wired as policy inputs; sensitive info
  **denies** (no redaction), with redaction documented as a named future phase
  and the ADR carve-out it would need.
- No content mutation anywhere; `make check` and `make test` pass at ≥80%
  coverage; `griffe` reports no unlabelled breaking change.

### Out of scope

- Redaction / rewriting of tool arguments or model output
- Sequence policy *evaluation*
- Security trace UI
- Backend drains or SIEM delivery
- Adapters for other Python frameworks
- Polished public launch docs

[adr-otel]: ../../../arcjet/docs/adrs/2026-07-11-otel-telemetry-for-sequences.md

## Acceptance Criteria

### langchain-helper.AC1: Checkpoints enforce policy and fail closed
- **langchain-helper.AC1.1 Success:** An `ALLOW` decision executes the wrapped callable and returns its value unchanged.
- **langchain-helper.AC1.2 Failure:** A `DENY` decision raises the typed denial error and the wrapped callable never runs.
- **langchain-helper.AC1.3 Failure:** A `DENY` decision still blocks when `on_guard_error="allow"`.
- **langchain-helper.AC1.4 Failure:** `guard()` raising with `on_guard_error="deny"` raises the typed unavailability error and the callable never runs.
- **langchain-helper.AC1.5 Success:** `guard()` raising with `on_guard_error="allow"` executes the callable.
- **langchain-helper.AC1.6 Failure:** A decision whose `has_failed_open()` is true raises unavailability under the default.
- **langchain-helper.AC1.7 Success:** `guard_tool` keeps its current signature, typed errors, and `handle_tool_error` delegation; existing tests pass unmodified.

### langchain-helper.AC2: Sequences are well-formed
- **langchain-helper.AC2.1 Success:** An allowed checkpoint emits a capture with `outcome="success"` carrying `decision_id` and the active correlation ID.
- **langchain-helper.AC2.2 Success:** A denied checkpoint emits a capture with `outcome="denied"`.
- **langchain-helper.AC2.3 Success:** A wrapped callable that raises emits `outcome="error"` and the exception propagates unchanged.
- **langchain-helper.AC2.4 Success:** An unevaluated policy emits `outcome="unavailable"`.
- **langchain-helper.AC2.5 Success:** One guarded tool call records both a guard and a capture sharing a single correlation ID.

### langchain-helper.AC3: Ambient correlation context
- **langchain-helper.AC3.1 Success:** `arcjet_sequence()` sets an ID that `current_correlation_id()` returns inside the block.
- **langchain-helper.AC3.2 Success:** Nested `arcjet_sequence()` blocks restore the outer ID on exit.
- **langchain-helper.AC3.3 Failure:** An ID over 256 bytes, or containing non-printable-ASCII, is rejected rather than silently truncated.
- **langchain-helper.AC3.4 Edge:** Outside any sequence, `current_correlation_id()` returns `None` and checkpoints still evaluate.

### langchain-helper.AC4: Non-tool actions can be guarded
- **langchain-helper.AC4.1 Success:** `guard_action` and `guard_action_sync` guard an arbitrary callable with no LangChain module imported.
- **langchain-helper.AC4.2 Success:** `guard=None` resolves the registered client; with nothing registered the call fails open per core semantics and `on_guard_error` governs the checkpoint.

### langchain-helper.AC5: LangChain surfaces
- **langchain-helper.AC5.1 Success:** `guard_tool` resolves the correlation ID from `RunnableConfig` when present.
- **langchain-helper.AC5.2 Success:** `RunnableConfig` outranks the ambient ContextVar; an explicit argument outranks both.
- **langchain-helper.AC5.3 Success:** With no `RunnableConfig` value, `guard_tool` falls back to the ambient ContextVar.
- **langchain-helper.AC5.4 Failure:** `ArcjetMiddleware` denying a tool call short-circuits without invoking `handler`.
- **langchain-helper.AC5.5 Success:** An allowed middleware call passes the request through with `tool_call` unmodified.
- **langchain-helper.AC5.6 Success:** Both `wrap_tool_call` and `awrap_tool_call` are exercised, and `import arcjet.guard.langchain` succeeds with `langchain` absent (only `langchain-core` installed).
- **langchain-helper.AC5.7 Success:** `ArcjetCaptureHandler` emits captures across a chain run sharing that run's correlation ID.
- **langchain-helper.AC5.8 Failure:** A capture failure inside the callback handler never raises into LangChain.

### langchain-helper.AC6: Correlation crosses boundaries
- **langchain-helper.AC6.1 Success:** Correlation set before `asyncio.create_task()` is visible inside the task.
- **langchain-helper.AC6.2 Success:** Correlation is visible inside `asyncio.to_thread()`.
- **langchain-helper.AC6.3 Edge:** A bare `ThreadPoolExecutor.submit()` does not inherit correlation, and the documented `copy_context()` idiom does.
- **langchain-helper.AC6.4 Success:** A worker resuming an explicit correlation ID produces decisions and captures on the same Sequence as the originating request.

### langchain-helper.AC7: Core parity for checkpoints
- **langchain-helper.AC7.1 Success:** Module-level `guard()` and `guard_sync()` accept `actor` and `inputs` and both reach the transport intact.
- **langchain-helper.AC7.2 Success:** Module-level `guard()` with no rules still contacts Guard, because the server selects remote policy by `label`.
- **langchain-helper.AC7.3 Success:** `RecordedGuard` exposes `actor` and `inputs` so tests assert a checkpoint without a hand-rolled transport.

### langchain-helper.AC8: No content mutation
- **langchain-helper.AC8.1 Success:** Tool arguments and model output are byte-identical before and after a checkpoint, on both allow and deny paths.
- **langchain-helper.AC8.2 Success:** A LIVE sensitive-info detection denies rather than redacting, and raw `LOCAL` input values never appear in the outbound request.

### langchain-helper.AC9: Deliverable and gates
- **langchain-helper.AC9.1 Success:** The example runs end to end — HTTP entrypoint through agent, guarded tool, background boundary, external action — producing one joined Sequence.
- **langchain-helper.AC9.2 Success:** `make check` and `make test` pass at ≥80% coverage, and `griffe check arcjet -s src --against origin/main` reports no breaking change.

## Glossary

- **Sequence**: A joined trace of everything that happened during one LangChain run — decisions and captures — grouped in the Arcjet Console by matching `site_id` and correlation ID.
- **Correlation ID**: An identifier threaded through a single run so that every checkpoint and capture along the way can be tied together into one Sequence. Derived from an existing thread/session ID where possible, or generated as a ULID.
- **Checkpoint**: The unit of enforcement in this design — evaluate a policy, classify the outcome (`success`, `denied`, `error`, or `unavailable`), capture it, then raise or let the wrapped call proceed.
- **Capture**: An observability event recorded for a checkpoint's outcome (e.g. `capture()` / `capture_action()`), independent of whether the checkpoint allowed or denied.
- **Fail-closed / fail-open, `on_guard_error`**: Fail-closed means an error or unavailable policy decision blocks the action by default; `on_guard_error="allow"` is the explicit opt-out that fails open instead. A `DENY` decision always blocks regardless of this setting.
- **Decision / conclusion**: The result object returned by Arcjet's policy evaluation (`guard()`), whose `conclusion` is `ALLOW` or `DENY`, and which may separately report that it `has_failed_open()`.
- **ContextVar / `contextvars`**: Python's standard mechanism for ambient state that follows execution implicitly (including across `asyncio` tasks) without being passed as an explicit argument. Used here to carry the correlation ID.
- **Token pattern (`set` / `reset(token)`)**: The `contextvars` idiom for scoping a value and restoring the previous one on exit, used here because Python's newer context-manager form for this isn't available until 3.14.
- **`copy_context()`**: The `contextvars` API needed to manually propagate ambient state into a `ThreadPoolExecutor` submission, which does not inherit it automatically.
- **`RunnableConfig`**: A LangChain object passed through a chain/agent invocation that can carry configuration data (including, here, a correlation ID) alongside the actual call.
- **LCEL (LangChain Expression Language)**: LangChain's composition syntax for chaining runnables together; mentioned as one of the contexts `guard_tool` must keep working in.
- **`AgentMiddleware` / `wrap_tool_call` / `awrap_tool_call`**: LangChain's hook points for intercepting a tool call (sync and async) with access to parsed arguments before the tool executes — the basis for `ArcjetMiddleware`.
- **`BaseCallbackHandler`**: LangChain's observer interface for chain/LLM/tool lifecycle events (start/end/error), used here purely to emit captures, never to enforce policy.
- **LangGraph**: The graph-execution library LangChain's agent runtime depends on; relevant because pulling in agent middleware support would force a LangGraph dependency, motivating a separate installable extra.
- **`griffe`**: A static analysis tool used to detect unlabelled breaking changes in the public API between this branch and `origin/main`.
- **ADR (Architecture Decision Record)**: A dated document recording a binding design decision; several are referenced as constraints this design must follow (e.g. no content mutation, dual sync/async clients).
- **Registry / registered client**: Arcjet's mechanism for registering a default `ArcjetGuard` client so call sites can omit `guard=` and fall back to the registered one.
- **Extra (Python packaging)**: An optional, separately installable dependency group declared in `pyproject.toml` (e.g. `langchain`, `langchain-agents`), letting users pull in only the LangChain support they need.
- **Sensitive info detection / PII**: Policy checks that identify sensitive content (e.g. personal data) in inputs; this design wires them in as a policy input but denies rather than redacting.
- **Prompt injection**: A policy check for attempts to manipulate an LLM's behavior via crafted input text; wired in here as another policy input to checkpoints.
- **Actor**: An identifier for who or what is performing the guarded action, passed through to the policy evaluation.
- **Metadata vocabulary (`security_metadata`)**: A helper producing a structured metadata object (user, agent, workflow, data classification, etc.) attached to captures, with `data_class` mapped to the wire key `data-class`.

## Architecture

`arcjet.guard.langchain` already ships `guard_tool` (`src/arcjet/guard/langchain.py`),
which evaluates a checkpoint immediately before tool execution and raises typed
errors. It never passes a correlation ID and never calls `capture()`, so no
Sequence forms. This design completes it and generalises the parts that are not
LangChain-specific.

Three layers, with a strictly one-way import direction:

**Core, public, no LangChain.** Ambient correlation context and `guard_action` /
`capture_action`. Importable from a Celery task, an RQ worker, or a bare script.
A user protecting a background job installs `arcjet` and nothing else. Core's
runtime dependencies stay `connect-python`, `pyqwest`, `wasmtime`.

**Private, framework-agnostic engine** (`src/arcjet/guard/_checkpoint.py`). The
single implementation of the checkpoint sequence: resolve actor and inputs, call
`guard()`, classify the outcome, capture, then raise or proceed. Imports core
only. Every public surface delegates to it, so fail-closed semantics and capture
shape are defined exactly once. Private for the reason
[ADR 2026-07-28][adr-subpath] gives — a public path is a compatibility
commitment, and one integration does not justify it.

**Optional LangChain adapters** (`src/arcjet/guard/langchain/`). Translation
only: `RunnableConfig` reading, `BaseTool` wrapping, `ToolMessage` construction,
middleware and callback plumbing. No policy logic.

### Checkpoint outcomes

The engine classifies every checkpoint into exactly four outcomes, using the same
`outcome` metadata key and values as the JavaScript helper
(`arcjet-js/arcjet-guard/src/agents/guarded.ts:95-161`):

| Condition | `outcome` | Effect |
|---|---|---|
| `decision.conclusion == "DENY"` | `denied` | Raise the denial error, regardless of `on_guard_error` |
| `guard()` raised, or `decision.has_failed_open()` | `unavailable` | Raise the unavailability error when `on_guard_error="deny"` |
| The wrapped callable raised | `error` | Re-raise unchanged |
| Otherwise | `success` | Return the value |

`on_guard_error` defaults to `"deny"` because these surfaces wrap consequential
effects, per [ADR 2026-07-27][adr-failclosed]. It governs every condition that
leaves a policy unevaluated, not only a thrown `guard()` call. This is the one
default that diverges from Arcjet's platform-wide fail-open convention, so
documentation must name both the default and the `"allow"` opt-out.

A denial is not a fail-open condition: it is a real decision and blocks even when
`on_guard_error="allow"`. Every capture carries `decision_id=decision.id` and the
active correlation ID, which is what joins the advice half of the trace to the
reality half.

`guard()` is called even when `rules` is empty, because the server selects remote
policy by `label`.

### Correlation context

A module-level `ContextVar` in `src/arcjet/guard/_context.py`, set through a
context manager using the `set` / `reset(token)` token pattern. The token
context-manager protocol only arrives in Python 3.14, so `try` / `finally` is
required on the supported 3.10 floor.

Precedence, highest first: **explicit argument → `RunnableConfig` →
ambient `ContextVar` → none**. The `RunnableConfig` tier exists only inside the
LangChain adapter; core code sees a two-level precedence.

Correlation is derived, never invented. Where a thread or session identifier
exists it becomes the correlation ID; a generated ULID is the fallback for a
genuinely new entrypoint. This follows the rule in
[ADR 2026-08-06 Eve guard surfaces][adr-eve] that a subagent's decisions must
land on the user-facing Sequence rather than one nobody queries. Values are
validated as ≤256 bytes of printable ASCII, matching server-side enforcement.

### Contracts

```python
# src/arcjet/guard/_context.py — core, public via arcjet.guard

@contextmanager
def arcjet_sequence(
    *,
    correlation_id: str | None = None,
    metadata: Metadata | None = None,
) -> Iterator[str]: ...  # yields the active correlation ID

def current_correlation_id() -> str | None: ...
def current_sequence_metadata() -> Metadata | None: ...
```

```python
# src/arcjet/guard/_vocabulary.py — core, public via arcjet.guard

def security_metadata(
    *,
    user: str | None = None,
    agent: str | None = None,
    workflow: str | None = None,
    data_class: str | None = None,      # wire key "data-class"
    destination: str | None = None,
    reversibility: str | None = None,
    resource: str | None = None,
) -> Metadata: ...
```

```python
# core, public via arcjet.guard

OnGuardError = Literal["allow", "deny"]

async def guard_action(
    fn: Callable[[], Awaitable[T]],
    *,
    action: str,
    guard: ArcjetGuard | None = None,
    actor: str | None = None,
    inputs: PolicyInputMap | None = None,
    rules: Sequence[RuleWithInput] = (),
    metadata: Metadata | None = None,
    correlation_id: str | None = None,
    on_guard_error: OnGuardError = "deny",
) -> T: ...

def guard_action_sync(
    fn: Callable[[], T],
    *,
    action: str,
    guard: ArcjetGuardSync | None = None,
    # ...remaining parameters as above
) -> T: ...

def capture_action(
    *,
    action: str,
    metadata: Metadata | None = None,
    correlation_id: str | None = None,
    decision_id: str | None = None,
) -> None: ...
```

`guard=None` resolves the registered client, which requires the registry parity
work in Phase 2.

```python
# src/arcjet/guard/langchain/middleware.py — requires the langchain-agents extra

class ArcjetMiddleware(AgentMiddleware):
    def __init__(
        self,
        *,
        guard: ArcjetGuard | ArcjetGuardSync,
        policies: Mapping[str, ToolPolicy],
        on_guard_error: OnGuardError = "deny",
    ) -> None: ...

    def wrap_tool_call(self, request, handler): ...
    async def awrap_tool_call(self, request, handler): ...
```

### Data flow

An HTTP request enters, `arcjet_sequence()` opens with a correlation ID derived
from the session. The agent runs; each guarded tool call resolves that ID (from
`RunnableConfig` if LangChain propagated it, otherwise from the ContextVar),
evaluates a checkpoint, and captures its outcome. Work handed to a background
worker carries the ID in its job payload, and the worker reopens
`arcjet_sequence(correlation_id=...)` before calling `guard_action` for the
external effect. Every decision and event shares one `site_id` + `correlation_id`
pair, which is how the Console joins a Sequence.

## Existing Patterns

This design follows patterns already established in the repository.

**Dual sync/async clients.** `ArcjetGuard` and `ArcjetGuardSync`
(`src/arcjet/guard/_client.py`) are separate types with separate methods. Every
new surface follows suit rather than bridging an event loop, which
[ADR 2026-08-01][adr-checkpoints] explicitly rejected. LangChain enforces the
same discipline: `AgentMiddleware` raises `NotImplementedError` when only one
flavour is defined (`langchain/agents/middleware/types.py:732`).

**Private modules prefixed with an underscore.** `_client.py`, `_registry.py`,
`_remote_policy.py`, `_policy_input.py`. The new `_context.py`, `_checkpoint.py`
and `_vocabulary.py` match, and are re-exported from
`src/arcjet/guard/__init__.py`.

**Frozen slotted dataclasses for immutable data.** `Decision`, `PolicyInput`,
`RecordedGuard`. New records follow the same form.

**Optional dependencies isolated behind an extra.** `sensitive-info-rampart` is
the precedent; `langchain` already follows it. Core imports no LangChain, which
this design preserves as an invariant.

**Registration as a shortcut, not the default.** The docstring in
`src/arcjet/guard/_registry.py` frames an explicitly passed client as the
recommended path. `guard_action` keeps that framing: `guard=` is preferred and
`None` falls back to the registry.

**Ambient correlation was reserved, not invented here.**
`src/arcjet/guard/_registry.py:22-23` states that `ContextVar` "is still the
right answer for *ambient correlation context*, which is a different problem and
deliberately out of scope." Phase 1 fills that reserved slot.

**Divergence from the JavaScript helper, deliberate in both cases.** `guard_tool`
raises typed errors instead of returning a denial object to the model, per
[ADR 2026-08-01][adr-checkpoints]. And `guard_action` lives in core rather than
behind the framework namespace, because a Python background worker has no
LangChain and must not be made to install it.

**Converting `langchain.py` into a package.** The middleware seam imports
`ToolCallRequest` from `langgraph.prebuilt.tool_node`, and `langchain`
hard-depends on `langgraph<1.3.0,>=1.2.5`. Keeping middleware in the existing
module would force LangGraph on every `guard_tool` user. Splitting into
`src/arcjet/guard/langchain/` preserves `from arcjet.guard.langchain import
guard_tool`, so it is not a breaking change.

## Implementation Phases

<!-- START_PHASE_1 -->
### Phase 1: Ambient correlation context in core

**Goal:** A correlation ID can be scoped ambiently and read back, in sync and
async code, with no LangChain present.

**Components:**
- `src/arcjet/guard/_context.py` — module-level `ContextVar`, `arcjet_sequence()`
  context manager using the `set` / `reset(token)` pattern, `current_correlation_id()`,
  `current_sequence_metadata()`, and ≤256-byte printable-ASCII validation
- `src/arcjet/guard/__init__.py` — export the three public names
- `tests/unit/guard/test_context.py` — including an `autouse` fixture that resets
  the ContextVar between tests

**Dependencies:** None.

**Covers:** `langchain-helper.AC3.1`, `langchain-helper.AC3.2`,
`langchain-helper.AC3.3`, `langchain-helper.AC3.4`, `langchain-helper.AC6.1`,
`langchain-helper.AC6.2`, `langchain-helper.AC6.3`

**Done when:** Tests prove nesting restores the outer ID, an invalid ID is
rejected, correlation survives `asyncio.create_task()` and `asyncio.to_thread()`,
and a fresh context reads `None`.
<!-- END_PHASE_1 -->

<!-- START_PHASE_2 -->
### Phase 2: Core parity for checkpoints

**Goal:** The registry free functions and the test client can both express a full
policy checkpoint.

**Components:**
- `src/arcjet/guard/_registry.py` — add `actor` and `inputs` to module-level
  `guard()` and `guard_sync()`; default `rules` to `()`
- `src/arcjet/guard/testing.py` — add optional `actor` and `inputs` fields to
  `RecordedGuard`
- `tests/unit/guard/test_registry.py`, `tests/unit/guard/test_testing.py` — extend

**Dependencies:** None.

**Covers:** `langchain-helper.AC7.1`, `langchain-helper.AC7.2`,
`langchain-helper.AC7.3`

**Done when:** A registry-path `guard()` call with no rules but an `actor` and
`inputs` reaches the transport intact, `RecordedGuard` exposes both, and
`griffe check arcjet -s src --against origin/main` reports no breaking change.
<!-- END_PHASE_2 -->

<!-- START_PHASE_3 -->
### Phase 3: Checkpoint engine, `guard_action`, and metadata vocabulary

**Goal:** One framework-agnostic engine enforces fail-closed semantics and emits
capture; `guard_action` exposes it to any Python code.

**Components:**
- `src/arcjet/guard/_checkpoint.py` — the four-outcome sequence, resolver
  invocation, correlation resolution, capture emission with `decision_id`, and
  swallowing of capture failures
- `src/arcjet/guard/_vocabulary.py` — `security_metadata()` with the seven fields
  and the `data-class` wire-key mapping
- `src/arcjet/guard/__init__.py` — export `guard_action`, `guard_action_sync`,
  `capture_action`, `security_metadata`, `OnGuardError`
- `tests/unit/guard/test_checkpoint.py`, `tests/unit/guard/test_vocabulary.py`

**Dependencies:** Phases 1 and 2.

**Covers:** `langchain-helper.AC1.1`–`langchain-helper.AC1.6`,
`langchain-helper.AC2.1`–`langchain-helper.AC2.4`, `langchain-helper.AC4.1`,
`langchain-helper.AC4.2`, `langchain-helper.AC8.1`, `langchain-helper.AC8.2`

**Done when:** Tests cover all four outcomes across sync and async, prove a
denial blocks under `on_guard_error="allow"`, prove `guard()` is still called with
empty rules, and prove a capture failure does not fail the action.
<!-- END_PHASE_3 -->

<!-- START_PHASE_4 -->
### Phase 4: Complete `guard_tool`

**Goal:** The shipped tool checkpoint joins a Sequence.

**Components:**
- `src/arcjet/guard/langchain.py` → `src/arcjet/guard/langchain/__init__.py` plus
  `src/arcjet/guard/langchain/_tool.py` — delegate to `_checkpoint.py`, resolve
  correlation from `RunnableConfig` then the ContextVar, emit capture. Signature,
  typed errors, and `handle_tool_error` delegation unchanged
- `tests/integration/guard/test_langchain.py` — extend

**Dependencies:** Phase 3.

**Covers:** `langchain-helper.AC1.7`, `langchain-helper.AC2.5`,
`langchain-helper.AC5.1`, `langchain-helper.AC5.2`, `langchain-helper.AC5.3`

**Done when:** Existing tests pass unmodified, a guarded tool call records both a
guard and a capture sharing one correlation ID, `RunnableConfig` outranks the
ContextVar, and `griffe` reports no breaking change.
<!-- END_PHASE_4 -->

<!-- START_PHASE_5 -->
### Phase 5: Agent middleware

**Goal:** `create_agent` applications guard tool calls at the parsed-argument
boundary.

**Components:**
- `src/arcjet/guard/langchain/middleware.py` — `ArcjetMiddleware` implementing
  `wrap_tool_call` and `awrap_tool_call`, reading `request.tool_call["args"]`
  without mutating the request
- `pyproject.toml` — new `langchain-agents = ["langchain>=1,<2"]` extra, leaving
  `langchain = ["langchain-core>=1,<2"]` unchanged
- `tests/integration/guard/test_langchain_middleware.py`

**Dependencies:** Phase 4.

**Covers:** `langchain-helper.AC5.4`, `langchain-helper.AC5.5`,
`langchain-helper.AC5.6`

**Done when:** A denied tool call short-circuits without invoking `handler`, an
allowed call passes through unchanged, both sync and async hooks are exercised,
and importing `arcjet.guard.langchain` still works without `langchain` installed.
<!-- END_PHASE_5 -->

<!-- START_PHASE_6 -->
### Phase 6: Capture callback handler

**Goal:** Sequence coverage across the chain and model lifecycle, where blocking
is impossible.

**Components:**
- `src/arcjet/guard/langchain/callbacks.py` — `ArcjetCaptureHandler`
  (`BaseCallbackHandler`) and an async counterpart, emitting capture on chain,
  model, and tool start/end/error. Observe-only; never evaluates policy
- `tests/integration/guard/test_langchain_callbacks.py`

**Dependencies:** Phase 4.

**Covers:** `langchain-helper.AC5.7`, `langchain-helper.AC5.8`

**Done when:** A chain run emits captures sharing the run's correlation ID, an
error path captures `outcome="error"`, and the handler never raises into
LangChain.
<!-- END_PHASE_6 -->

<!-- START_PHASE_7 -->
### Phase 7: End-to-end example and documentation

**Goal:** A design partner can instrument a LangChain workflow by reading one
example.

**Components:**
- `examples/fastapi-langchain-guard/` — `main.py`, `worker.py`, `pyproject.toml`,
  `README.md`, `example.env`, `uv.lock`, following the existing example layout.
  Covers HTTP entrypoint → agent → guarded tool → background boundary → external
  action, producing one Sequence
- `README.md` — document the surfaces, the two extras, and the fail-closed
  default with its `on_guard_error="allow"` opt-out
- Document the `ThreadPoolExecutor` / broker propagation gaps and the
  `copy_context()` idiom, plus redaction as a named future phase

**Dependencies:** Phases 1–6.

**Covers:** `langchain-helper.AC6.4`, `langchain-helper.AC9.1`,
`langchain-helper.AC9.2`

**Done when:** The example runs end to end against a real key and produces a
single joined Sequence; `make check` and `make test` pass at ≥80% coverage.
<!-- END_PHASE_7 -->

## Additional Considerations

**Sensitive-info redaction is deliberately excluded.** `wrap_tool_call` could
rewrite arguments via `request.override(tool_call=...)`, but
[ADR 2026-08-01][adr-checkpoints] requires a checkpoint to map inputs "without
mutating the original value". Redaction therefore needs an explicit ADR
amendment carving out that rule, not a quiet implementation. Until then
sensitive info denies, per
[ADR 2026-08-11][adr-sanitized]. No surface in this design mutates content.

**Capture must never turn a success into a failure.** Delivery is bounded,
batched, and send-once; a full queue drops events and reports through the
`arcjet` logger. The engine swallows capture errors so an audit-trail problem
cannot break an application action.

**Local sensitive-info denial ordering is already handled in core.**
[ADR 2026-08-11][adr-sanitized] requires a LIVE local PII detection to run before
rule conversion or server input transmission, sending only kind and digest for
`LOCAL` inputs. That lives in `guard()` and `_remote_policy.py`; the checkpoint
engine inherits it and must not attempt to re-implement or bypass it.

**Correlation gaps are documented, not papered over.** Contextvars do not cross
`ThreadPoolExecutor`, `ProcessPoolExecutor`, generators, or a broker boundary.
The design ships `current_correlation_id()` plus `arcjet_sequence()` as the
export/resume pair and documents the `copy_context()` idiom rather than wrapping
executor APIs the SDK has no business owning.

**Actor and input mappings are trusted application assertions.** Per
[ADR 2026-08-01][adr-checkpoints], the wrappers do not prevent trusted
application code from bypassing Guard or changing values after evaluation.

[adr-checkpoints]: ../../../arcjet/docs/adrs/2026-08-01-guard-vercel-ai-and-langchain-policy-checkpoints.md
[adr-subpath]: ../../../arcjet/docs/adrs/2026-07-28-guard-sdk-subpath-namespaces.md
[adr-eve]: ../../../arcjet/docs/adrs/2026-08-06-eve-guard-surfaces.md
[adr-sanitized]: ../../../arcjet/docs/adrs/2026-08-11-finalize-local-guard-denials-with-sanitized-checkpoints.md
[adr-failclosed]: ../../../arcjet/docs/adrs/2026-07-27-sdk-agent-helpers-fail-closed-default.md
