# LangChain Framework Helper — Test Requirements

Maps every acceptance criterion in `docs/design-plans/2026-08-13-langchain-helper.md`
to the verification that discharges it. The test-analyst uses this during execution to
check that what was written actually covers what was promised — not to design new tests.
Every row is drawn from a phase file's `Verifies:` field or `Testing:` bullets; nothing
here is invented.

**Verification commands:**

```bash
make test    # uv run pytest, coverage fail_under = 80
make check   # ruff lint + format, ty, pyright, griffe (make apicheck)
```

**Repository convention that constrains every row:** there is no `pytest-asyncio` and no
`anyio` plugin, and zero `async def test_*` functions. Async behavior is exercised from a
plain `def test_*` calling `asyncio.run(...)`. Any row below that mentions an async flavor
means that shape, never an `async def` test.

**Supporting test infrastructure (verifies no AC, required for the rest):**
`tests/guard_doubles.py` (the shared `reset_sequence_context` fixture and
`StubGuardClient`), and `tests/unit/test_ids.py` (regression cover for the Phase 1
`arcjet._ids` refactor, required because `fail_under = 80` applies to the new module).

---

## Summary

| | Count |
|---|---|
| Acceptance criteria total | **37** |
| Automated (sections 3) | 35 |
| Human-verified (section 4) | 1 |
| Gate checks (section 5) | 1 |
| **Accounted for** | **37** |

Per group: AC1 = 7, AC2 = 5, AC3 = 4, AC4 = 2, AC5 = 8, AC6 = 4, AC7 = 3, AC8 = 2,
AC9 = 2. Each criterion appears exactly once across sections 3, 4 and 5.

Two criteria are split across phases and appear as two rows in one cell:
`langchain-helper.AC3.4` (Phase 1 + Phase 3) and `langchain-helper.AC8.1`
(Phase 3 + Phase 4).

---

## Automated tests

### langchain-helper.AC1: Checkpoints enforce policy and fail closed

| AC | Criterion (verbatim) | Test type | Expected test file | What the test must assert |
|---|---|---|---|---|
| AC1.1 | **langchain-helper.AC1.1 Success:** An `ALLOW` decision executes the wrapped callable and returns its value unchanged. | unit | `tests/unit/guard/test_checkpoint.py` | A clean ALLOW runs the callable exactly once and the return value is the identical object (`result is sentinel`, not equality). Both flavors. |
| AC1.2 | **langchain-helper.AC1.2 Failure:** A `DENY` decision raises the typed denial error and the wrapped callable never runs. | unit | `tests/unit/guard/test_checkpoint.py` | `ArcjetDeniedError` is raised, a call-counter on the callable is still `0`, and the error carries `.action` and `.decision`. |
| AC1.3 | **langchain-helper.AC1.3 Failure:** A `DENY` decision still blocks when `on_guard_error="allow"`. | unit | `tests/unit/guard/test_checkpoint.py` | The same DENY with `on_guard_error="allow"` still raises and the call-counter is still `0`. |
| AC1.4 | **langchain-helper.AC1.4 Failure:** `guard()` raising with `on_guard_error="deny"` raises the typed unavailability error and the callable never runs. | unit | `tests/unit/guard/test_checkpoint.py` | A client whose `guard` raises produces `ArcjetUnavailableError` with `__cause__` set to the original exception, and the callable never ran. |
| AC1.5 | **langchain-helper.AC1.5 Success:** `guard()` raising with `on_guard_error="allow"` executes the callable. | unit | `tests/unit/guard/test_checkpoint.py` | The same raising client with `on_guard_error="allow"` runs the callable and returns its value. |
| AC1.6 | **langchain-helper.AC1.6 Failure:** A decision whose `has_failed_open()` is true raises unavailability under the default. | unit | `tests/unit/guard/test_checkpoint.py` | `ArcjetUnavailableError` under the default — and the test first asserts `decision.has_failed_open()` really is `True`, so it cannot pass for the wrong reason. |
| AC1.7 | **langchain-helper.AC1.7 Success:** `guard_tool` keeps its current signature, typed errors, and `handle_tool_error` delegation; existing tests pass unmodified. | integration | `tests/integration/guard/test_langchain.py` | The 193 pre-existing lines pass with no test body changed (`git diff --stat` shows additions only), **plus** the previously-untested half: a failed-open decision and a raising `guard()` each raise `ArcjetToolUnavailableError`; a raising actor/input resolver becomes `ArcjetToolUnavailableError` rather than the resolver's own exception; both errors satisfy `isinstance(exc, ToolException)` *and* the core `ArcjetDeniedError` / `ArcjetUnavailableError` bases. Both `invoke` and `ainvoke`. |

### langchain-helper.AC2: Sequences are well-formed

| AC | Criterion (verbatim) | Test type | Expected test file | What the test must assert |
|---|---|---|---|---|
| AC2.1 | **langchain-helper.AC2.1 Success:** An allowed checkpoint emits a capture with `outcome="success"` carrying `decision_id` and the active correlation ID. | unit | `tests/unit/guard/test_checkpoint.py` | Inside `arcjet_sequence(correlation_id="corr-1")`, exactly one capture with `metadata["outcome"] == "success"`, `correlation_id == "corr-1"`, `decision_id == decision.id`. |
| AC2.2 | **langchain-helper.AC2.2 Success:** A denied checkpoint emits a capture with `outcome="denied"`. | unit | `tests/unit/guard/test_checkpoint.py` | The capture exists on the client *after the call raised* — capture happens before the raise. Also: `metadata={"outcome": "success"}` passed into a denying checkpoint still emits `outcome="denied"` (a caller cannot override the engine's observation). |
| AC2.3 | **langchain-helper.AC2.3 Success:** A wrapped callable that raises emits `outcome="error"` and the exception propagates unchanged. | unit | `tests/unit/guard/test_checkpoint.py` | A callable raising `ValueError("boom")` emits `outcome="error"` and the exact exception instance is re-raised, not wrapped. |
| AC2.4 | **langchain-helper.AC2.4 Success:** An unevaluated policy emits `outcome="unavailable"`. | unit | `tests/unit/guard/test_checkpoint.py` | Both unevaluated paths — `has_failed_open()` true, and `guard()` raising — emit `outcome="unavailable"`; on the `guard()`-raises path `decision_id is None`. A decision with `id=""` produces `decision_id is None`, not `""`. Scoped to the failing-closed path (see Coverage risks). |
| AC2.5 | **langchain-helper.AC2.5 Success:** One guarded tool call records both a guard and a capture sharing a single correlation ID. | integration | `tests/integration/guard/test_langchain.py` | One invoke inside `arcjet_sequence(correlation_id="corr-1")` yields exactly one guard call and exactly one capture, **both** carrying `correlation_id == "corr-1"`; the capture's `decision_id` equals the decision's `id` and `metadata["outcome"] == "success"`. |

### langchain-helper.AC3: Ambient correlation context

| AC | Criterion (verbatim) | Test type | Expected test file | What the test must assert |
|---|---|---|---|---|
| AC3.1 | **langchain-helper.AC3.1 Success:** `arcjet_sequence()` sets an ID that `current_correlation_id()` returns inside the block. | unit | `tests/unit/guard/test_context.py` | With `correlation_id="corr-1"`, both the yielded value and `current_correlation_id()` equal `"corr-1"`; with no argument, the yielded value is a non-empty string and `current_correlation_id()` returns that same value. Imported from `arcjet.guard`, not `arcjet.guard._context`, so the export path is proven too. |
| AC3.2 | **langchain-helper.AC3.2 Success:** Nested `arcjet_sequence()` blocks restore the outer ID on exit. | unit | `tests/unit/guard/test_context.py` | Outer `"outer"` → nested `"inner"` → on nested exit reads `"outer"` again → on outer exit reads `None`. A second case where the nested body raises a caught exception still restores `"outer"`. |
| AC3.3 | **langchain-helper.AC3.3 Failure:** An ID over 256 bytes, or containing non-printable-ASCII, is rejected rather than silently truncated. | unit | `tests/unit/guard/test_context.py` | `ValueError` for `"a"*257`, `"a"*256 + "b"`, `"café"`, `"a\tb"`, `"a\nb"`, `""`; `"a"*256` is accepted (boundary inclusive); a non-`str` raises `TypeError`. After every `pytest.raises`, `current_correlation_id() is None` — proving rejection, not truncation. |
| AC3.4 | **langchain-helper.AC3.4 Edge:** Outside any sequence, `current_correlation_id()` returns `None` and checkpoints still evaluate. | unit | *first clause:* `tests/unit/guard/test_context.py`<br>*second clause:* `tests/unit/guard/test_checkpoint.py` | **First clause (Phase 1):** with no enclosing block, `current_correlation_id()` and `current_sequence_metadata()` both return `None`. **Second clause (Phase 3):** outside any `arcjet_sequence`, a checkpoint still evaluates — the guard call happens and the emitted capture carries `correlation_id is None`. |

### langchain-helper.AC4: Non-tool actions can be guarded

| AC | Criterion (verbatim) | Test type | Expected test file | What the test must assert |
|---|---|---|---|---|
| AC4.1 | **langchain-helper.AC4.1 Success:** `guard_action` and `guard_action_sync` guard an arbitrary callable with no LangChain module imported. | unit | `tests/unit/guard/test_checkpoint.py` | In a `subprocess` running `python -c` with a `sys.meta_path` finder that raises `ImportError` for any `langchain*` module, `import arcjet.guard` and `guard_action_sync` succeed — assert exit code 0. The in-process `assert "langchain" not in sys.modules` is a cheaper second check only, never the primary one. |
| AC4.2 | **langchain-helper.AC4.2 Success:** `guard=None` resolves the registered client; with nothing registered the call fails open per core semantics and `on_guard_error` governs the checkpoint. | unit | `tests/unit/guard/test_checkpoint.py` | With `guard=None` and a client registered via `register_test_client()`, `client.guards` grew. With nothing registered, the free call fails open, so the default raises `ArcjetUnavailableError` and `on_guard_error="allow"` runs the callable. |

### langchain-helper.AC5: LangChain surfaces

| AC | Criterion (verbatim) | Test type | Expected test file | What the test must assert |
|---|---|---|---|---|
| AC5.1 | **langchain-helper.AC5.1 Success:** `guard_tool` resolves the correlation ID from `RunnableConfig` when present. | integration | `tests/integration/guard/test_langchain.py` | With no ambient sequence open, `config={"configurable": {"arcjet_correlation_id": "from-config"}}` makes the guard call carry `"from-config"`; the same asserted with the value under `config["metadata"]`. |
| AC5.2 | **langchain-helper.AC5.2 Success:** `RunnableConfig` outranks the ambient ContextVar; an explicit argument outranks both. | integration | `tests/integration/guard/test_langchain.py` | (a) Inside `arcjet_sequence(correlation_id="ambient")` with a config carrying `"from-config"`, the guard call carried `"from-config"`. (b) The top tier is exercised where it exists: `guard_action_sync(..., correlation_id="explicit")` inside `arcjet_sequence(correlation_id="ambient")` carries `"explicit"`. |
| AC5.3 | **langchain-helper.AC5.3 Success:** With no `RunnableConfig` value, `guard_tool` falls back to the ambient ContextVar. | integration | `tests/integration/guard/test_langchain.py` | With a config carrying no Arcjet key, and separately with `config=None`, inside `arcjet_sequence(correlation_id="ambient")`, the guard call carried `"ambient"`. A 300-byte config value does not raise: the tool call succeeds and correlation falls back to ambient (or `None`). |
| AC5.4 | **langchain-helper.AC5.4 Failure:** `ArcjetMiddleware` denying a tool call short-circuits without invoking `handler`. | integration | `tests/integration/guard/test_langchain_middleware.py` | `wrap_tool_call` raises `ArcjetDeniedError` **and the handler's call-counter is still 0** — the counter is the criterion; an exception alone does not prove the handler was skipped rather than run-then-discarded. Repeated for `awrap_tool_call`. |
| AC5.5 | **langchain-helper.AC5.5 Success:** An allowed middleware call passes the request through with `tool_call` unmodified. | integration | `tests/integration/guard/test_langchain_middleware.py` | `handler` ran exactly once and received the *same request object* (`received is request`); `request.tool_call["args"]` is unchanged and equal to what was constructed — no key added, removed, or rewritten; the middleware's return value is the handler's return value. Both flavors. |
| AC5.6 | **langchain-helper.AC5.6 Success:** Both `wrap_tool_call` and `awrap_tool_call` are exercised, and `import arcjet.guard.langchain` succeeds with `langchain` absent (only `langchain-core` installed). | integration | `tests/integration/guard/test_langchain_middleware.py` | Both hooks have async counterparts driven via `asyncio.run(...)`. Import isolation is a `subprocess` with a `sys.meta_path` blocker for `langchain.agents*` and `langgraph*`: `import arcjet.guard.langchain` and `from arcjet.guard.langchain import guard_tool` exit 0 with empty stderr, **and** the mirror-image check that `import arcjet.guard.langchain.middleware` under the same blocker fails. |
| AC5.7 | **langchain-helper.AC5.7 Success:** `ArcjetCaptureHandler` emits captures across a chain run sharing that run's correlation ID. | integration | `tests/integration/guard/test_langchain_callbacks.py` | Driving `on_chain_start`, `on_tool_start`, `on_tool_end`, `on_llm_start`, `on_llm_end`, `on_chain_end` inside `arcjet_sequence(correlation_id="corr-1")`, every recorded capture carries `correlation_id == "corr-1"`, the action names are the expected past-tense `prefix.resource.verb` strings, and the count matches the hooks driven. Plus: one handler reused across `arcjet_sequence("a")` then `("b")` emits `"a"` then `"b"` (correlation resolves per event, not at construction); an explicit `correlation_id="explicit"` beats an ambient `"ambient"`; outside any sequence captures still emit with `correlation_id is None`; a recognisable secret string driven through `on_tool_start` / `on_llm_start` appears in no capture's metadata. Async handler covered via `asyncio.run(...)`. |
| AC5.8 | **langchain-helper.AC5.8 Failure:** A capture failure inside the callback handler never raises into LangChain. | integration | `tests/integration/guard/test_langchain_callbacks.py` | With a client double whose `capture()` raises, every hook returns normally — at least one start, one end and one error hook, on both the sync and async handlers. The failure is asserted to have been logged via `caplog` against the `arcjet` logger, so a swallowed error is distinguishable from one that never happened. |

### langchain-helper.AC6: Correlation crosses boundaries

| AC | Criterion (verbatim) | Test type | Expected test file | What the test must assert |
|---|---|---|---|---|
| AC6.1 | **langchain-helper.AC6.1 Success:** Correlation set before `asyncio.create_task()` is visible inside the task. | unit | `tests/unit/guard/test_context.py` | From a plain `def test_*` calling `asyncio.run(...)`: inside `arcjet_sequence(correlation_id="task-1")`, an awaited `asyncio.create_task(reader())` captures `"task-1"`. |
| AC6.2 | **langchain-helper.AC6.2 Success:** Correlation is visible inside `asyncio.to_thread()`. | unit | `tests/unit/guard/test_context.py` | Same shape: `await asyncio.to_thread(current_correlation_id) == "thread-1"`. |
| AC6.3 | **langchain-helper.AC6.3 Edge:** A bare `ThreadPoolExecutor.submit()` does not inherit correlation, and the documented `copy_context()` idiom does. | unit | `tests/unit/guard/test_context.py` | Inside an open sequence: `ThreadPoolExecutor.submit(current_correlation_id).result() is None`; `ThreadPoolExecutor.submit(copy_context().run, current_correlation_id).result()` equals the active ID; `loop.run_in_executor(pool, current_correlation_id)` returns `None`. A fresh `copy_context()` per submission (re-entering one `Context` concurrently raises `RuntimeError`). |
| AC6.4 | **langchain-helper.AC6.4 Success:** A worker resuming an explicit correlation ID produces decisions and captures on the same Sequence as the originating request. | unit | `tests/unit/guard/test_sequence_boundary.py` | One test models the whole hop: checkpoint inside `arcjet_sequence(correlation_id="req-1")`, export via `current_correlation_id()`, **leave the sequence and assert `current_correlation_id() is None`**, then in a bare `ThreadPoolExecutor.submit` reopen the sequence from the payload and run a second checkpoint plus a `capture_action`. Every recorded guard and every recorded capture from both sides carries `correlation_id == "req-1"`. Negative control required: the same worker function without reopening produces a guard whose `correlation_id is None`. |

### langchain-helper.AC7: Core parity for checkpoints

| AC | Criterion (verbatim) | Test type | Expected test file | What the test must assert |
|---|---|---|---|---|
| AC7.1 | **langchain-helper.AC7.1 Success:** Module-level `guard()` and `guard_sync()` accept `actor` and `inputs` and both reach the transport intact. | unit | `tests/unit/guard/test_registry.py` | With a registered test client, `guard_sync(label="checkout.refund", actor="user-1", inputs={...})` records one `RecordedGuard` carrying `actor == "user-1"` and the same `inputs` mapping — neither dropped in the forwarding layer. Repeated for the async module-level `guard()` via `asyncio.run(...)`. Also: with nothing registered, `guard_sync(label="x", actor="u")` returns a decision whose `has_failed_open()` is `True` and does not raise. |
| AC7.2 | **langchain-helper.AC7.2 Success:** Module-level `guard()` with no rules still contacts Guard, because the server selects remote policy by `label`. | unit | `tests/unit/guard/test_registry.py` | `guard(label="support.reply")` with no `rules` argument at all records a `RecordedGuard` with `rules == ()` and `len(client.guards) == 1` — the call was made, not skipped. Both flavors. (The engine-layer counterpart is asserted in `tests/unit/guard/test_checkpoint.py`.) |
| AC7.3 | **langchain-helper.AC7.3 Success:** `RecordedGuard` exposes `actor` and `inputs` so tests assert a checkpoint without a hand-rolled transport. | unit | `tests/unit/guard/test_testing.py` | `guard_sync(label=..., actor=..., inputs=...)` records a `RecordedGuard` exposing `actor` and the same `inputs` mapping, recorded **by identity** (`recorded.inputs is the_mapping_passed`); the async `guard()` likewise via `asyncio.run(...)`; the record stays frozen (`FrozenInstanceError` on assigning `actor`); a call passing neither leaves `actor is None` and `inputs is None`. |

### langchain-helper.AC8: No content mutation

| AC | Criterion (verbatim) | Test type | Expected test file | What the test must assert |
|---|---|---|---|---|
| AC8.1 | **langchain-helper.AC8.1 Success:** Tool arguments and model output are byte-identical before and after a checkpoint, on both allow and deny paths. | unit + integration | *engine level:* `tests/unit/guard/test_checkpoint.py`<br>*real `guard_tool` surface:* `tests/integration/guard/test_langchain.py` | **Engine (Phase 3):** on both the allow and deny paths, a mutable argument object is unchanged afterwards, the `inputs` mapping the client received `is` the mapping passed in, and the returned value is the identical object the callable produced. **Surface (Phase 4):** invoking a guarded tool with a dict argument on both paths leaves the caller's dict unchanged and the tool receives arguments equal to what was passed. |
| AC8.2 | **langchain-helper.AC8.2 Success:** A LIVE sensitive-info detection denies rather than redacting, and raw `LOCAL` input values never appear in the outbound request. | unit | `tests/unit/guard/test_checkpoint.py` | (a) `inputs` reach `guard()` untouched — the engine adds, removes and rewrites nothing — so `_remote_policy.py`'s `LOCAL` digest guarantee is the only thing governing and the engine cannot have bypassed it. (b) A `DENY` whose `reason` reflects sensitive info raises `ArcjetDeniedError`, the callable never runs, and the `inputs` mapping the client received is the identical object passed in. `_remote_policy.py`'s digesting is **not** re-tested here — `tests/unit/guard/test_remote_policy.py` owns it. |

---

## Human verification

### langchain-helper.AC9.1

> **langchain-helper.AC9.1 Success:** The example runs end to end — HTTP entrypoint through agent, guarded tool, background boundary, external action — producing one joined Sequence.

**Why automation is impossible.** Three live resources, none of which exist in CI or in a
test process: a real `ARCJET_KEY` bound to an Arcjet account, a real `OPENAI_API_KEY` for
the agent's model calls, and a human reading the Arcjet Console to confirm the decisions
and captures landed as **one** Sequence on a single `site_id` + `correlation_id`. The
"one joined Sequence" claim is a statement about backend join behavior in a product
surface, not about SDK-local state, so no in-process assertion can stand in for it.

Its supporting mechanism, `langchain-helper.AC6.4`, **is** automated in
`tests/unit/guard/test_sequence_boundary.py`. A green test run evidences the mechanism,
never `langchain-helper.AC9.1` itself.

**Procedure** (record the result in a follow-up comment on the PR, not in the description):

1. `cd examples/fastapi-langchain-guard && cp example.env .env`, then fill in a real
   `ARCJET_KEY` and `OPENAI_API_KEY`.
2. `uv run fastapi dev main.py`
3. `curl` the guarded endpoint with a known session id, e.g. `sess-verify-001`.
4. Confirm the tool ran and the background action completed.
5. In the Arcjet Console, search that correlation ID and confirm **one** Sequence
   containing: the tool checkpoint's decision, its `outcome="success"` capture, the
   chain/model lifecycle captures, and the worker's decision and capture — all on one
   `site_id` + `correlation_id`.
6. Repeat with a prompt-injection payload in the user message; confirm the denial appears
   on the same Sequence with `outcome="denied"` and that the tool did not run.
7. Repeat with a value that trips the sensitive-info rule; confirm it is **denied, not
   redacted** — the tool did not run, and the value was not silently rewritten and passed
   through.

No other criterion in the seven phase files rests on human judgement. The nearest
neighbour is `langchain-helper.AC1.7`'s "existing tests pass unmodified" clause, whose
"unmodified" half is a reviewer's `git diff --stat` check rather than an assertion — see
Coverage risks.

---

## Gate checks

| AC | Criterion (verbatim) | Command that satisfies it |
|---|---|---|
| AC9.2 | **langchain-helper.AC9.2 Success:** `make check` and `make test` pass at ≥80% coverage, and `griffe check arcjet -s src --against origin/main` reports no breaking change. | `make check` and `make test`. The griffe half is `make apicheck`, which `make check` already runs: `uv run griffe check arcjet -s src -e tools/griffe_extensions.py:IgnoreProtobufDescriptors --against origin/main`. The design quotes the command without the `-e tools/griffe_extensions.py:IgnoreProtobufDescriptors` flag this repo requires (`Makefile:18`); **`make apicheck` is the real gate.** |

If `make apicheck` reports a break, do not add the `breaking` label to route around it —
every change in this plan is additive by construction, so a reported break means a public
name was renamed or dropped by accident (likeliest cause: a name lost in Phase 4's
module-to-package conversion).

---

## Coverage risks

**(a) Proven through a test double, not a real transport.**

| AC | Double used | Which existing suite covers the real-transport half |
|---|---|---|
| AC7.1, AC7.2 | `ArcjetTestClient` | Phase 2's own "done when" concedes this asserts *client*-inward, not transport-inward. `ArcjetGuard.guard()` already serialized `actor` / `inputs` before this work; `tests/integration/guard/test_client.py` and `tests/integration/guard/test_remote_policy.py` own client-to-transport. The end-to-end claim is discharged by Phase 4's `guard_tool` tests, which assert against the real `_Transport` in `tests/integration/guard/test_langchain.py`. |
| AC1.1–AC1.6, AC2.1–AC2.4, AC4.2, AC8.1 (engine half) | `StubGuardClient` / `ArcjetTestClient` | Real-transport behavior is not re-tested; the engine only proves it hands values through. `tests/integration/guard/test_client.py` owns the transport. |
| AC8.2 part (a) | `StubGuardClient` | The `LOCAL` digest guarantee itself lives in `_remote_policy.py` and is owned by `tests/unit/guard/test_remote_policy.py`. Phase 3 explicitly declines to re-test it, and explicitly permits the engine-level identity assertion as a substitute if end-to-end assertion "needs a real transport". That escape hatch means AC8.2(a) can end up proving only that the engine passes `inputs` by reference — which is necessary but not the AC's full claim. |
| AC6.4 | `ArcjetTestClient` | No real transport; the AC is about correlation propagation, so this is appropriate. The negative control is what makes it non-vacuous — do not let it be dropped. |

**(b) `langchain-helper.AC5.6`'s import-isolation half can pass vacuously.**
The dev dependency group installs the full `langchain` (Phase 5 Task 1 adds
`"langchain>=1,<2"` to it), so an in-process `import arcjet.guard.langchain` proves
nothing — LangChain *is* importable in the test process. It must be a `subprocess` test
with a `sys.meta_path` finder raising `ImportError` for `langchain.agents*` and
`langgraph*`. **The negative control is mandatory:** the same subprocess must show
`import arcjet.guard.langchain.middleware` *failing* under the blocker. Without it, a
blocker that silently fails to install produces two green assertions and zero evidence.
The same warning applies to `langchain-helper.AC4.1`, where the plan offers
`assert "langchain" not in sys.modules` as "a weaker but acceptable second, cheaper
check" — acceptable only *in addition to* the subprocess test, never instead of it.

**(c) Criteria described only in prose, satisfiable too weakly as written.**

- **`langchain-helper.AC2.4`** reads unconditionally ("An unevaluated policy emits
  `outcome="unavailable"`") but Phase 3 narrows it to the failing-closed path: under
  `on_guard_error="allow"` an unevaluated policy proceeds and the eventual capture
  reports `success` or `error`. The narrowing is correct (it matches the JS reference and
  avoids double-counting one checkpoint on a Sequence) but it lives only in a phase file.
  **The design's AC text should be amended** rather than leaving the reconciliation
  buried in Phase 3.
- **`langchain-helper.AC5.2`**'s top tier is never exercised through the LangChain
  surface. `guard_tool` has no `correlation_id=` parameter, so "an explicit argument
  outranks both" is proven via `guard_action_sync` instead. That is a deliberate design
  choice, but it means the AC as written is not proven on the surface it names — the test
  docstring must say so.
- **`langchain-helper.AC8.1`** says "tool arguments **and model output**". Neither phase
  specifies a test touching model output: Phase 3 asserts the engine returns the
  callable's identical object, Phase 4 asserts a tool's dict argument is unchanged. The
  model-output clause is unexercised. Either read "model output" as the wrapped
  callable's return value (which the identity assertion does cover) or accept the gap
  knowingly — do not let a reader assume a model-output test exists.
- **`langchain-helper.AC1.7`**'s "existing tests pass unmodified" is evidenced by a
  reviewer running `git diff --stat tests/integration/guard/test_langchain.py` and seeing
  additions only. Nothing asserts it; a rewritten test body would still show green.
  Treat the diff check as a required review step, not an optional one.
- **`langchain-helper.AC5.5`** depends on constructing a real `ToolCallRequest`. Phase 5
  forbids hand-rolling a stand-in — the point is that the *real* request shape flows
  through unmodified — but the instruction is prose ("use whatever factory
  `langgraph.prebuilt.tool_node` exposes"). A hand-rolled object would make the test pass
  while proving nothing about LangGraph's request.
- **~~Mechanism risk, `tests/unit/guard/test_checkpoint.py`~~ — RESOLVED before handoff:**
  Phase 3's wrong-flavor-client test originally prescribed `pytest.warns(None)` to assert
  the absence of a "coroutine was never awaited" `RuntimeWarning`. That form was removed in
  pytest 8 and raises `TypeError` on this repo's pinned `pytest==9.0.3` (confirmed by
  running it), so the test could not have run as written. Phase 3 Task 6 now specifies
  `recwarn` / `warnings.catch_warnings(record=True)`, or
  `@pytest.mark.filterwarnings("error::RuntimeWarning")`. Left here as a record of the
  correction, not as an outstanding risk.
