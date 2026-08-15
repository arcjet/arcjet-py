# Guarded-tool review findings — implementation plan

**Branch:** `rei/fix/guarded-tool-limitations`
**Created:** 2026-08-15
**Delete before merging to main** (plans are transient; anything that must outlive the
branch belongs in an ADR).

**Goal:** Fix the verified findings from the `/code-review max` pass, ordered by the four
amplification paths — the ways a defect here would be magnified once the LangChain
helpers branch (`rei/feat/langchain-helpers`) is rebased on top and builds middleware,
capture handlers and Sequence semantics on these primitives.

**Commit convention:** one commit per finding where findings are independent; where one
root-cause fix inherently closes several, ONE commit that names every finding it closes.
Repo convention is a `fix(guard):` commit followed by a `test(guard):` commit.

---

## Progress

Mark each `[ ]` → `[x]` as it lands. This is the recovery point after a context clear.

- [ ] P1.1 `_run`/`_arun` argument binding (F1)
- [ ] P1.2 Schema-rejected arguments on direct surfaces (F2)
- [ ] P2.1 Normalize entrypoints via `BaseTool.invoke` (F3, F4, F5, F8, F9)
- [ ] P2.2 Uniform field sourcing; withdraw config forwarding (F6, F7, F13)
- [ ] P3.1 Faithful wrapper construction (F10)
- [ ] P4.1 `ArcjetTestClient` deepcopy sharing (F11)
- [ ] P5.0 Re-evaluate remaining findings against the new code
- [ ] P5.1 Handler-raised ToolException swallowed (F12)
- [ ] P5.2 pydantic v1 ValidationError (F14)
- [ ] P5.3 Signature-less callable (F15)
- [ ] P5.4 Unpicklable resolvers — doc + error (F16)
- [ ] P5.5 `langchain-core` floor to `>=1.0.2` (F17)
- [ ] P5.6 `allow` mode logs a swallowed failure (F18)
- [ ] P5.7 Unreadable-arguments error carries its cause (F19)
- [ ] P5.8 Fix the unreadable-arguments test (F20)
- [ ] P5.9 Resolve the guard method once (F21)
- [ ] P5.10 Dedupe report-swallow and fail-closed blocks (F22)
- [ ] P5.11 Guard-client Protocol (F23)
- [ ] P6.1 Final gates + README/docstring reconciliation
- [ ] P6.2 Delete this plan directory before opening the PR

---

## Environment notes (cost me time once; do not rediscover)

- `pyproject.toml` `addopts` already contains `-q`. Passing a second `-q` **hides the
  summary line**. Use `uv run pytest tests/ --no-cov -p no:warnings` and read the tail.
- `fail_under = 80` makes **any subset run exit 1** on coverage. Use `--no-cov` for
  subsets; run the full suite with coverage only at the end.
- `set_config_context(cfg)` sets the ambient config inside a **copied context**. Code
  must run via `ctx.run(fn)` to see it:
  ```python
  with set_config_context(ensure_config(cfg)) as ctx:
      ctx.run(lambda: tool.invoke(...))
  ```
  Probing without `ctx.run` makes real ambient-config findings look false. This is how I
  initially mis-refuted three of them.
- Gates: `make lint`, `make typecheck` (ty + pyright), `make apicheck` (griffe vs
  origin/main), `make test`. `ty` reports **one pre-existing diagnostic** at
  `src/arcjet/_analyze/_imports.py:36` — unrelated, expect it, do not "fix" it.
- Scratch probes go in `/home/rei/.claude/jobs/8f077742/tmp/`, never in the repo.

## Falsifiability rule

Every fix commit must be paired with a test that **fails without the production change**.
Verify by:
```bash
git stash push src/arcjet/guard/langchain.py
uv run pytest tests/integration/guard/test_langchain.py --no-cov -p no:warnings -k <selector>
git stash pop
```
Record in the commit message that the test fails without the change.

---

## Path 1 — Direct-call surfaces must uphold the input-rule contract

**Why this amplifies:** the helpers branch routes tool calls through `run_checkpoint` and
records a capture per evaluation. If a surface evaluates policy without the call's
arguments, the Sequence records an evaluation that never saw what it was meant to judge.

### P1.1 — `_run`/`_arun` bind against the wrong signature (F1)

**File:** `src/arcjet/guard/langchain.py`, `_GuardMixin._run` / `_arun`.

**Defect (verified):** binds the call against the delegate's raw `_run` signature. For
`Tool`/`StructuredTool` that is `(*args, config, run_manager, **kwargs)`, so
`apply_defaults()` yields `{'args': (), 'config': ..., 'run_manager': None, 'kwargs':
{real args}}`. The resolver is then skipped (StructuredTool: schema rejects that shape)
or handed the scaffolding mapping, and the body still runs under `deny`.

Probe result: `guarded._run(x='secret', config={})` → resolver never called, guard got
`inputs=None`, body returned `ran:secret`.

**Fix:** post-process the bound mapping before it becomes the resolver's view —
expand the `VAR_KEYWORD` parameter into the top level, drop `VAR_POSITIONAL`, and drop
framework-supplied names (`run_manager`, `callbacks`, `config`; `BaseTool.FILTERED_ARGS`
covers the first two). Apply in `_call_arguments` so `func`/`coroutine` benefit too.

**Test:** `_run` with an inputs resolver hands the resolver the tool's real arguments.

### P1.2 — Schema-rejected arguments still execute the body (F2)

**File:** `src/arcjet/guard/langchain.py`, `_arcjet_resolve_inputs` ValidationError branch.

**Defect (verified):** the branch returns `None` (evaluate without inputs) on the premise
that "the tool's own schema rejects the call too and its body never runs". True for
`invoke`/`run`; false for `func`/`coroutine`/`_run`/`_arun`, which do no validation.

Probe result: `guarded.func(amount=-5)` against `args_schema` requiring `amount >= 0`
returned `charged` with the resolver never called, under the `deny` default.

**Fix:** thread a flag through the evaluate path recording whether the caller is a
validating surface. `invoke`/`run` → validated (keep today's behaviour). Direct callables
and `_run`/`_arun` → not validated, so a ValidationError is a genuine
`_UnreadableArguments` and `on_guard_error` governs it (deny by default).

**Test:** `guarded.func` with schema-rejected arguments raises `ArcjetToolUnavailableError`
under `deny` and does not run the body; the `invoke` path keeps returning the tool's own
`handle_validation_error` message.

---

## Path 2 — Config plumbing

**Why this amplifies:** the helpers branch IS middleware and callback handlers — code
whose whole job is riding LangChain's config propagation. Resolver-blindness and merge
corruption would be inherited wholesale by `ArcjetMiddleware` and the capture handlers.

### P2.1 — Normalize entrypoints via `BaseTool.invoke` (F3, F4, F5, F8, F9)

**File:** `src/arcjet/guard/langchain.py`, `_GuardMixin`.

**Defects (all verified):**
- F3: resolvers see `{}` where the delegate sees the inherited ambient config.
- F4: blocked reports never reach ambient tracers.
- F5: `run(..., callbacks=[h])` (the AgentExecutor path) reports nothing on a denial.
- F8: handle callbacks + positionally-passed callbacks → `TypeError: got multiple values`.
- F9: blocked report invents a run id instead of using the caller's `run_id`/`run_name`.

**Root cause:** the wrapper overrides `invoke`/`ainvoke` and hand-rolls its own config
plumbing, so it never runs `ensure_config` and never sees `run()`'s keyword dialect.

**Fix — stop overriding `invoke`/`ainvoke`.** `BaseTool.invoke` already calls
`_prep_run_args(input, config, **kwargs)`, which runs `ensure_config` (ambient
resolution), unwraps a `ToolCall` into `tool_input` + `tool_call_id`, and normalizes
`callbacks`, `tags`, `metadata`, `run_name`, `run_id`, `config` into `run()` kwargs. It
then calls `self.run(...)` — our guarded `run`. Result: one checkpoint per call, one
canonical view, and a tool class that overrides `invoke` itself keeps its override.

Give `run`/`arun` the real `BaseTool.run`/`arun` signature (named `verbose`,
`start_color`, `color`, `callbacks`, then keyword-only `tags`, `metadata`, `run_name`,
`run_id`, `config`, `tool_call_id`, `**kwargs`) instead of `*args, **kwargs`, so the
positional and keyword forms both land in named parameters — which is what removes the
collision in F8 rather than patching around it.

Pass the normalized values to the checkpoint and to the blocked report: `config` for the
resolvers, and `callbacks`/`tags`/`metadata`/`run_id`/`run_name` for the report.

`_unwrap_tool_call` becomes dead for the invoke path — check whether any caller remains
before deleting it.

**Tests:** ambient config reaches an actor resolver; a denial reaches an ambient tracer;
`run(..., callbacks=[h])` reports a denial; positional callbacks do not crash; the blocked
report carries the caller's `run_id`.

### P2.2 — Uniform field sourcing; withdraw the config forwarding (F6, F7, F13)

**File:** `src/arcjet/guard/langchain.py`, `_arcjet_child_config` / `_arcjet_run_kwargs`.

**Defects (all verified):**
- F6: `merge_configs(config, own)` runs `ensure_config` on the fragment, resurrecting the
  ambient config — same handler ambient + explicit fires **twice**
  (`start,start,end,end` vs unguarded `start,end`); with `config=None` and handle
  callbacks, the ambient handler is **dropped entirely**.
- F7: folding the handle's callbacks into the config makes them *inheritable*, so a
  tool-local handler now also fires for the tool body's internal child runs
  (`tool_start, chain_start, chain_end, tool_end` vs unguarded `tool_start, tool_end`).
- F13: `handle_tool_error` is read off the handle on the blocked path but off the delegate
  on allowed calls — one field, opposite behaviour by error source.

**Decision — revert commit `cf16838` ("let fields attached to the guarded handle reach
every call").** That commit closed the old "limitation 7" but bought it with F6, F7 and
F8. The earlier analysis had explicitly listed item 7 as the one to leave. The finding
that actually mattered was the *asymmetry* (a late-attached handler seeing only denials),
and that is fixed by making both paths read the same source, not by forwarding.

**Fix:** delete `_arcjet_child_config` and `_arcjet_run_kwargs`. Delegate with the
normalized kwargs unchanged. Make the blocked report configure from
`(caller's callbacks, delegate.callbacks, delegate.verbose, caller's tags,
delegate.tags, caller's metadata, delegate.metadata)` and read `handle_tool_error` off
the **delegate**, matching what an allowed call's own run would do.

Net contract: fields reassigned on the guarded handle after `guard_tool()` affect
neither path — uniform, and documented as a known gap in the README and the `guard_tool`
docstring.

**Tests:** no double-fire when a handler is both ambient and explicit; the ambient handler
still fires when `config=None`; a tool with internal child runs reports the same events
guarded and unguarded; denial handling follows the delegate's `handle_tool_error`.
Update/remove the three tests added by `cf16838` and `c357643`, which pin the withdrawn
behaviour.

---

## Path 3 — Faithful wrapper construction

**Why this amplifies:** the helpers branch wraps a much wider zoo of tool shapes; each
shape multiplies the chance of silently hitting one of these.

### P3.1 — `wrapper(**values)` loses aliases and extras, and crashes (F10)

**File:** `src/arcjet/guard/langchain.py`, `guard_tool`.

**Defects (all verified):**
- A field with an alias (`Field(default=3, alias="maxHits")`) constructed as `5` yields a
  handle reading `3` — `BaseTool`'s `extra="ignore"` swallows the field-name kwarg.
- An `extra="allow"` tool's instance attribute is absent from the handle
  (`AttributeError`) while the delegate has it.
- A tool class whose `__init__` takes a required non-field parameter cannot be guarded:
  `TypeError: ClientTool.__init__() missing 1 required positional argument: 'client'`.

Because `__reduce__` snapshots the handle's `__dict__`, the infidelity also survives
pickling.

**Fix:** stop re-running the class's `__init__`/validation. Construct via
`wrapper.__new__(wrapper)` and copy pydantic's state directly with `object.__setattr__`:
`__dict__` (with the existing one-level container copy applied to list/dict values),
`__pydantic_fields_set__`, `__pydantic_extra__`, `__pydantic_private__`. Then set
`_arcjet_tool` and `_arcjet`.

Verify with probes before committing: aliased field preserved, extras present, a class
with a required `__init__` parameter guards successfully, and private attrs carry over.

**Test:** all four shapes above.

---

## Path 4 — Test double parity

**Why this amplifies:** the helpers branch's own test suite leans on `ArcjetTestClient`
heavily; a forking recorder makes those tests assert against empty lists.

### P4.1 — `ArcjetTestClient` forks on deepcopy (F11)

**File:** `src/arcjet/guard/testing.py`, `ArcjetTestClient`.

**Defect (verified):** the two real clients gained `__deepcopy__ = _shared_with_copies`;
the test client did not, so `copy.deepcopy(guarded_tool)` duplicates the recorder and the
original `client.guards` stays empty while the clone records.

**Fix:** `__deepcopy__ = _shared_with_copies` on `ArcjetTestClient` (already importable
from `._client`, which `testing.py` imports from).

**Test:** deepcopy a tool guarded by an `ArcjetTestClient`, invoke the clone, assert the
original client recorded the call.

---

## Path 5 — Remaining findings

### P5.0 — Re-evaluate first

Before fixing, re-check each against the post-Path-1..4 code; some are expected to be
already closed (F13 by P2.2; part of F21 by P2.2 deleting the per-call merges). Record
the verdict for each in this file before acting.

### P5.1 — Handler-raised ToolException swallowed (F12)
`_arcjet_blocked`'s `except ToolException: pass` cannot tell the no-handler re-raise from
a `ToolException` the handler itself raised, so the handler's exception is discarded and
the denial is raised instead. Verified: a handler raising `ToolException('quota
exhausted')` produced `ArcjetToolDeniedError`. Fix: decide from the handler's
configuration (`handle_tool_error` falsy → re-raise) rather than catching, or re-raise
only when the caught exception *is* the same object.

### P5.2 — pydantic v1 ValidationError (F14)
`except ValidationError` catches only v2, but langchain-core accepts `pydantic.v1`
`args_schema` and `BaseTool.run` catches both. Verified: a v1-schema tool returns its
handled message unguarded and raises `ArcjetToolUnavailableError` (cause `None`) guarded.
Fix: catch both flavours, as `BaseTool.run` does.

### P5.3 — Signature-less callable (F15)
`_guarded_callables` calls `inspect.signature()` unconditionally, so
`Tool(func=time.time)` raises `ValueError: no signature found for builtin`. Fix: tolerate
the failure and fall back to passing the call's kwargs through as the resolver view.

### P5.4 — Unpicklable resolvers (F16)
`__reduce__` pickles `policy.actor`/`policy.inputs` verbatim, so a lambda resolver — the
shape the README's own example uses — makes a guarded tool unpicklable even though the
tool pickles. Cannot be fixed generally. Fix: narrow the README claim and raise a clear
error naming the resolver rather than letting pickle blame the lambda.

### P5.5 — `langchain-core` floor (F17)
`_arcjet_start_args` calls `BaseTool._filter_injected_args`, added in langchain-core
1.0.2, but the extra pins `>=1,<2`. Fix: raise the floor to `>=1.0.2` in the `langchain`
extra and the dev dependency. **Verify the 1.0.0/1.0.1 absence claim first** — it came
from a finder's wheel inspection, not my own probe.

### P5.6 — `allow` mode swallows silently (F18)
Under `on_guard_error="allow"` the trailing `except Exception` swallows resolver and
client failures with no log line, while the sibling unreadable-arguments path warns.
Pre-existing on main. Fix: log a warning naming the action, matching the sibling.

### P5.7 — Unreadable-arguments error hides its cause (F19)
The `except _UnreadableArguments` sites raise `ArcjetToolUnavailableError` without a
cause, and `__init__` sets `__cause__` unconditionally so context is suppressed even when
`None`. Fix: carry the original exception through as the cause; only set `__cause__` when
one was supplied.

### P5.8 — Unreadable-arguments test is vacuous (F20)
`test_unreadable_arguments_still_reach_the_checkpoint` uses a dict (JSON-schema)
`args_schema` whose `_parse_input` passes dicts through, so the arguments are readable and
the named path is never exercised. Fix: make the arguments genuinely unreadable.

### P5.9 — Resolve the guard method once (F21)
`_blocking`/`_awaitable` re-resolve the client's flavour on every call though the frozen
`_Policy` fixes it. Fix: resolve in `guard_tool`, store on `_Policy`. Keep the wrong-
flavour `TypeError` behaviour and its test.

### P5.10 — Dedupe report-swallow and fail-closed (F22)
The `_reporting` swallow is hand-rolled again in both `_arcjet_open_run` variants (the
warning string lives in three places) and the fail-closed except-chain is duplicated
between the evaluators. Fix: reuse `_reporting`; extract the fail-closed chain the way
`_arcjet_after_decision` already is.

### P5.11 — Guard-client Protocol (F23)
`guard_tool` types `guard` as the nominal union while dispatch and the README define a
structural contract, forcing `cast(Any, ...)` at every documented test wiring. Fix: a
`Protocol` in `_client.py` (precedent: the transport Protocols there), used by
`guard_tool`; drop the casts in the repo's own tests. Run `make apicheck` — this touches a
public signature.

---

## Path 6 — Close out

### P6.1 — Final gates and doc reconciliation
`make check` clean (bar the known `_imports.py` diagnostic), `make test` green, then
reconcile the README's `guard_tool` section and the module/`guard_tool` docstrings with
the final behaviour — in particular the withdrawn late-attached-fields claim from P2.2 and
the resolver-pickling caveat from P5.4.

### P6.2 — Delete this plan
`git rm -r docs/implementation-plans/2026-08-15-guarded-tool-review-findings/` before
opening the PR. Anything that must outlive the branch goes in an ADR in the `arcjet`
monorepo's `docs/adrs/`, not here.
