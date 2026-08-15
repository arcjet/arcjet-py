# Guarded-tool review, round two — implementation plan

**Branch:** `rei/fix/guarded-tool-limitations`
**Created:** 2026-08-15
**Delete before merging to main.**

**Goal:** work the 13 findings left from the merge-readiness review. Two of the original
15 are already fixed (pyright import; the awaited-call flavour regression that broke the
repo's own example).

**Commit convention:** one `fix(guard):` commit per finding followed by its
`test(guard):` commit. Where one root cause closes several, one commit naming all of
them.

---

## Progress

- [ ] R1 Guard call skipped entirely when a resolver fails under `allow` (C)
- [ ] R2 Non-reentrant lock deadlocks if a hook re-enters `guard_tool` (H)
- [ ] R3 `_arcjet` / `_arcjet_tool` shadowed by the tool's own state (I)
- [ ] R4 Client bound to a frame local puts the site key in tracebacks (O)
- [ ] R5 Direct surfaces resolve no config (D)
- [ ] R6 `_arguments` filters against the wrong key-space (F)
- [ ] R7 A narrowed `args_schema` is advertised but not enforced (E)
- [ ] R8 Guarding breaks frozen tools and tool classes that hook subclassing (G)
- [ ] R9 `__reduce__` hand-rolls pydantic's state protocol (J)
- [ ] R10 Schema ownership decided by identity a copy destroys (K)
- [ ] R11 Weak class cache regenerates, refiring `__init_subclass__` (L)
- [ ] R12 Blocked report drops values `BaseTool.run` passes (M)
- [ ] R13 Handler output diverges from LangChain's own formatting (N)
- [ ] R14 Runner-ups: deepcopy forking a hand-rolled double, per-call `_signature_of`,
      closure cycle, `GuardClient` export, coverage gaps
- [ ] R15 Doc reconciliation + final gates + delete this plan

---

## Verification rules (learned the hard way this session)

- **Judge gates by exit code**, never by grepping output for success strings:
  `make check >/dev/null 2>&1; echo $?`. A pattern matching `errors,` cannot match
  pyright's `1 error, 0 warnings`, and that is how a real CI failure was reported as
  green last round.
- **`ruff` here selects only `F401` and `I`.** Undefined names are not linted; a
  deleted-but-still-called function passes lint *and* imports. Only calling the line
  fails. Do not treat green ruff as internal consistency.
- Every fix commit needs a test that fails without it:
  `git stash push <file>` → run selector → `git stash pop`.
- `set_config_context` needs `ctx.run(fn)` to take effect.
- pytest: `--no-cov -p no:warnings` for subsets (`fail_under` makes subsets exit 1);
  never add a second `-q`.
- `ty` has one pre-existing diagnostic at `src/arcjet/_analyze/_imports.py:36`. Expect it.
- Compare against `origin/main` before calling something a regression:
  `git archive origin/main -- src | tar -x -C <tmp>` and run the probe there.

---

## R1 — A failed resolver under `allow` skips the guard call (C)

`_fail_closed` wraps actor and input resolution *and* the `guard(...)` call, so a
resolver that raises under `on_guard_error="allow"` skips Guard entirely: the tool runs
and Guard has no record the call happened. Verified: zero recorded guard calls, tool
returned `ok`.

This contradicts the rule stated one branch later in `_arcjet_after_decision` — "Guard
still saw the call, so the decision is on the record" — and the property
`test_a_zero_argument_tool_is_still_guarded` pins with `transport.calls == 2`. A rate
limit or remote policy on the label silently stops counting for exactly the calls whose
actor could not be resolved.

**Fix:** resolution failures degrade the *inputs to* the decision, not the decision. Catch
a failing actor/inputs resolver, record it as unresolved, and still call `guard(...)`.
Only a failure of `guard(...)` itself is a failure to evaluate.

## R2 — Deadlock when a hook re-enters `guard_tool` (H)

`_guarded_classes_lock` is a plain `Lock` held across `type(name, (base,), namespace)`,
which runs the tool class's `__init_subclass__` and pydantic's metaclass — arbitrary code.
A hook that calls `guard_tool` re-enters `_guarded_class` on the same thread and blocks
forever (verified: hung until killed).

**Fix:** `threading.RLock`, or build the class outside the lock. RLock is the smaller
change and is correct for self-re-entry.

## R3 — `_arcjet` / `_arcjet_tool` are shadowed (I)

`_copy_of` copies the tool's state over the generated `PrivateAttr` declarations, so a
tool holding its own `_arcjet` wins and the handle breaks with
`AttributeError: 'str' object has no attribute 'blocking'` — before `_fail_closed`, so
`on_guard_error` does not govern it. `test_guarding_preserves_a_tools_own_private_state`
builds exactly this collision and passes only because it asserts through the delegate.

**Fix:** verify where pydantic actually stores such an attribute (`__dict__` vs
`__pydantic_private__`) before choosing. Then either namespace the guard's own attributes
so a tool cannot collide, or keep the guard state outside the model entirely.

## R4 — The site key becomes reachable from a traceback (O)

`guard = self._arcjet.blocking` binds the client's bound method to a frame local on the
per-call path. `_Policy` carries `repr=False` precisely so the key never lands in a
traceback captured with locals, and this defeats it: `repr()` of the bound method renders
the dataclass, including `_key`. Separately `_Policy.guard` is now written and never read.

**Fix:** do not bind the client to a local on the error path; drop the dead field.

## R5 — Direct surfaces resolve no config (D)

`_run`/`_arun` and the `func`/`coroutine` closures pass `config=None`, so a resolver gets
`{}` on every surface except `invoke`/`ainvoke`/`run`/`arun`. The README's own resolver
raises `KeyError` there. These are the two surfaces this branch newly added.

**Fix:** resolve the ambient config on those surfaces too.

## R6 — `_arguments` filters against the wrong key-space (F)

`_has_derivable_schema` recognises only `SimpleTool`. Verified three shapes: an
`infer_schema=False` StructuredTool hands the resolver `{'args': 'payload'}`; a
`_run(self, *args, **kwargs)` adapter hands it `{}` with every real argument dropped and
no warning; a dict `args_schema` skips filtering entirely and hands over `run_manager` and
`callbacks`, which the docstring says must never be handed over.

**Fix:** use the tool's own `_filter_injected_args` — the helper the blocked report
already uses — rather than re-deriving the rule from `tool_call_schema`.

## R7 — A narrowed `args_schema` is advertised but not enforced (E)

Reassigning `args_schema` on the handle changes only what the model is told; the delegate
still validates and executes against the wide schema, so a hidden `admin_override` still
reaches the body. The docstring calls this "how an application narrows what a model may
send" and the test asserts only the advertisement.

**Fix:** either enforce the narrowed schema before delegating, or stop claiming it
narrows anything. Decide from what the wrapper can honestly guarantee.

## R8 — Guarding breaks frozen tools and subclass-hooking classes (G)

Three verified: a frozen `StructuredTool` subclass makes `guard_tool` itself raise from
`guarded.func = ...`; a validating `__init_subclass__` makes it raise; a registering hook
gains a phantom `ArcjetGuardedX` and holds it strongly.

**Fix:** set the guarded callables without going through validation. For the hooks, the
firing is inherent to subclassing (decided earlier) — but `guard_tool` raising is not:
decide whether to fall back or to fail with a message naming the cause.

## R9 — `__reduce__` hand-rolls pydantic's state protocol (J)

The rebuild replays fields through `setattr` (breaking frozen models — guarding is what
destroys picklability) and the snapshot reads only `__dict__`, losing `__pydantic_extra__`
and inflating `__pydantic_fields_set__` so `model_dump(exclude_unset=True)` emits the full
model on a worker.

**Fix:** use pydantic's own `__getstate__`/`__setstate__` for the handle's state.

## R10 — Schema ownership decided by identity a copy destroys (K)

`_arcjet_owns_schema` compares `args_schema` by identity, but `_copy_of` rebuilds every
dict field with `dict(value)`, so a JSON-schema `args_schema` is never identical and the
wrapper permanently claims ownership — hard-calling `BaseTool.get_input_schema` and
skipping the tool class's own override.

**Fix:** decide ownership by something a faithful copy preserves.

## R11 — Weak class cache regenerates (L)

The generated class is a weak value, so once the last guarded instance is collected the
next `guard_tool` regenerates it and `__init_subclass__` fires again — against the
"once" both the docstring and README state. Request-scoped guarding hits this every GC
cycle.

**Fix:** hold the class strongly (the number of distinct tool *classes* is small and
stable), or stop documenting "once".

## R12 — Blocked report drops what `BaseTool.run` passes (M)

`verbose` is never captured, so `run(x, verbose=True)` prints for allowed calls and not
for denied ones — hiding exactly the call an operator wants. `color`, `name`,
`tool_call_id` and the caller's `**kwargs` are omitted from the callback calls, so a
handler reading `kwargs['tool_call_id']` in `on_tool_error` raises only on blocked calls.

**Fix:** carry them, and reconcile the docstring's "reads exactly what an allowed call's
own run reads".

## R13 — Handler output diverges from LangChain's formatting (N)

`_handle_tool_exception` reimplements `_format_output` and diverges: a `ToolOutputMixin`
return is double-wrapped instead of passed through; a dict is `repr`'d instead of
JSON-encoded; `handle_tool_error=""` is treated as handling where `BaseTool.run` gates on
truthiness and raises.

**Fix:** reuse LangChain's own formatting rather than re-deriving it.

## R14 — Runner-ups

- `copy.deepcopy` of a tool guarded by a hand-rolled double forks the client; main's
  `_GuardMixin.__deepcopy__` shared it unconditionally.
- The copy keeps the *original* handle's `func` closure.
- `_signature_of(delegate._run)` recomputed per call where `_guarded_callables` caches.
- handle → closure → handle reference cycle.
- `@runtime_checkable` on `GuardClient` has no `isinstance` user; `GuardClient` is not
  exported though it now types a public parameter.
- Coverage: the guarded `coroutine` closure and the allowed direct `_arun` path.

## R15 — Close out

Reconcile the README and docstrings with whatever R1–R14 settle — in particular the two
claims currently falsified by R5 and R9, and the `ArcjetGuarded<ClassName>` trace claim
(`on_tool_start` sends `tool.name`; only `repr()` shows the class). Then all gates by
exit code, and `git rm -r` this directory.
