# LangChain Framework Helper — Phase 5: Agent middleware

**Goal:** `create_agent` applications guard tool calls at the parsed-argument boundary.

**Architecture:** `ArcjetMiddleware` implements LangChain's `AgentMiddleware.wrap_tool_call` / `awrap_tool_call`, which see a tool call's parsed and validated arguments immediately before execution and may short-circuit by not invoking `handler`. It translates the request into a call against Phase 3's checkpoint engine and mutates nothing. Because the middleware types import from LangGraph, it lives in its own module behind a new `langchain-agents` extra, leaving the existing `langchain` extra — and every `guard_tool` user — free of LangGraph.

**Tech Stack:** Python 3.10+, `langchain>=1,<2` (which pulls LangGraph), pytest 9.0.3.

**Scope:** Phase 5 of 7 from `docs/design-plans/2026-08-13-langchain-helper.md`.

**Dependencies:** Phase 4.

**Codebase verified:** 2026-08-13

---

## Acceptance Criteria Coverage

This phase implements and tests:

### langchain-helper.AC5: LangChain surfaces
- **langchain-helper.AC5.4 Failure:** `ArcjetMiddleware` denying a tool call short-circuits without invoking `handler`.
- **langchain-helper.AC5.5 Success:** An allowed middleware call passes the request through with `tool_call` unmodified.
- **langchain-helper.AC5.6 Success:** Both `wrap_tool_call` and `awrap_tool_call` are exercised, and `import arcjet.guard.langchain` succeeds with `langchain` absent (only `langchain-core` installed).

---

## Design gap this phase fills

The design's contract names `policies: Mapping[str, ToolPolicy]` but never defines `ToolPolicy`. It is specified here: a frozen slotted dataclass describing how one tool is guarded, keyed by tool name. A tool with no entry passes through unguarded — opt-in, so adding the middleware cannot silently start blocking tools nobody configured.

## Dependency facts

From `../../../../arcjet/docs/adrs/2026-08-13-python-langchain-helper-layering.md`, verified there against `langchain==1.3.14`:

- `langchain` declares `Requires-Dist: langgraph<1.3.0,>=1.2.5`.
- `langchain/agents/middleware/types.py:29` — `from langgraph.prebuilt.tool_node import ToolCallRequest, ToolCallWrapper`.
- `:383` — `AgentMiddleware[StateT, ContextT, ResponseT]`.
- `:662` / `:744` — `wrap_tool_call` / `awrap_tool_call`. The request exposes parsed, validated `request.tool_call["args"]` and a `request.override(...)`; `handler` may be called zero, one, or many times, so short-circuiting is supported.
- `:732` — `NotImplementedError` when only one of sync/async is defined. Both must be implemented.

**That ADR is a draft research dossier and says so: "re-verify before merge if those have moved."** The current lockfile has `langchain-core==1.5.1` and **no `langchain` and no `langgraph`** — this phase installs them for the first time. Task 1 therefore verifies the API against the actually-installed wheel before any code is written against it. Do not write against the line numbers above; write against what Task 1 prints.

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: Add the `langchain-agents` extra and verify the installed middleware API

**Verifies:** None — dependency setup, verified operationally.

**Files:**
- Modify: `pyproject.toml` — new optional-dependency entry, and a dev-group entry
- Modify: `uv.lock` — regenerated

**Step 1: Add the extra**

In `[project.optional-dependencies]`, leave `langchain` exactly as it is and add:

```toml
langchain = ["langchain-core>=1,<2"]
# Agent middleware only. Separate from `langchain` because the full
# `langchain` package hard-depends on LangGraph, and folding it into the
# extra above would push LangGraph onto every `guard_tool` user.
langchain-agents = ["langchain>=1,<2"]
```

Add `"langchain>=1,<2"` to the `dev` dependency group, next to the existing `langchain-core` line, so CI exercises the middleware. CI runs a bare `uv run pytest` with no extra selection, so anything not in the dev group is never tested.

**Step 2: Resolve and install**

Record `langchain-core`'s currently-locked version **before** re-resolving, because adding `langchain>=1,<2` forces a full re-resolve that may move it:

```bash
BEFORE=$(uv pip list | awk '$1=="langchain-core"{print $2}'); echo "before: $BEFORE"
uv lock && uv sync
uv pip list | grep -iE '^(langchain|langchain-core|langgraph) '
AFTER=$(uv pip list | awk '$1=="langchain-core"{print $2}'); echo "after: $AFTER"
[ "$BEFORE" = "$AFTER" ] || echo "WARNING: langchain-core moved $BEFORE -> $AFTER"
```
Expected: all three present, and **`langchain-core` unchanged at 1.5.1**.

If it moved, stop and decide deliberately. Phase 4's `guard_tool` work was written and verified against `langchain-core==1.5.1`, and Phase 7's example pins `langchain==1.3.14`; silently re-resolving core underneath means Phase 4's tests are now running against a version nobody checked. Either pin `langchain-core` to hold it, or re-run Phase 4's suite and record the new version in this task's commit message. Do not let a resolver change the verified baseline unremarked.

**Step 3: Verify the middleware API against the installed wheel**

```bash
uv run python - <<'PY'
import inspect
from langchain.agents.middleware.types import AgentMiddleware
from langgraph.prebuilt.tool_node import ToolCallRequest

for name in ("wrap_tool_call", "awrap_tool_call"):
    fn = getattr(AgentMiddleware, name)
    print(name, inspect.signature(fn))
print("override:", hasattr(ToolCallRequest, "override"))
print("ToolCallRequest fields:", getattr(ToolCallRequest, "__annotations__", {}))
PY
```
Expected: both hooks exist with a `(self, request, handler)` shape. **If the signatures differ from what this plan assumes, the signatures win** — adjust Task 2 and say so in the commit message.

Confirm the LangGraph coupling is real, which is the whole justification for a second extra:
```bash
uv run python -c "
import langchain.agents.middleware.types as t, inspect
assert 'langgraph' in inspect.getsource(t), 'expected a langgraph import'
print('ok')
"
```

**Step 4: Confirm the base extra stayed clean**

```bash
uv run python -c "
import tomllib, pathlib
d = tomllib.loads(pathlib.Path('pyproject.toml').read_text())
extras = d['project']['optional-dependencies']
assert extras['langchain'] == ['langchain-core>=1,<2'], extras['langchain']
assert 'langchain-agents' in extras
print('ok')
"
```
Expected: `ok`. The `langchain` extra must not have grown.

**Step 5: Commit**

```bash
git add pyproject.toml uv.lock
git commit -m "deps: add the langchain-agents extra for agent middleware"
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: `ArcjetMiddleware`

**Verifies:** langchain-helper.AC5.4, langchain-helper.AC5.5

**Files:**
- Create: `src/arcjet/guard/langchain/middleware.py`

**Implementation:**

Public module, not underscore-prefixed: it is the documented import path, `from arcjet.guard.langchain.middleware import ArcjetMiddleware`. It is deliberately **not** imported from `src/arcjet/guard/langchain/__init__.py` — doing so would make `import arcjet.guard.langchain` fail without LangGraph, breaking `langchain-helper.AC5.6`.

```python
"""Arcjet policy checkpoints as LangChain agent middleware.

Install ``arcjet[langchain-agents]``.  This module imports ``langchain``,
which pulls in LangGraph; :mod:`arcjet.guard.langchain` deliberately does not
import it, so ``guard_tool`` keeps working with only ``langchain-core``.

``wrap_tool_call`` sees a tool call's parsed, validated arguments immediately
before execution and may decline to call ``handler`` at all, which is what
makes it an enforcement point rather than an observation point.  Nothing here
rewrites a request: ``request.override(...)`` exists and is deliberately
unused, per the no-mutation rule in the checkpoint ADR.
"""
```

`ToolPolicy` — how one tool is guarded:

```python
@dataclass(frozen=True, slots=True)
class ToolPolicy:
    """How one tool's calls are checked.

    Args:
        action: The label for this checkpoint, e.g. ``"email.sent"``.
            Convention is ``resource.verb`` in the past tense.
        rules: Bound rule inputs. Empty is normal and still contacts Guard,
            because the server selects remote policy by ``action``.
        actor: Who is acting — a string, or a callable taking the tool call's
            parsed arguments.
        inputs: Values offered for policy evaluation — a mapping, or a
            callable taking the parsed arguments.
        metadata: Metadata attached to this checkpoint's capture.
    """

    action: str
    rules: Sequence[RuleWithInput] = ()
    actor: Optional[Union[str, Callable[[Mapping[str, Any]], Optional[str]]]] = None
    inputs: Optional[
        Union[PolicyInputMap, Callable[[Mapping[str, Any]], PolicyInputMap]]
    ] = None
    metadata: Optional[Metadata] = None
```

`ArcjetMiddleware`:

```python
class ArcjetMiddleware(AgentMiddleware):
    def __init__(
        self,
        *,
        guard: Union[ArcjetGuard, ArcjetGuardSync],
        policies: Mapping[str, ToolPolicy],
        on_guard_error: OnGuardError = "deny",
    ) -> None:
```

Store `dict(policies)` — a defensive copy of the *configuration*, which is not the caller's live data and must not change under the agent mid-run. This is unrelated to the no-mutation rule, which is about tool arguments and model output.

`wrap_tool_call(self, request, handler)`:

1. Look up `request.tool_call["name"]` in `self._policies`. Miss → `return handler(request)` unchanged. No guard call, no capture.
2. Require `ArcjetGuardSync`, raising `TypeError` otherwise — mirroring the guard-flavor check at the top of `_GuardedTool.invoke` in `_tool.py`. (Find it by symbol, not line number: Phase 4 Task 1 `git mv`s the file and strips its docstring and `__all__`, so every line number in it has shifted.) `awrap_tool_call` requires `ArcjetGuard`.
3. Read `args = request.tool_call["args"]`. Do not copy it, do not normalize it — LangChain already parsed and validated it, which is the reason this hook is a better enforcement point than wrapping the tool.
4. Call `run_checkpoint_sync(lambda: handler(request), action=policy.action, guard=self._guard, prepare=..., rules=policy.rules, metadata=policy.metadata, on_guard_error=self._on_guard_error)`, with `prepare` resolving `policy.actor` / `policy.inputs` against `args`.
5. Let denial propagate. `ArcjetDeniedError` is raised by the engine before `handler` is ever called, which is the short-circuit `langchain-helper.AC5.4` asserts. Do not catch it — there is no `handle_tool_error` at this layer, and converting it into a passing result would hide an enforced denial from the agent.

Correlation: pass no `correlation_id`, so the engine falls back to the ambient ContextVar. The middleware has no `RunnableConfig` in hand at this hook, so the two-tier core precedence is the whole rule here.

`awrap_tool_call` is the same with `await run_checkpoint(...)` and `await handler(request)`. **Both must be defined** — `AgentMiddleware` raises `NotImplementedError` when only one is.

**Verification:**
```bash
uv run python -c "
from arcjet.guard.langchain.middleware import ArcjetMiddleware, ToolPolicy
assert callable(ArcjetMiddleware.wrap_tool_call)
assert callable(ArcjetMiddleware.awrap_tool_call)
print('ok')
"
make check
```
Expected: `ok`, then clean.

**Commit:** `feat(guard): add ArcjetMiddleware for LangChain agents`
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (task 3) -->

<!-- START_TASK_3 -->
### Task 3: Tests for the middleware and the import isolation

**Verifies:** langchain-helper.AC5.4, langchain-helper.AC5.5, langchain-helper.AC5.6

**Files:**
- Create: `tests/integration/guard/test_langchain_middleware.py` (integration)

**Implementation:**

Drive the hooks directly rather than standing up a real agent. `wrap_tool_call(request, handler)` is an ordinary method; a test supplies a `ToolCallRequest` and a handler that records whether it ran. That keeps the test about Arcjet's behavior instead of LangGraph's execution model.

Build the `ToolCallRequest` the way the installed version requires — Task 1 printed its fields. If constructing one directly is awkward, use whatever factory `langgraph.prebuilt.tool_node` exposes; do not hand-roll a stand-in object, because the point is that the real request shape flows through unmodified.

Reuse the Phase 3 stub client (allow / deny / raise) and the shared autouse fixture from Phase 1 Task 5 (already active in this directory).

**Testing:**

- **langchain-helper.AC5.4:** With a policy whose checkpoint denies, calling `wrap_tool_call` raises `ArcjetDeniedError` **and the handler's call-counter is still 0**. Asserting the counter is the criterion — an exception alone does not prove the handler was skipped rather than run-then-discarded. Repeat for `awrap_tool_call`.
- **langchain-helper.AC5.5:** With an allowing checkpoint, `handler` ran exactly once and received the *same request object* (`received is request`). Assert `request.tool_call["args"]` is unchanged and equal to what was constructed — no key added, removed, or rewritten. Assert the middleware's return value is the handler's return value. Repeat for both flavors.
- **langchain-helper.AC5.6 (both hooks):** Both are covered by the two criteria above; make sure each has an async counterpart driven from a plain `def test_*` via `asyncio.run(...)`.
- **langchain-helper.AC5.6 (import isolation):** The critical one, and it cannot be an in-process import check because the dev group now installs the full `langchain`. Run a `subprocess` with `python -c` that installs a `sys.meta_path` finder raising `ImportError` for `langchain.agents*`, `langgraph*`, then does `import arcjet.guard.langchain; from arcjet.guard.langchain import guard_tool`. Assert exit code 0 and empty stderr. Add the mirror-image check that `import arcjet.guard.langchain.middleware` under the same blocker **fails**, proving the blocker actually bites and the first assertion is not vacuous.
- **Unconfigured tools pass through:** a tool name absent from `policies` reaches `handler` with no guard call and no capture recorded. This pins the opt-in behavior.
- **`on_guard_error`:** with a client whose `guard` raises, the default denies (handler not called) and `"allow"` passes through (handler called once).
- **Capture:** an allowed call inside `arcjet_sequence(correlation_id="corr-1")` emits one capture with that correlation ID and `outcome="success"`; a denied one emits `outcome="denied"`.

**Verification:**
```bash
uv run pytest tests/integration/guard/test_langchain_middleware.py -q
make test
make check
```
Expected: all pass, coverage ≥80%, clean, `make apicheck` reports no breaking change.

**Commit:** `test(guard): cover ArcjetMiddleware and langchain import isolation`
<!-- END_TASK_3 -->

<!-- END_SUBCOMPONENT_B -->

---

## Phase 5 done when

- A denied tool call short-circuits without invoking `handler`.
- An allowed call passes through with `tool_call` unmodified.
- Both sync and async hooks are exercised.
- `import arcjet.guard.langchain` still works with `langchain` and `langgraph` unimportable, proven in a subprocess.
- `make test` passes at ≥80% coverage and `make check` is clean.
