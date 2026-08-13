# LangChain Framework Helper — Phase 6: Capture callback handler

**Goal:** Sequence coverage across the chain and model lifecycle, where blocking is impossible.

**Architecture:** `ArcjetCaptureHandler` implements `langchain_core.callbacks.BaseCallbackHandler`, emitting a capture on chain, model, and tool start/end/error. It is **observe-only**: LangChain's callback dispatch inspects no return value, so a callback physically cannot block a call. That makes callbacks the right home for capture and the wrong home for policy — the rule `../../../../arcjet/docs/adrs/2026-08-06-eve-guard-surfaces.md` generalises from Eve. The handler never evaluates policy and never raises into LangChain.

**Tech Stack:** Python 3.10+, `langchain-core>=1,<2`, pytest 9.0.3.

**Scope:** Phase 6 of 7 from `docs/design-plans/2026-08-13-langchain-helper.md`.

**Dependencies:** Phase 4.

**Codebase verified:** 2026-08-13

---

## Acceptance Criteria Coverage

This phase implements and tests:

### langchain-helper.AC5: LangChain surfaces
- **langchain-helper.AC5.7 Success:** `ArcjetCaptureHandler` emits captures across a chain run sharing that run's correlation ID.
- **langchain-helper.AC5.8 Failure:** A capture failure inside the callback handler never raises into LangChain.

---

## Why this is capture-only

`langchain_core/callbacks/manager.py` dispatches handlers without inspecting any return value — the evidence cited in `../../../../arcjet/docs/adrs/2026-08-13-python-langchain-helper-layering.md`. A handler cannot deny, cannot rewrite, and cannot delay. Enforcement lives in `guard_tool` (Phase 4) and `ArcjetMiddleware` (Phase 5). This module must never call `guard()` — say so in the module docstring, because a future reader will otherwise try to add it.

Belongs in the `langchain` extra, not `langchain-agents`: `BaseCallbackHandler` is a `langchain-core` type with no LangGraph involvement.

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: Verify the installed callback API

**Verifies:** None — verified operationally, so Task 2 is written against the real signatures.

**Step 1: Print what is actually installed**

```bash
uv run python - <<'PY'
import inspect
from langchain_core.callbacks import AsyncCallbackHandler, BaseCallbackHandler

for cls in (BaseCallbackHandler, AsyncCallbackHandler):
    print("===", cls.__name__)
    for name in sorted(n for n in dir(cls) if n.startswith("on_")):
        print(" ", name, inspect.signature(getattr(cls, name)))
    for prop in ("raise_error", "ignore_chain", "ignore_llm", "ignore_agent"):
        print(" prop", prop, getattr(cls, prop, "<absent>"))
PY
```

Record the exact signatures of `on_chain_start`, `on_chain_end`, `on_chain_error`, `on_llm_start`, `on_llm_end`, `on_llm_error`, `on_tool_start`, `on_tool_end`, `on_tool_error`, and note which kwargs (`run_id`, `parent_run_id`, `tags`, `metadata`) each receives. **Task 2 is written against this output, not against memory.**

Also note the `raise_error` class attribute. LangChain swallows handler exceptions when it is falsy — do **not** rely on that for `langchain-helper.AC5.8`. The handler must swallow its own errors so it is safe even under `raise_error = True`.

**Step 2: Commit**

No code change. Record the findings in the Task 2 commit message instead.
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: `ArcjetCaptureHandler` and `ArcjetAsyncCaptureHandler`

**Verifies:** langchain-helper.AC5.7, langchain-helper.AC5.8

**Files:**
- Create: `src/arcjet/guard/langchain/callbacks.py`

**Implementation:**

```python
"""Observe-only capture across the LangChain lifecycle.

Callbacks are dispatched without their return value being inspected, so a
handler here cannot deny a call, rewrite it, or delay it.  That makes this the
right home for capture and the wrong home for policy: enforcement lives in
``guard_tool`` and ``ArcjetMiddleware``.  **Never call guard() from this
module.**

Needs only ``arcjet[langchain]`` — ``BaseCallbackHandler`` is a
``langchain-core`` type and involves no LangGraph.
"""
```

Constructor:

```python
class ArcjetCaptureHandler(BaseCallbackHandler):
    def __init__(
        self,
        *,
        guard: Union[ArcjetGuard, ArcjetGuardSync, None] = None,
        correlation_id: Optional[str] = None,
        metadata: Optional[Metadata] = None,
        prefix: str = "langchain",
    ) -> None:
```

- `guard=None` routes through the free `capture()`, so a registered client works with no wiring.
- `correlation_id` is the explicit tier; omitted, each event resolves the ambient ContextVar **at emit time**, not at construction. A handler is typically built once and reused across runs, so binding the ID at construction would stamp every later run with the first run's Sequence. This is the single most important detail in the module — comment it.
- `prefix` builds action names: `f"{prefix}.chain.started"`, `.chain.completed`, `.chain.failed`, and the same for `.model.` and `.tool.`. Past tense, `resource.verb`, per the capture ADR.

Every hook body reduces to one guarded call:

```python
    def _emit(self, action: str, **extra: Any) -> None:
        """Record one lifecycle event. Never raises.

        A callback that throws would surface as a failure of the chain it was
        only watching. Capture is best-effort telemetry; an observation problem
        must never become the application's problem.
        """
        try:
            correlation_id = (
                self._correlation_id
                if self._correlation_id is not None
                else current_correlation_id()
            )
            metadata = {**(self._metadata or {}), **extra}
            payload = dict(
                action=action, correlation_id=correlation_id, metadata=metadata
            )
            if self._guard is None:
                _registry_capture(**payload)
            else:
                self._guard.capture(**payload)
        except Exception:
            logger.warning("arcjet: failed to capture %r", action)
```

Catch `Exception` — not `BaseException` — so `KeyboardInterrupt` and `SystemExit` still propagate.

Put `run_id` and `parent_run_id` into the event metadata as strings when the installed signatures provide them: they are what let a Console reader see the shape of a run inside one Sequence. Do **not** use `run_id` *as* the correlation ID; correlation is derived from the user-facing session, per the Eve ADR.

Do not put chain inputs, model prompts, or tool outputs into metadata. Metadata is untrusted and must not carry secrets or PII, and this handler sees exactly the raw user content the rest of the design refuses to move. Record shapes — names, counts, run ids — never content. This is a hard rule; state it in the docstring.

`ArcjetAsyncCaptureHandler(AsyncCallbackHandler)` mirrors it with `async def` hooks calling the *same synchronous* `_emit`. `capture()` queues and returns on both client flavors, so there is nothing to await and no second code path.

Both classes are exported from this module only, not from `arcjet.guard.langchain.__init__`, matching how `guard_tool` and `middleware` are kept separable.

**Verification:**
```bash
uv run python -c "
from arcjet.guard.langchain.callbacks import ArcjetCaptureHandler
from arcjet.guard.testing import register_test_client
from arcjet.guard import arcjet_sequence
with register_test_client() as aj:
    h = ArcjetCaptureHandler()
    with arcjet_sequence(correlation_id='corr-1'):
        h.on_chain_start({'name': 'x'}, {})
    assert aj.captures and aj.captures[0].correlation_id == 'corr-1'
    print('ok', aj.captures[0].action)
"
make check
```
Expected: `ok langchain.chain.started`, then clean. Adjust the `on_chain_start` argument shape to whatever Task 1 printed.

**Commit:** `feat(guard): add observe-only LangChain capture handlers`
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (task 3) -->

<!-- START_TASK_3 -->
### Task 3: Tests for the capture handlers

**Verifies:** langchain-helper.AC5.7, langchain-helper.AC5.8

**Files:**
- Create: `tests/integration/guard/test_langchain_callbacks.py` (integration)

**Testing:**
Use `register_test_client()` — this phase emits captures and never guards, and `RecordedCapture` already exposes `action`, `correlation_id`, `decision_id`, `metadata`, and `warnings`. Reuse the shared autouse fixture from Phase 1 Task 5 (already active in this directory).

- **langchain-helper.AC5.7:** Inside `arcjet_sequence(correlation_id="corr-1")`, drive a chain-shaped lifecycle — `on_chain_start`, `on_tool_start`, `on_tool_end`, `on_llm_start`, `on_llm_end`, `on_chain_end` — and assert every recorded capture carries `correlation_id == "corr-1"`. Assert the action names are the expected past-tense `prefix.resource.verb` strings, and that the count matches the number of hooks driven. Sharing one ID across all of them is the criterion.
- **Correlation resolves per event, not per handler:** construct **one** handler outside any sequence, then drive it inside `arcjet_sequence(correlation_id="a")` and again inside `arcjet_sequence(correlation_id="b")`, and assert the two captures carry `"a"` and `"b"`. This is the construction-time-binding bug the implementation comment warns about; without this test the bug ships silently.
- **Explicit correlation wins:** a handler built with `correlation_id="explicit"` emits `"explicit"` even inside `arcjet_sequence(correlation_id="ambient")`.
- **Outside any sequence:** captures are still emitted, with `correlation_id is None`. Observation must not require a sequence.
- **langchain-helper.AC5.8:** Build a client double whose `capture()` raises, pass it as `guard=`, and assert every hook returns normally — no exception escapes. Cover at least one start, one end, and one error hook, on both the sync and async handlers. Additionally assert the failure was logged, using pytest's `caplog` against the `arcjet` logger, so a silently-swallowed error is distinguishable from one that never happened.
- **Error hooks:** `on_chain_error` / `on_tool_error` / `on_llm_error` emit `...failed` actions.
- **Async handler:** drive `ArcjetAsyncCaptureHandler` from a plain `def test_*` calling `asyncio.run(...)`, asserting the same correlation sharing.
- **No content leaks into metadata:** drive `on_tool_start` / `on_llm_start` with a recognisable secret string in the inputs and assert that string appears in **no** recorded capture's metadata. This is the hard rule from Task 2; assert it rather than trusting it.

**Verification:**
```bash
uv run pytest tests/integration/guard/test_langchain_callbacks.py -q
make test
make check
```
Expected: all pass, coverage ≥80%, clean, `make apicheck` reports no breaking change.

**Commit:** `test(guard): cover the LangChain capture handlers`
<!-- END_TASK_3 -->

<!-- END_SUBCOMPONENT_B -->

---

## Phase 6 done when

- A chain run emits captures sharing the run's correlation ID.
- An error path captures `outcome`-equivalent `...failed` actions.
- The handler never raises into LangChain, even when capture itself fails.
- `make test` passes at ≥80% coverage and `make check` is clean.
