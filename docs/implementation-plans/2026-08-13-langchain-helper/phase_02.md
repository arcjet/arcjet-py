# LangChain Framework Helper — Phase 2: Core parity for checkpoints

**Goal:** The registry free functions and the test client can both express a full policy checkpoint.

**Architecture:** `ArcjetGuard.guard()` and `ArcjetGuardSync.guard()` already accept `actor` and `inputs` and already default `rules` to `()`. The two surfaces that do not are the module-level free functions in `src/arcjet/guard/_registry.py` and the in-memory double in `src/arcjet/guard/testing.py`. This phase brings both up to the client's signature so the Phase 3 checkpoint engine can drive either one, and so a test can assert a full checkpoint without hand-rolling a transport.

**Tech Stack:** Python 3.10+, frozen slotted dataclasses, pytest 9.0.3, griffe.

**Scope:** Phase 2 of 7 from `docs/design-plans/2026-08-13-langchain-helper.md`.

**Dependencies:** None.

**Codebase verified:** 2026-08-13

---

## Acceptance Criteria Coverage

This phase implements and tests:

### langchain-helper.AC7: Core parity for checkpoints
- **langchain-helper.AC7.1 Success:** Module-level `guard()` and `guard_sync()` accept `actor` and `inputs` and both reach the transport intact.
- **langchain-helper.AC7.2 Success:** Module-level `guard()` with no rules still contacts Guard, because the server selects remote policy by `label`.
- **langchain-helper.AC7.3 Success:** `RecordedGuard` exposes `actor` and `inputs` so tests assert a checkpoint without a hand-rolled transport.

---

## Verified starting state

Read these before editing. Line numbers are as of 2026-08-13.

**Already correct — do not change.** `ArcjetGuard.guard()` (`src/arcjet/guard/_client.py:487`) and `ArcjetGuardSync.guard()` (`src/arcjet/guard/_client.py:736`) both already read:

```python
async def guard(
    self,
    rules: Sequence[RuleWithInput] = (),
    *,
    label: str,
    metadata: Metadata | None = None,
    correlation_id: str | None = None,
    actor: str | None = None,
    inputs: PolicyInputMap | None = None,
) -> Decision:
```

That signature is the target the two surfaces below must match.

**Needs work — the registry free functions** (`src/arcjet/guard/_registry.py:176` and `:222`) currently read:

```python
async def guard(
    rules: Sequence[RuleWithInput],          # positional, required
    *,
    label: str,
    metadata: Optional[Metadata] = None,
    correlation_id: Optional[str] = None,
) -> Decision:                                # no actor, no inputs
```

**Needs work — the test client.** `RecordedGuard` (`src/arcjet/guard/testing.py:86-93`) has `label`, `rules`, `metadata`, `correlation_id` and no `actor` / `inputs`. Critically, the design's component list mentions only the dataclass, but `ArcjetTestClient.guard()` (`:182`), `.guard_sync()` (`:199`) and `._record_guard()` (`:210`) do not accept `actor` or `inputs` either. Without those, a Phase 3 checkpoint calling the double with `actor=` raises `TypeError` before anything is recorded. Both must change together.

## Behavioral fact that shapes later phases

`ArcjetTestClient._record_guard()` returns `_make_error_decision(...)` — a **fail-open ALLOW carrying an error result**, so `decision.has_failed_open()` is `True`. The docstring at `src/arcjet/guard/testing.py:190-196` states this deliberately. Consequence for Phases 3–6: a checkpoint run against a bare `ArcjetTestClient` under the default `on_guard_error="deny"` **denies**. Tests that need an allow path must either pass `on_guard_error="allow"` or use a hand-built transport double in the style of `_Transport` in `tests/integration/guard/test_langchain.py`.

## Project conventions this phase must follow

- No `pytest-asyncio`. Async paths are exercised from a plain `def test_*` calling `asyncio.run(...)`. See `tests/unit/test_client_async.py:11-32`.
- Registry tests already exist at `tests/unit/guard/test_registry.py`; test-client tests at `tests/unit/guard/test_testing.py`. Extend those files rather than adding new ones.
- `tests/unit/guard/conftest.py` intentionally disables the parent protobuf-mocking autouse fixture. Leave it alone.
- Tests that register a client must clear it in teardown. Copy `_clear_registration` (`tests/unit/guard/test_testing.py:27-33`).
- Verify with `make check` and `make test`. Use `make apicheck` for griffe — the design quotes a command missing this repo's required `-e tools/griffe_extensions.py:IgnoreProtobufDescriptors` flag (`Makefile:18`).

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: `ArcjetTestClient` and `RecordedGuard` record `actor` and `inputs`

**Verifies:** langchain-helper.AC7.3

**Files:**
- Modify: `src/arcjet/guard/testing.py` — `RecordedGuard` (lines 86-93), `ArcjetTestClient.guard` (182-197), `.guard_sync` (199-207), `._record_guard` (210-226)

**Implementation:**

Add two optional fields to `RecordedGuard`, after the existing ones so positional construction in any existing test keeps working, and give them the same docstring treatment the sibling `RecordedCapture` fields get:

```python
@dataclass(frozen=True, slots=True)
class RecordedGuard:
    """A guard call recorded by an :class:`ArcjetTestClient`."""

    label: str
    rules: tuple[RuleWithInput, ...]
    metadata: Optional[Metadata] = None
    correlation_id: Optional[str] = None
    actor: Optional[str] = None
    """Who the call said was acting.  Present only when the call supplied one."""
    inputs: Optional[PolicyInputMap] = None
    """Inputs offered for remote policy evaluation, exactly as passed."""
```

Add `from ._policy_input import PolicyInputMap` to the imports.

Widen the three methods to match `ArcjetGuard.guard()`. `rules` also picks up the `= ()` default so the double accepts a checkpoint that passes no rules:

```python
    async def guard(
        self,
        rules: Sequence[RuleWithInput] = (),
        *,
        label: str,
        metadata: Optional[Metadata] = None,
        correlation_id: Optional[str] = None,
        actor: Optional[str] = None,
        inputs: Optional[PolicyInputMap] = None,
    ) -> Decision:
        """Record the guard call and answer fail-open.

        A fail-open ALLOW rather than a plain one, because no rule was
        evaluated and a plain ALLOW would claim otherwise.  Note this means the
        decision reports an error, so helpers that fail closed on an errored
        decision will deny against this client.
        """
        return self._record_guard(rules, label, metadata, correlation_id, actor, inputs)
```

Mirror the same widening on `guard_sync`, and thread both through `_record_guard`:

```python
    def _record_guard(
        self,
        rules: Sequence[RuleWithInput],
        label: str,
        metadata: Optional[Metadata],
        correlation_id: Optional[str],
        actor: Optional[str] = None,
        inputs: Optional[PolicyInputMap] = None,
    ) -> Decision:
        self.guards.append(
            RecordedGuard(
                label=label,
                rules=tuple(rules),
                metadata=metadata,
                correlation_id=correlation_id,
                actor=actor,
                inputs=inputs,
            )
        )
        return _make_error_decision(
            "guard() was called on the Arcjet test client; no rules ran"
        )
```

Record `inputs` by reference without copying. It is a `Mapping` the caller built for this call, and Phase 3's no-mutation guarantee (`langchain-helper.AC8.1`) is easier to assert when the recorder holds the same object the call site passed.

**Verification:**
```bash
uv run python -c "
from arcjet.guard.testing import register_test_client
from arcjet.guard import local_input
with register_test_client() as aj:
    aj.guard_sync(label='t', actor='u1', inputs={'prompt': local_input('hi')})
    g = aj.guards[0]
    assert g.actor == 'u1', g.actor
    assert g.inputs is not None and 'prompt' in g.inputs
    assert g.rules == ()
    print('ok')
"
```
Expected: `ok`

**Commit:** `feat(guard): record actor and inputs on the test client`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Tests for test-client parity

**Verifies:** langchain-helper.AC7.3

**Files:**
- Modify: `tests/unit/guard/test_testing.py` (unit)

**Testing:**
Follow the file's existing class-based grouping and its `_clear_registration` autouse fixture.

- **langchain-helper.AC7.3:** With `register_test_client()`, call `guard_sync(label=..., actor=..., inputs=...)` and assert the recorded `RecordedGuard` exposes `actor` and the same `inputs` mapping. Repeat for the async `guard()` from a plain `def test_*` via `asyncio.run(...)`.
- Assert `RecordedGuard` remains frozen — `pytest.raises(FrozenInstanceError)` on assigning `actor` — since the repo's records are frozen slotted dataclasses and later phases rely on that.
- Assert the defaults: a call passing neither leaves `actor is None` and `inputs is None`, so existing recorded-guard assertions elsewhere are unaffected.
- Assert `inputs` is recorded by identity (`recorded.inputs is the_mapping_passed`), pinning the no-copy behavior Phase 3 asserts against.

**Verification:**
```bash
uv run pytest tests/unit/guard/test_testing.py -q
```
Expected: all tests pass, including the pre-existing ones unmodified.

**Commit:** `test(guard): cover actor and inputs on the test client`
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-4) -->

<!-- START_TASK_3 -->
### Task 3: Registry free functions accept `actor` and `inputs`

**Verifies:** langchain-helper.AC7.1, langchain-helper.AC7.2

**Files:**
- Modify: `src/arcjet/guard/_registry.py` — `guard()` (lines 176-219), `guard_sync()` (lines 222-249)

**Implementation:**

Give `rules` the `= ()` default and add the two keyword-only parameters, so both free functions mirror `ArcjetGuard.guard()` exactly. Forward them to the client:

```python
async def guard(
    rules: Sequence[RuleWithInput] = (),
    *,
    label: str,
    metadata: Optional[Metadata] = None,
    correlation_id: Optional[str] = None,
    actor: Optional[str] = None,
    inputs: Optional[PolicyInputMap] = None,
) -> Decision:
```

and inside, extend the existing forwarding call:

```python
    if method is not None:
        return await method(
            rules,
            label=label,
            metadata=metadata,
            correlation_id=correlation_id,
            actor=actor,
            inputs=inputs,
        )
```

Apply the identical change to `guard_sync()`. Add `from ._policy_input import PolicyInputMap` to the imports.

Extend the `guard()` docstring with the two new arguments, and state why an empty `rules` is a real call rather than a no-op — this is the substance of `langchain-helper.AC7.2`:

```
        rules: Bound rule inputs.  Defaults to none, which is still a real
            call: the server selects remote policy by ``label``, so a
            checkpoint that configures no local rules is exactly how a
            remotely-managed policy is evaluated.
        actor: Who is performing the action, forwarded to policy evaluation.
        inputs: Values offered for remote policy evaluation, keyed by name.
```

Leave the fail-open behavior alone. With nothing registered the function still returns `_make_error_decision(...)` rather than raising, and `actor` / `inputs` change nothing about that — `langchain-helper.AC4.2` depends on it staying that way.

**Verification:**
```bash
uv run python -c "
import inspect, arcjet.guard as g
for fn in (g.guard, g.guard_sync):
    p = inspect.signature(fn).parameters
    assert 'actor' in p and 'inputs' in p, fn.__name__
    assert p['rules'].default == (), fn.__name__
print('ok')
"
make apicheck
```
Expected: `ok`, then griffe reports no breaking change. Adding keyword-only parameters with defaults and giving an existing positional parameter a default are both additive.

**Commit:** `feat(guard): accept actor and inputs on the free guard calls`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Tests for registry parity

**Verifies:** langchain-helper.AC7.1, langchain-helper.AC7.2

**Files:**
- Modify: `tests/unit/guard/test_registry.py` (unit)

**Testing:**
Use `register_test_client()` as the transport-free assertion point — that is what Task 1 made possible, and it is what `langchain-helper.AC7.3` exists to enable. Follow the file's existing registration-cleanup fixture.

- **langchain-helper.AC7.1:** Register a test client, call the module-level `guard_sync(label="checkout.refund", actor="user-1", inputs={...})`, and assert the single `RecordedGuard` carries `actor == "user-1"` and the same `inputs` mapping — i.e. both reached the client intact rather than being dropped in the forwarding layer. Repeat for the async module-level `guard()` from a plain `def test_*` via `asyncio.run(...)`.
- **langchain-helper.AC7.2:** Call the module-level `guard(label="support.reply")` with no `rules` argument at all and assert a `RecordedGuard` was recorded with `rules == ()`. The point is that the call is made, not skipped: assert `len(client.guards) == 1`. Cover both flavors.
- Assert the unregistered path is unchanged: with nothing registered, `guard_sync(label="x", actor="u")` returns a decision whose `has_failed_open()` is `True` and does not raise. This pins the behavior `langchain-helper.AC4.2` will depend on in Phase 3.

**Verification:**
```bash
uv run pytest tests/unit/guard/test_registry.py tests/unit/guard/test_testing.py -q
make test
make check
```
Expected: all tests pass, coverage ≥80%, ruff/ty/pyright clean, `make apicheck` reports no breaking change.

**Commit:** `test(guard): cover actor and inputs on the free guard calls`
<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_B -->

---

## Phase 2 done when

- A registry-path `guard()` / `guard_sync()` call with no rules but an `actor` and `inputs` reaches the client intact, proven against `ArcjetTestClient` rather than a hand-rolled transport.

  **On "client" vs the AC's "transport".** `langchain-helper.AC7.1` says the two "reach the transport intact". This phase asserts they reach the *client* intact, which is the whole of what it changes: the only new code is the forwarding hop from the free function to the client method. `ArcjetGuard.guard()` already accepted `actor` and `inputs` before this phase (`_client.py:487`) and already serializes them — `result.actor = actor` at the transport boundary and `inputs` through `_remote_policy.prepare` — all of which is pre-existing behavior covered by `tests/integration/guard/test_client.py` and `test_remote_policy.py`. Asserting client-inward here and letting the existing suite own client-to-transport avoids re-testing a dependency through new code. The end-to-end claim is discharged by Phase 4's `guard_tool` tests, which assert against a real `_Transport`.
- `RecordedGuard` exposes `actor` and `inputs`, and `ArcjetTestClient.guard()` / `.guard_sync()` accept them.
- `make test` passes at ≥80% coverage, `make check` is clean, and `make apicheck` reports no breaking change.
