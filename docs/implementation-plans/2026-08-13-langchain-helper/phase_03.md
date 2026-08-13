# LangChain Framework Helper — Phase 3: Checkpoint engine, `guard_action`, and metadata vocabulary

**Goal:** One framework-agnostic engine enforces fail-closed semantics and emits capture; `guard_action` exposes it to any Python code.

**Architecture:** `src/arcjet/guard/_checkpoint.py` becomes the single implementation of the checkpoint sequence — prepare, evaluate, classify into one of four outcomes, capture, then raise or proceed. It imports core only and knows nothing about LangChain. `guard_action` / `guard_action_sync` expose it publicly for background jobs and bare scripts; Phase 4's `guard_tool` and Phase 5's middleware delegate to the same engine, so fail-closed semantics and capture shape exist in exactly one place. Typed errors split into a core pair (`ArcjetDeniedError`, `ArcjetUnavailableError`) that the engine raises through injected factories, letting each surface raise its own subclass without the engine knowing the surface.

**Tech Stack:** Python 3.10+, frozen slotted dataclasses, `contextvars` (Phase 1), pytest 9.0.3.

**Scope:** Phase 3 of 7 from `docs/design-plans/2026-08-13-langchain-helper.md`.

**Dependencies:** Phases 1 and 2.

**Codebase verified:** 2026-08-13

---

## Acceptance Criteria Coverage

This phase implements and tests:

### langchain-helper.AC1: Checkpoints enforce policy and fail closed
- **langchain-helper.AC1.1 Success:** An `ALLOW` decision executes the wrapped callable and returns its value unchanged.
- **langchain-helper.AC1.2 Failure:** A `DENY` decision raises the typed denial error and the wrapped callable never runs.
- **langchain-helper.AC1.3 Failure:** A `DENY` decision still blocks when `on_guard_error="allow"`.
- **langchain-helper.AC1.4 Failure:** `guard()` raising with `on_guard_error="deny"` raises the typed unavailability error and the callable never runs.
- **langchain-helper.AC1.5 Success:** `guard()` raising with `on_guard_error="allow"` executes the callable.
- **langchain-helper.AC1.6 Failure:** A decision whose `has_failed_open()` is true raises unavailability under the default.

### langchain-helper.AC2: Sequences are well-formed
- **langchain-helper.AC2.1 Success:** An allowed checkpoint emits a capture with `outcome="success"` carrying `decision_id` and the active correlation ID.
- **langchain-helper.AC2.2 Success:** A denied checkpoint emits a capture with `outcome="denied"`.
- **langchain-helper.AC2.3 Success:** A wrapped callable that raises emits `outcome="error"` and the exception propagates unchanged.
- **langchain-helper.AC2.4 Success:** An unevaluated policy emits `outcome="unavailable"`.

### langchain-helper.AC4: Non-tool actions can be guarded
- **langchain-helper.AC4.1 Success:** `guard_action` and `guard_action_sync` guard an arbitrary callable with no LangChain module imported.
- **langchain-helper.AC4.2 Success:** `guard=None` resolves the registered client; with nothing registered the call fails open per core semantics and `on_guard_error` governs the checkpoint.

### langchain-helper.AC8: No content mutation
- **langchain-helper.AC8.1 Success:** Tool arguments and model output are byte-identical before and after a checkpoint, on both allow and deny paths.
- **langchain-helper.AC8.2 Success:** A LIVE sensitive-info detection denies rather than redacting, and raw `LOCAL` input values never appear in the outbound request.

**Partial AC notes:**
- `langchain-helper.AC3.4`'s second clause ("checkpoints still evaluate" outside a sequence) is completed here; the first clause landed in Phase 1.
- `langchain-helper.AC8.1` says "tool arguments and model output". This phase proves the engine never mutates the values handed to it. The tool-argument half is re-proven through the real `guard_tool` path in Phase 4.

---

## Binding constraints from the ADR corpus

Read `../../../../arcjet/docs/adrs/2026-08-13-python-langchain-helper-layering.md` before starting — it is the layering decision for exactly this work and postdates the design plan. Its binding points for this phase:

- **Raw `LOCAL` policy input values must never leave SDK memory** — only kind and digest travel. That guarantee lives in `guard()` and `_remote_policy.py`. **The checkpoint engine must inherit it, never re-implement or bypass it.** Concretely: the engine passes `inputs` straight to `guard()` and does nothing else with them.
- **Capture is fire-and-forget and must never convert a successful action into a failure.**
- **No mutation of the original value.** The engine reads `inputs` and the callable's return value; it copies, rewrites, and redacts nothing.
- **Fail closed by default**, diverging from the platform-wide fail-open convention.

## The JavaScript reference — match it exactly

The four outcomes and their ordering come from `../../../../arcjet-js/arcjet-guard/src/agents/guarded.ts:80-161`. Read it. Three details there are easy to miss and are **required**:

1. **Capture happens before the raise, on every path.** Deny captures then raises; unavailable captures then raises. An outcome that raises without capturing leaves a hole in the Sequence.
2. **Suppress an empty decision id.** The comment at `guarded.ts:103-105` is explicit: every decision the client synthesizes on a fail-open path carries `id: ""`, and `""` is not a correlatable id — putting it on the event is junk. Set `decision_id` only when `decision.id` is a non-empty string.
3. **A `guard()` that throws under `on_guard_error="allow"` produces no decision at all**, so no `decision_id` is available for the later `success` / `error` capture. Carry `decision_id` as `None` in that case rather than inventing one.

`has_failed_open()` in Python already folds in the ALLOW check — `_types.py:545` reads `return self.conclusion == "ALLOW" and bool(self.error_results())` — so the Python condition is simply `decision.has_failed_open()`, without the JS version's explicit `conclusion === "ALLOW"` conjunct.

## Outcome table

| Condition | `outcome` | Effect |
|---|---|---|
| `decision.conclusion == "DENY"` | `denied` | Capture, then raise the denial error — regardless of `on_guard_error` |
| `guard()` raised, or `decision.has_failed_open()` | `unavailable` | Capture and raise the unavailability error when `on_guard_error="deny"`; otherwise log and proceed |
| The wrapped callable raised | `error` | Capture, then re-raise unchanged |
| Otherwise | `success` | Capture, return the value |

When `on_guard_error="allow"` and policy was unevaluated, the checkpoint proceeds and the eventual capture is `success` or `error` — **not** `unavailable`. `unavailable` is captured only on the path that raises. This matches `guarded.ts`, where the fail-open branches set `decision = undefined` and fall through to the shared tail.

> **This narrows `langchain-helper.AC2.4`, which reads unconditionally.** The AC says "An unevaluated policy emits `outcome='unavailable'`", but under `on_guard_error="allow"` an unevaluated policy proceeds and its eventual capture reports what actually happened to the action. Emitting `unavailable` *and then* `success` for one checkpoint would double-count it on the Sequence. The JS reference settles it. Treat the AC as scoped to the failing-closed path, and consider amending the AC text in the design rather than leaving the reconciliation buried here.

## Verified starting state

- `src/arcjet/guard/_checkpoint.py` and `src/arcjet/guard/_vocabulary.py` **do not exist**.
- `ArcjetGuard.capture()` (`_client.py:403`) and `ArcjetGuardSync.capture()` (`_client.py:640`) are **both plain synchronous methods** returning `None`. One capture code path serves both flavors — there is nothing to await.
- The free `capture()` (`_registry.py:252`) already exists and is already exported from `arcjet.guard`.
- `Decision` (`_types.py:479`) is a frozen slotted dataclass with `.conclusion`, `.id`, `.reason`, `.has_failed_open()`.
- The logger is `from arcjet._logging import logger` — a stdlib `logging.Logger` named `arcjet` with a `NullHandler` attached.
- `OnGuardError = Literal["allow", "deny"]` currently lives at `src/arcjet/guard/langchain.py:23`. It moves to core in this phase.

## Project conventions this phase must follow

- No `pytest-asyncio`. Async paths run from a plain `def test_*` calling `asyncio.run(...)`. See `tests/unit/test_client_async.py:11-32`.
- New unit tests go in `tests/unit/guard/`; that directory's `conftest.py` disables protobuf mocking on purpose.
- **`ArcjetTestClient` returns a fail-open decision** (`testing.py:190-196`), so `has_failed_open()` is `True` and a default-configured checkpoint against it **denies**. For allow-path tests, either pass `on_guard_error="allow"` or use a stub client that returns a clean ALLOW.
- Verify with `make check` and `make test` (coverage `fail_under = 80`). Use `make apicheck` for griffe.

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: Core typed errors and `OnGuardError`

**Verifies:** None directly — it is the error vocabulary `langchain-helper.AC1.2` and `langchain-helper.AC1.4` assert against.

**Why:** The engine must raise a denial or unavailability error without knowing which surface called it. `guard_tool`'s existing `ArcjetToolDeniedError` / `ArcjetToolUnavailableError` subclass `langchain_core.tools.ToolException`, which core cannot import. So core defines the base pair, the LangChain module narrows them in Phase 4, and the engine raises through injected factories.

**Files:**
- Create: `src/arcjet/guard/_errors.py`

**Implementation:**

```python
"""Typed errors raised by Arcjet checkpoints.

Split from the surfaces that raise them so the checkpoint engine can stay
framework-agnostic: :mod:`arcjet.guard.langchain` narrows these into
``ToolException`` subclasses, and a caller that guards a Celery task catches
the base pair without importing LangChain.
"""

from __future__ import annotations

from typing import Literal, Optional

from ._types import Decision

__all__ = [
    "ArcjetDeniedError",
    "ArcjetUnavailableError",
    "OnGuardError",
]

OnGuardError = Literal["allow", "deny"]
"""What to do when policy could not be evaluated.

``"deny"`` is the default on every checkpoint surface, because they wrap
consequential effects.  This is the one place Arcjet diverges from its
platform-wide fail-open convention, so it is always documented alongside the
``"allow"`` opt-out.
"""


class ArcjetDeniedError(Exception):
    """Raised when Arcjet policy denied the action.

    A real decision, not a degraded one: this is raised regardless of
    ``on_guard_error``, because ``"allow"`` opts out of failing closed on an
    *unevaluated* policy, never out of an evaluated denial.
    """

    def __init__(self, action: str, decision: Decision) -> None:
        super().__init__(f'Arcjet denied action "{action}" ({decision.reason})')
        self.action = action
        self.decision = decision


class ArcjetUnavailableError(Exception):
    """Raised when a required Arcjet policy could not be evaluated.

    Distinct from :class:`ArcjetDeniedError` on purpose. Nothing decided this
    action was disallowed — the check did not happen, and the surface was
    configured to fail closed.
    """

    def __init__(self, action: str, *, cause: Optional[BaseException] = None) -> None:
        super().__init__(f'Arcjet policy for "{action}" could not be evaluated')
        self.action = action
        self.__cause__ = cause
```

**Verification:**
```bash
uv run python -c "
from arcjet.guard._errors import ArcjetDeniedError, ArcjetUnavailableError, OnGuardError
assert issubclass(ArcjetDeniedError, Exception)
assert issubclass(ArcjetUnavailableError, Exception)
print('ok')
"
```
Expected: `ok`

**Commit:** `feat(guard): add core checkpoint error types`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: `src/arcjet/guard/_vocabulary.py` — `security_metadata()`

**Verifies:** None directly — a metadata helper with no policy behavior. Covered by tests in Task 3 because coverage is gated at 80%.

**Files:**
- Create: `src/arcjet/guard/_vocabulary.py`

**Implementation:**

The seven fields and the one wire-key rename come from `../../../../arcjet-js/arcjet-guard/src/agents/vocabulary.ts:22-56`. Only `data_class` differs from a straight snake-to-kebab mapping of its JS name (`dataClass` → `data-class`); every other field is already a single lowercase word.

```python
"""A shared vocabulary for describing a guarded action.

Nothing here is required — ``metadata`` accepts any JSON-serializable mapping.
Consistent key names are what let the Console group and filter across
applications, so the common seven get a helper rather than being retyped as
string literals at every call site.

Matches the JavaScript ``SecurityMetadataFields``, including the one key that
is not a straight rename: ``data_class`` travels as ``data-class``.
"""

from __future__ import annotations

from typing import Optional

from arcjet._metadata import Metadata

__all__ = ["security_metadata"]


def security_metadata(
    *,
    user: Optional[str] = None,
    agent: Optional[str] = None,
    workflow: Optional[str] = None,
    data_class: Optional[str] = None,
    destination: Optional[str] = None,
    reversibility: Optional[str] = None,
    resource: Optional[str] = None,
) -> Metadata:
    """Build a metadata mapping from the common security fields.

    Fields left as ``None`` are omitted rather than sent as null, so an event
    carries only what the caller actually knew.

    Args:
        user: Who the action is on behalf of.
        agent: Which agent or model is acting.
        workflow: The workflow or chain this belongs to.
        data_class: Sensitivity of the data involved. Travels as
            ``"data-class"``.
        destination: Where an effect lands, e.g. an external service.
        reversibility: Whether the effect can be undone.
        resource: What is being acted on.

    Returns:
        A metadata mapping containing only the fields that were supplied.
        Metadata is untrusted: do not put secrets or PII in it.

    Example:
        ::

            from arcjet.guard import guard_action, security_metadata

            await guard_action(
                send_it,
                action="email.sent",
                metadata=security_metadata(
                    user=user.id,
                    destination="sendgrid",
                    reversibility="irreversible",
                ),
            )
    """
    fields = (
        ("user", user),
        ("agent", agent),
        ("workflow", workflow),
        ("data-class", data_class),
        ("destination", destination),
        ("reversibility", reversibility),
        ("resource", resource),
    )
    return {key: value for key, value in fields if value is not None}
```

**Verification:**
```bash
uv run python -c "
from arcjet.guard._vocabulary import security_metadata
assert security_metadata() == {}
m = security_metadata(user='u1', data_class='pii')
assert m == {'user': 'u1', 'data-class': 'pii'}, m
print('ok')
"
```
Expected: `ok`

**Commit:** `feat(guard): add security metadata vocabulary`
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-6) -->

<!-- START_TASK_3 -->
### Task 3: `src/arcjet/guard/_checkpoint.py` — the engine

**Verifies:** langchain-helper.AC1.1, langchain-helper.AC1.2, langchain-helper.AC1.3, langchain-helper.AC1.4, langchain-helper.AC1.5, langchain-helper.AC1.6, langchain-helper.AC2.1, langchain-helper.AC2.2, langchain-helper.AC2.3, langchain-helper.AC2.4, langchain-helper.AC8.1

**Files:**
- Create: `src/arcjet/guard/_checkpoint.py`

**Implementation:**

Two public-to-the-package entry points, `run_checkpoint` (async) and `run_checkpoint_sync`, plus shared helpers. They are deliberately separate rather than one bridging the other — `../../../../arcjet/docs/adrs/2026-08-01-guard-vercel-ai-and-langchain-policy-checkpoints.md` rejects event-loop bridging, and the repository keeps `ArcjetGuard` / `ArcjetGuardSync` split for the same reason.

`prepare` exists so a surface can resolve `actor` and `inputs` *inside* the engine's try block. `guard_tool` resolves them from a `RunnableConfig`, and a resolver that raises must produce `unavailable`, exactly as it does today (`langchain.py:165-167`). Surfaces with nothing to resolve pass `None` and supply static values.

```python
"""The single implementation of an Arcjet policy checkpoint.

Every guarding surface delegates here, so fail-closed semantics and the shape
of a capture event are defined once.  Surfaces above this module translate
framework constructs into its arguments; they do not re-implement any of it.

The four outcomes, their ordering, and the ``outcome`` metadata key match the
JavaScript helper (``arcjet-guard/src/agents/guarded.ts``) so one Sequence
reads the same whichever SDK produced it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import (
    Any,
    Awaitable,
    Callable,
    Literal,
    Optional,
    Sequence,
    TypeVar,
)

from arcjet._logging import logger
from arcjet._metadata import Metadata

from ._context import current_correlation_id, current_sequence_metadata
from ._errors import ArcjetDeniedError, ArcjetUnavailableError, OnGuardError
from ._policy_input import PolicyInputMap
from ._registry import _awaitable, _blocking
from ._registry import capture as _registry_capture
from ._registry import guard as _registry_guard
from ._registry import guard_sync as _registry_guard_sync
from ._rules import RuleWithInput
from ._types import Decision

T = TypeVar("T")

Outcome = Literal["success", "denied", "error", "unavailable"]

DeniedFactory = Callable[[str, Decision], BaseException]
UnavailableFactory = Callable[[str, Optional[BaseException]], BaseException]

# Two distinct aliases, not one union. `make check` runs both `ty` and
# `pyright`, and a single `Callable[[], ResolvedInputs | Awaitable[...]]`
# would force every sync call site to narrow a value that can never be
# awaitable there.
SyncPrepare = Callable[[], "ResolvedInputs"]
AsyncPrepare = Callable[[], Awaitable["ResolvedInputs"]]


@dataclass(frozen=True, slots=True)
class ResolvedInputs:
    """What a surface resolved for a checkpoint, immediately before evaluation."""

    actor: Optional[str] = None
    inputs: Optional[PolicyInputMap] = None


def _default_denied(action: str, decision: Decision) -> BaseException:
    return ArcjetDeniedError(action, decision)


def _default_unavailable(
    action: str, cause: Optional[BaseException]
) -> BaseException:
    return ArcjetUnavailableError(action, cause=cause)


def _resolve_correlation_id(explicit: Optional[str]) -> Optional[str]:
    """Explicit argument wins; otherwise fall back to the ambient sequence.

    A surface with a third tier — LangChain reads a ``RunnableConfig`` — folds
    that in before calling, by passing the config's value as *explicit*.
    """
    return explicit if explicit is not None else current_correlation_id()


def _merged_metadata(explicit: Optional[Metadata], outcome: Outcome) -> Metadata:
    """Sequence metadata, then the call's own, then the outcome.

    The outcome is applied last on purpose: it is what the engine observed, and
    a caller must not be able to overwrite it with a metadata key of the same
    name.
    """
    merged: dict[str, Any] = {}
    ambient = current_sequence_metadata()
    if ambient:
        merged.update(ambient)
    if explicit:
        merged.update(explicit)
    merged["outcome"] = outcome
    return merged


def _decision_id(decision: Optional[Decision]) -> Optional[str]:
    """The decision's id, or ``None`` when there is nothing correlatable.

    Every decision the client synthesizes on a fail-open path carries
    ``id=""``.  An empty string is not an id — putting it on an event is junk
    that looks like data.
    """
    if decision is None or not decision.id:
        return None
    return decision.id


def _emit_capture(
    *,
    client: Any,
    action: str,
    outcome: Outcome,
    correlation_id: Optional[str],
    decision: Optional[Decision],
    metadata: Optional[Metadata],
) -> None:
    """Record the outcome. Never raises.

    Capture is the reality half of a Sequence and is best-effort by design.  An
    audit-trail problem must not turn a successful application action into a
    failure, so every error here is swallowed and reported on the ``arcjet``
    logger instead.

    ``capture()`` is synchronous on both client flavors — it queues and
    returns, doing no I/O on the caller's path — so one code path serves both.
    """
    try:
        payload = dict(
            action=action,
            correlation_id=correlation_id,
            decision_id=_decision_id(decision),
            metadata=_merged_metadata(metadata, outcome),
        )
        if client is None:
            _registry_capture(**payload)
        else:
            client.capture(**payload)
    except Exception:
        logger.warning(
            "arcjet: failed to capture checkpoint outcome for action %r", action
        )


def _classify_decision(
    decision: Decision,
    *,
    action: str,
    on_guard_error: OnGuardError,
    denied_error: DeniedFactory,
    unavailable_error: UnavailableFactory,
) -> Optional[BaseException]:
    """Return the exception this decision requires, or ``None`` to proceed.

    Deny is checked first and is unconditional: ``on_guard_error`` opts out of
    failing closed on an *unevaluated* policy, never out of an evaluated
    denial.
    """
    if decision.conclusion == "DENY":
        return denied_error(action, decision)
    if decision.has_failed_open():
        if on_guard_error == "deny":
            return unavailable_error(action, None)
        logger.warning(
            "arcjet: policy for action %r could not be evaluated; proceeding "
            "because on_guard_error is 'allow'",
            action,
        )
    return None


def run_checkpoint_sync(
    fn: Callable[[], T],
    *,
    action: str,
    guard: Any = None,
    prepare: Optional[SyncPrepare] = None,
    actor: Optional[str] = None,
    inputs: Optional[PolicyInputMap] = None,
    rules: Sequence[RuleWithInput] = (),
    metadata: Optional[Metadata] = None,
    correlation_id: Optional[str] = None,
    on_guard_error: OnGuardError = "deny",
    denied_error: DeniedFactory = _default_denied,
    unavailable_error: UnavailableFactory = _default_unavailable,
) -> T:
    """Evaluate a checkpoint, then run *fn* if policy allows it."""
    resolved_correlation_id = _resolve_correlation_id(correlation_id)
    decision: Optional[Decision] = None

    try:
        prepared = prepare() if prepare is not None else ResolvedInputs(actor, inputs)
        decision = _guard_sync(
            guard,
            rules=rules,
            label=action,
            metadata=metadata,
            correlation_id=resolved_correlation_id,
            actor=prepared.actor,
            inputs=prepared.inputs,
        )
    except Exception as exc:
        # The guard call itself, or the surface's own resolution, failed. Rare
        # on the guard side: the client turns transport failures into decisions
        # rather than raising.
        if on_guard_error == "deny":
            _emit_capture(
                client=guard,
                action=action,
                outcome="unavailable",
                correlation_id=resolved_correlation_id,
                decision=None,
                metadata=metadata,
            )
            raise unavailable_error(action, exc) from exc
        logger.warning(
            "arcjet: policy for action %r could not be evaluated; proceeding "
            "because on_guard_error is 'allow'",
            action,
        )

    if decision is not None:
        failure = _classify_decision(
            decision,
            action=action,
            on_guard_error=on_guard_error,
            denied_error=denied_error,
            unavailable_error=unavailable_error,
        )
        if failure is not None:
            outcome: Outcome = (
                "denied" if decision.conclusion == "DENY" else "unavailable"
            )
            _emit_capture(
                client=guard,
                action=action,
                outcome=outcome,
                correlation_id=resolved_correlation_id,
                decision=decision,
                metadata=metadata,
            )
            raise failure

    try:
        result = fn()
    except Exception:
        _emit_capture(
            client=guard,
            action=action,
            outcome="error",
            correlation_id=resolved_correlation_id,
            decision=decision,
            metadata=metadata,
        )
        raise

    _emit_capture(
        client=guard,
        action=action,
        outcome="success",
        correlation_id=resolved_correlation_id,
        decision=decision,
        metadata=metadata,
    )
    return result
```

`run_checkpoint` is the same sequence with `await` on the guard call and on `fn()`, and with `prepare: Optional[AsyncPrepare]` — a coroutine function, awaited inside the same `try`. It must be a coroutine function rather than an optionally-awaitable one, because Phase 4's `ainvoke` genuinely needs to await `_resolve_actor_async` / `_resolve_inputs_async` (`langchain.py:219, 228`) while resolving. Keep the two bodies structurally identical so a reader can diff them; do not factor the shared tail into a helper that would have to exist in both flavors anyway.

The two dispatch helpers keep the registry fallback in one place:

**Reuse `_registry`'s dispatch helpers — do not write a third rule.** `_registry._blocking(client, "guard_sync", "guard")` (`_registry.py:341-355`) and `_registry._awaitable(client, "guard")` (`:326-339`) already encode the exact rule needed, *including the coroutine check that makes it safe*:

```python
def _guard_sync(client: Any, **kwargs: Any) -> Decision:
    """Evaluate through *client*, or the registered client when it is ``None``.

    An explicitly passed client always wins over the registered one, per the
    client-lifecycle ADR.  ``None`` falls back to the free call, which fails
    open with an error decision when nothing is registered — so an unguarded
    process produces ``has_failed_open()``, and ``on_guard_error`` governs from
    there.
    """
    if client is None:
        return _registry_guard_sync(**kwargs)

    method = _blocking(client, "guard_sync", "guard")
    if method is None:
        # An async client handed to the sync path. Raising here is what routes
        # it into the caller's `except` and out as an unavailability error,
        # rather than letting a coroutine object escape as if it were a
        # decision.
        raise TypeError(
            "A synchronous checkpoint requires a synchronous Arcjet client"
        )
    return method(**kwargs)
```

**The coroutine check is load-bearing, not defensive tidiness.** `ArcjetGuardSync` spells its blocking method `guard`, not `guard_sync` (`_client.py:736`). A naive `getattr(client, "guard_sync", None) or client.guard` therefore falls through to `client.guard` for *both* flavors — and for an async `ArcjetGuard` that returns an un-awaited coroutine object, which sails out of the `try` block and only fails later when `_classify_decision` reads `.conclusion` off it. The result is a bare `AttributeError` plus an "un-awaited coroutine" warning instead of the `ArcjetUnavailableError` the fail-closed contract promises. `_blocking` rejects a coroutine function explicitly (`inspect.iscoroutinefunction`), which is why it must be reused rather than reimplemented.

`_guard_async` is the mirror image: `_awaitable(client, "guard")`, raising `TypeError` when it returns `None`, then `await method(**kwargs)`.

Note both helpers pass `rules` as a keyword. `ArcjetGuardSync.guard`, the free `guard_sync`, and (after Phase 2 Task 1) the test client all accept it that way.

**Verification:**
```bash
make check
```
Expected: ruff/ty/pyright clean. No public API added yet, so `make apicheck` is unaffected.

**Commit:** `feat(guard): add the framework-agnostic checkpoint engine`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: `guard_action`, `guard_action_sync`, `capture_action`

**Verifies:** langchain-helper.AC4.1, langchain-helper.AC4.2

**Files:**
- Create: `src/arcjet/guard/_action.py`
- Modify: `src/arcjet/guard/_registry.py` — `capture()` gains an ambient correlation default

**Implementation:**

`guard_action` / `guard_action_sync` are thin: validate nothing, translate nothing, just call the engine with the default error factories.

```python
async def guard_action(
    fn: Callable[[], Awaitable[T]],
    *,
    action: str,
    guard: Optional[ArcjetGuard] = None,
    actor: Optional[str] = None,
    inputs: Optional[PolicyInputMap] = None,
    rules: Sequence[RuleWithInput] = (),
    metadata: Optional[Metadata] = None,
    correlation_id: Optional[str] = None,
    on_guard_error: OnGuardError = "deny",
) -> T:
```

Document on both: the fail-closed default and the `"allow"` opt-out; that a `DENY` blocks regardless; that `guard=None` uses the registered client and that with nothing registered the checkpoint fails closed by default because the free call fails open into `has_failed_open()`; and that `rules=()` still contacts Guard, because the server selects remote policy by `label`.

`capture_action` is the ambient-aware spelling of `capture()`:

```python
def capture_action(
    *,
    action: str,
    metadata: Optional[Metadata] = None,
    correlation_id: Optional[str] = None,
    decision_id: Optional[str] = None,
) -> None:
    """Record something the application did, on the enclosing Sequence.

    The agent-facing spelling of :func:`capture`: identical, except that an
    omitted *correlation_id* is taken from the enclosing
    :func:`arcjet_sequence` and omitted *metadata* inherits the sequence's.
    Never raises.
    """
```

> **Deliberate divergence from the design.** The design's contract block (design lines 282–288) proposes `capture_action` *only*, and never lists `capture()` as something to modify. Shipping both — `capture_action()` **and** an ambient default on the already-public `capture()` — was chosen explicitly, over the two alternatives of "wrapper only" and "modify `capture()` only". Rationale: `capture_action` is the documented agent-facing spelling that keeps the design's vocabulary intact, while giving `capture()` the same default means existing code inside an `arcjet_sequence` joins the Sequence without being rewritten. The cost is two near-identical public names, accepted knowingly. This is a behavior change to a shipped function on a `0.10.0b1` package and needs a changelog entry; it is additive to the signature, so `make apicheck` stays clean.

**Both** surfaces get the ambient default. Modify the free `capture()` in `_registry.py:252` so an omitted `correlation_id` falls back to `current_correlation_id()`, and an omitted `metadata` falls back to `current_sequence_metadata()`.

**Omitted vs. explicit `None`.** Both parameters already default to `None`, so `capture(correlation_id=None)` is indistinguishable from omitting it — "an explicit argument wins" is unimplementable as stated without a sentinel. Do **not** introduce one. Treat explicit `None` as omission for both parameters, i.e. the rule is simply *"a non-`None` argument wins; `None` means fall back to the ambient value"*. Passing `None` to mean "deliberately no correlation" is not a supported request, and the way to get an event with no correlation is to emit it outside any `arcjet_sequence`. State this in the docstring so the absence of a sentinel reads as a decision rather than an oversight.

Add a note to the docstring, since this changes the behavior of an already-shipped function:

```
        correlation_id: Optional opaque identifier tying this event to
            ``guard()`` and ``capture()`` calls in the same workflow or agent
            run.  Defaults to the enclosing :func:`arcjet_sequence`'s id when
            there is one, so code inside a sequence joins it without threading
            the id through.
```

Watch the import direction: `_registry.py` must import from `._context`, and `._context` imports only `arcjet._ids` and `arcjet._metadata`. There is no cycle. `_checkpoint.py` importing `_registry` and `_registry` importing `_context` is likewise fine.

**Verification:**
```bash
uv run python -c "
import asyncio
from arcjet.guard import arcjet_sequence, guard_action_sync
from arcjet.guard.testing import register_test_client

with register_test_client() as aj:
    with arcjet_sequence(correlation_id='corr-1'):
        # test client fails open, so the default deny path raises
        try:
            guard_action_sync(lambda: 'x', action='thing.done')
            raise AssertionError('expected a denial')
        except Exception as exc:
            assert type(exc).__name__ == 'ArcjetUnavailableError', type(exc)
        assert aj.captures[-1].metadata['outcome'] == 'unavailable'
        assert aj.captures[-1].correlation_id == 'corr-1'
print('ok')
"
```
Expected: `ok`

**Commit:** `feat(guard): add guard_action and capture_action`
<!-- END_TASK_4 -->

<!-- START_TASK_5 -->
### Task 5: Export the new public names, and move `OnGuardError`

**Verifies:** langchain-helper.AC4.1

**Files:**
- Modify: `src/arcjet/guard/__init__.py`
- Modify: `src/arcjet/guard/langchain.py` — import `OnGuardError` from core instead of defining it

**Implementation:**

Export from `arcjet.guard`: `guard_action`, `guard_action_sync`, `capture_action`, `security_metadata`, `OnGuardError`, `ArcjetDeniedError`, `ArcjetUnavailableError`. Add them to `__all__` in the existing grouped-and-alphabetized style.

In `src/arcjet/guard/langchain.py`, delete the local `OnGuardError = Literal["allow", "deny"]` at line 23 and import it from `._errors`. Drop the now-unused `Literal` from the `typing` import if nothing else in the file uses it — ruff's F401 will say. This keeps `from arcjet.guard.langchain import OnGuardError` resolving to the same alias, so it is not a breaking change.

Do **not** re-point `ArcjetToolDeniedError` / `ArcjetToolUnavailableError` yet — that is Phase 4, which also rewires `guard_tool` onto the engine.

**Verification:**
```bash
uv run python -c "
import arcjet.guard as g
for n in ('guard_action','guard_action_sync','capture_action','security_metadata','OnGuardError','ArcjetDeniedError','ArcjetUnavailableError'):
    assert n in g.__all__ and hasattr(g, n), n
from arcjet.guard.langchain import OnGuardError as L
assert L is g.OnGuardError
print('ok')
"
make check
```
Expected: `ok`, then clean. `make apicheck` reports no breaking change — all additions.

**Commit:** `feat(guard): export guard_action and the checkpoint vocabulary`
<!-- END_TASK_5 -->

<!-- START_TASK_6 -->
### Task 6: Tests for the checkpoint engine, `guard_action`, and vocabulary

**Verifies:** langchain-helper.AC1.1, langchain-helper.AC1.2, langchain-helper.AC1.3, langchain-helper.AC1.4, langchain-helper.AC1.5, langchain-helper.AC1.6, langchain-helper.AC2.1, langchain-helper.AC2.2, langchain-helper.AC2.3, langchain-helper.AC2.4, langchain-helper.AC3.4, langchain-helper.AC4.1, langchain-helper.AC4.2, langchain-helper.AC8.1, langchain-helper.AC8.2

**Files:**
- Modify: `tests/guard_doubles.py` — add `StubGuardClient` and the `Decision` builders
- Create: `tests/unit/guard/test_checkpoint.py` (unit)
- Create: `tests/unit/guard/test_vocabulary.py` (unit)

**Implementation — the stub client:**

`ArcjetTestClient` always fails open, so it cannot exercise the allow or deny paths. Build a small recording double — **`StubGuardClient` in `tests/guard_doubles.py`**, the shared module Phase 1 Task 5 created, **not** inside `test_checkpoint.py`. Phases 4, 5 and 7 all import it (`from guard_doubles import StubGuardClient`), and a double defined in a test module cannot be imported from another directory: `tests/unit/__init__.py` does not exist, so `tests.unit.guard.test_checkpoint` is not a valid module path.

Write it in the hand-built style this repo already uses for `_Transport` (`tests/integration/guard/test_langchain.py`):

- Constructed with the `Decision` to return, or an exception to raise from `guard`.
- Offers `guard` (async), `guard_sync`, and a synchronous `capture` that appends to a list — matching the real clients, so `_emit_capture` reaches it.
- Records the kwargs of every `guard` and `capture` call so tests can assert on `correlation_id`, `decision_id`, and merged metadata.

Build `Decision` instances directly — it is a frozen dataclass with `conclusion`, `id`, `results` required. An ALLOW that has **not** failed open needs `results=()`, since `has_failed_open()` is `conclusion == "ALLOW" and bool(error_results())`. A failed-open ALLOW needs a `RuleResultError` in `results`. Check `tests/unit/guard/` for an existing decision-building helper before writing one; `tests/fixtures/protobuf_stubs.py` exposes `make_allow_decision` / `make_deny_decision` / `make_error_decision`, but those are protobuf-level and the guard tests deliberately do not use the protobuf mocks — confirm which applies before reusing.

Sequence isolation is automatic here — Phase 1 Task 5 installed an autouse fixture in this directory's `conftest.py`.

**Testing:**
Run every outcome across **both** flavors — sync directly, async from a plain `def test_*` via `asyncio.run(...)`.

- **langchain-helper.AC1.1:** A clean ALLOW runs the callable exactly once and returns its value unchanged (assert identity, `result is sentinel`, not just equality).
- **langchain-helper.AC1.2:** A DENY raises `ArcjetDeniedError` and the callable never ran — assert a call-counter is still `0`. Assert the raised error carries `.action` and `.decision`.
- **langchain-helper.AC1.3:** The same DENY with `on_guard_error="allow"` still raises and still does not run the callable. This is the ACs' sharpest distinction: `"allow"` opts out of failing closed on unevaluated policy, never out of a real denial.
- **langchain-helper.AC1.4:** A client whose `guard` raises, with the default `on_guard_error="deny"`, raises `ArcjetUnavailableError` with `__cause__` set to the original exception, and the callable never ran.
- **langchain-helper.AC1.5:** The same raising client with `on_guard_error="allow"` runs the callable and returns its value.
- **langchain-helper.AC1.6:** A decision with `has_failed_open()` true raises `ArcjetUnavailableError` under the default. Assert `has_failed_open()` really is `True` on the fixture decision first, so the test cannot pass for the wrong reason.
- **langchain-helper.AC2.1:** After an allowed checkpoint inside `arcjet_sequence(correlation_id="corr-1")`, exactly one capture was emitted with `metadata["outcome"] == "success"`, `correlation_id == "corr-1"`, and `decision_id == decision.id`.
- **langchain-helper.AC2.2:** A denied checkpoint emits `outcome="denied"` — and emits it *before* raising, so the capture exists on the client even though the call raised.
- **langchain-helper.AC2.3:** A callable that raises `ValueError("boom")` emits `outcome="error"` and the `ValueError` propagates unchanged — assert the exact exception instance is re-raised, not wrapped.
- **langchain-helper.AC2.4:** The `has_failed_open()` path and the `guard`-raises path each emit `outcome="unavailable"`. On the `guard`-raises path assert `decision_id is None`, since there was no decision.
- **Empty decision id:** a decision with `id=""` produces a capture whose `decision_id` is `None`, not `""`.
- **Outcome cannot be overridden:** pass `metadata={"outcome": "success"}` into a checkpoint that denies, and assert the emitted capture still reads `outcome="denied"`.
- **langchain-helper.AC3.4 (second clause):** Outside any `arcjet_sequence`, a checkpoint still evaluates — the guard call happens and the capture carries `correlation_id is None`.
- **langchain-helper.AC4.1:** `guard_action` and `guard_action_sync` guard a plain callable. Prove the no-LangChain claim mechanically rather than by inspection: in a `subprocess` running `python -c`, install a `sys.meta_path` finder that raises `ImportError` for any module named `langchain*`, then import `arcjet.guard` and call `guard_action_sync`. Assert exit code 0. A plain `assert "langchain" not in sys.modules` is weaker but acceptable as a second, cheaper check.
- **langchain-helper.AC4.2:** With `guard=None` and a client registered via `register_test_client()`, the checkpoint reaches that client — assert `client.guards` grew. With `guard=None` and nothing registered, the free call fails open, so the default `on_guard_error="deny"` raises `ArcjetUnavailableError` and `on_guard_error="allow"` runs the callable.
- **langchain-helper.AC8.1:** Pass a mapping of `inputs` and a mutable argument object into a checkpoint on both the allow and the deny path, and assert afterwards that the object is unchanged and that the mapping the client received `is` the mapping passed in. Also assert the returned value is the identical object the callable produced.
- **langchain-helper.AC8.2:** Two parts. (a) Assert `inputs` reach `guard()` untouched — the engine adds, removes, and rewrites nothing — so the `LOCAL` digest guarantee in `_remote_policy.py` is the only thing that governs, and the engine cannot have bypassed it. (b) Assert that a `DENY` driven by sensitive info raises `ArcjetDeniedError` and the callable never runs, i.e. denial rather than redaction. Do **not** re-test `_remote_policy.py`'s digesting here; that is covered by `tests/unit/guard/test_remote_policy.py` and re-testing a dependency through this code is not this phase's job. If asserting (a) end-to-end needs a real transport, state that in the test docstring and keep the engine-level identity assertion.
- **Capture never breaks the action:** a client whose `capture()` raises must not stop an allowed checkpoint from returning its value, nor change which exception a denied one raises. Assert the callable's value still comes back.
- **Empty rules still contact Guard:** a checkpoint with no `rules` argument still produces exactly one guard call, recorded with `rules == ()`. The server selects remote policy by `label`, so skipping the call would silently disable every remotely-managed policy. Cover both flavors. (Phase 2 Task 4 asserts the same at the registry layer; this asserts it at the engine layer, which is what the phase's "done when" claims.)
- **Wrong-flavor client is an unavailability, not a crash:** pass an async-only client to `run_checkpoint_sync` and assert it raises `ArcjetUnavailableError` under the default — **not** `AttributeError`, and with no "coroutine was never awaited" warning. Assert the reverse for a sync-only client passed to `run_checkpoint`. This is the `_blocking` / `_awaitable` dispatch from Task 3; without the coroutine check an un-awaited coroutine escapes the `try` and fails later as a bare `AttributeError`. Assert the absence of the `RuntimeWarning` with `recwarn` or `warnings.catch_warnings(record=True)` — **not** `pytest.warns(None)`, which was removed in pytest 8 and raises `TypeError: exceptions must be derived from Warning, not <class 'NoneType'>` on the pinned `pytest==9.0.3` (verified). For example, decorate with `@pytest.mark.filterwarnings("error::RuntimeWarning")` so an un-awaited coroutine fails the test outright.
- **Prompt injection and sensitive info reach the checkpoint as policy inputs** (the design's Definition of Done requires both to be wired as policy inputs, and this is the only place that is asserted). Build a checkpoint with `rules=[DetectPromptInjection()(user_message)]` and, separately, with a `LocalDetectSensitiveInfo` rule, and assert the bound rule arrives in the recorded guard call's `rules` unchanged. Import both from `arcjet.guard` — confirm the exact constructor spelling against `src/arcjet/guard/_rules/` before writing, since the rules take a config then bind an input.
- **langchain-helper.AC8.2, denial not redaction:** drive a `DENY` whose `reason` reflects sensitive info and assert `ArcjetDeniedError` is raised, the callable never ran, and the `inputs` mapping the client received is the identical object passed in — nothing was rewritten on the way through. Do **not** re-test `_remote_policy.py`'s digesting; `tests/unit/guard/test_remote_policy.py` owns that, and re-testing a dependency through this code is not this phase's job.

`test_vocabulary.py` covers `security_metadata()`: all-`None` returns `{}`; each field maps to its own key; `data_class` maps to `data-class`; a partially-populated call omits the absent keys entirely rather than emitting nulls.

**Verification:**
```bash
uv run pytest tests/unit/guard/test_checkpoint.py tests/unit/guard/test_vocabulary.py -q
make test
make check
```
Expected: all pass, coverage ≥80%, ruff/ty/pyright clean, `make apicheck` reports no breaking change.

**Commit:** `test(guard): cover the checkpoint engine and guard_action`
<!-- END_TASK_6 -->

<!-- END_SUBCOMPONENT_B -->

---

## Phase 3 done when

- All four outcomes are covered across sync and async.
- A denial blocks under `on_guard_error="allow"`.
- `guard()` is still called when `rules` is empty.
- A capture failure does not fail the action.
- `guard_action` works in a process where importing `langchain` is impossible.
- `make test` passes at ≥80% coverage, `make check` is clean, `make apicheck` reports no breaking change.
