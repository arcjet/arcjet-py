# LangChain Framework Helper — Phase 1: Ambient correlation context in core

**Goal:** A correlation ID can be scoped ambiently and read back, in sync and async code, with no LangChain present.

**Architecture:** A module-level `ContextVar` in `src/arcjet/guard/_context.py` carries the correlation ID for the current execution context. A `arcjet_sequence()` context manager scopes it using the `set` / `reset(token)` token pattern, and `current_correlation_id()` / `current_sequence_metadata()` read it back. Correlation ID generation is extracted from `src/arcjet/_client.py` into a new `src/arcjet/_ids.py` so the guard package and the HTTP client share one sortable-ID implementation instead of two.

**Tech Stack:** Python 3.10+ (`contextvars`, `contextlib.contextmanager`), pytest 9.0.3, ruff, ty, pyright, griffe.

**Scope:** Phase 1 of 7 from `docs/design-plans/2026-08-13-langchain-helper.md`.

**Dependencies:** None.

**Codebase verified:** 2026-08-13

---

## Acceptance Criteria Coverage

This phase implements and tests:

### langchain-helper.AC3: Ambient correlation context
- **langchain-helper.AC3.1 Success:** `arcjet_sequence()` sets an ID that `current_correlation_id()` returns inside the block.
- **langchain-helper.AC3.2 Success:** Nested `arcjet_sequence()` blocks restore the outer ID on exit.
- **langchain-helper.AC3.3 Failure:** An ID over 256 bytes, or containing non-printable-ASCII, is rejected rather than silently truncated.
- **langchain-helper.AC3.4 Edge:** Outside any sequence, `current_correlation_id()` returns `None` and checkpoints still evaluate.

### langchain-helper.AC6: Correlation crosses boundaries
- **langchain-helper.AC6.1 Success:** Correlation set before `asyncio.create_task()` is visible inside the task.
- **langchain-helper.AC6.2 Success:** Correlation is visible inside `asyncio.to_thread()`.
- **langchain-helper.AC6.3 Edge:** A bare `ThreadPoolExecutor.submit()` does not inherit correlation, and the documented `copy_context()` idiom does.

**Partial AC note:** `langchain-helper.AC3.4` has two clauses. This phase completes the first ("`current_correlation_id()` returns `None`"). The second clause ("checkpoints still evaluate") requires the checkpoint engine and is completed in Phase 3.

---

## Project conventions this phase must follow

Read before writing any test. These are observed facts about this repository, not suggestions.

- **There is no `pytest-asyncio` and no `anyio` plugin.** There are zero `async def test_*` functions in this repository. Async behavior is tested from a plain `def test_*` that calls `asyncio.run(...)`. See `tests/unit/test_client_async.py:11-32`. Follow this exactly.
- **Guard unit tests live in `tests/unit/guard/`.** That directory's `conftest.py` deliberately overrides the parent `_ensure_protobuf_mocked` autouse fixture to a no-op, because guard tests use real protobuf. Do not re-add mocking.
- **Autouse fixtures reset global state**, using `yield` inside `try` / `finally`. The pattern to copy is `_clear_registration` in `tests/unit/guard/test_testing.py:27-33`.
- **Verification commands** are `make check` (ruff lint + format check, `ty check`, `pyright`, and griffe) and `make test` (`uv run pytest`, coverage `fail_under = 80` per `pyproject.toml`). Use `make apicheck` for the griffe gate — the design document quotes a shorter griffe command that omits the `-e tools/griffe_extensions.py:IgnoreProtobufDescriptors` flag this repo actually requires (`Makefile:18`).
- Full testing conventions: `tests/TESTING_PATTERNS.md`, `AGENTS.md`, `CONTRIBUTING.md`. **Caveat on `TESTING_PATTERNS.md`:** it is partly generic imported boilerplate, and its examples contradict the rule above — it shows `async def test_feature(datasette, scenario, table)` at line 53 and another `async def` at line 146, referencing a `datasette` fixture from an unrelated project. Those two are the only `async def test_` occurrences anywhere in the repository; no actual test file has one. Take the fixture-isolation and shared-scope guidance from that document, and ignore its async examples.

## Measured contextvars behavior (Python 3.10.20, this repo's floor)

These were executed against this project's `uv` environment, not recalled. Tests in Task 6 assert exactly this table.

| Boundary | Propagates? |
|---|---|
| `asyncio.create_task()` | Yes |
| `asyncio.to_thread()` | Yes |
| `loop.run_in_executor(pool, fn)` | **No** |
| `ThreadPoolExecutor.submit(fn)` | **No** |
| `ThreadPoolExecutor.submit(copy_context().run, fn)` | Yes |

Also measured: `ContextVar.set()` returns a `Token` that is **not** a context manager on 3.10 (`hasattr(token, "__enter__")` is `False`). Token-as-context-manager arrives in Python 3.14, so `try` / `finally` is mandatory here.

`contextvars.Context.run()` raises `RuntimeError` if the same `Context` object is already entered, including from another thread. Never reuse one `copy_context()` result across concurrent submissions.

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: Extract time-ordered ID generation into `src/arcjet/_ids.py`

**Verifies:** None — this is a pure refactor of existing behavior. Existing tests must keep passing unchanged.

**Why:** `src/arcjet/_client.py` already contains a UUIDv7 generator and a Crockford base32 encoder producing a 26-character sortable string — which is structurally what the design calls a ULID. Reusing it beats hand-rolling a second ULID implementation (DRY), and it moves to its own module so `arcjet/guard/_context.py` can depend on ID generation without depending on the HTTP client's module.

**Not an import-cost argument.** `src/arcjet/__init__.py:3` is `from ._client import Arcjet, ArcjetSync, arcjet, arcjet_sync`, so importing *any* `arcjet.*` submodule already executes `arcjet._client` — `guard/_context.py` importing `arcjet._metadata` triggers it regardless. Extraction buys layering and DRY, not a lighter import. Do not repeat a load-time claim for it.

**Files:**
- Create: `src/arcjet/_ids.py`
- Modify: `src/arcjet/_client.py` (remove `_CROCKFORD_ALPHABET` at line 105 and `_uuidv7_bytes()` at lines 108-117, and replace the encoder body inside `_new_local_request_id()` at lines 126-133 — keeping its docstring at 121-125)

**Step 1: Confirm the symbols have no other callers**

```bash
grep -rn "_uuidv7_bytes\|_CROCKFORD_ALPHABET" src/ tests/ tools/
```

Expected: hits only in `src/arcjet/_client.py`. If anything else references them, update that call site too in this task.

**Step 2: Create `src/arcjet/_ids.py`**

```python
"""Time-ordered identifier generation shared across the SDK.

Two callers need a sortable id and nothing else from each other:
``_new_local_request_id`` in the HTTP client, and correlation IDs in
:mod:`arcjet.guard._context`.  One implementation, owned by neither.
"""

from __future__ import annotations

import os
import time

__all__ = ["crockford32", "new_correlation_id", "uuidv7_bytes"]

_CROCKFORD_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"


def uuidv7_bytes() -> bytes:
    """Generate a UUIDv7 as 16 raw bytes (RFC 9562)."""
    timestamp_ms = int(time.time() * 1000)
    rand_bytes = os.urandom(10)
    rand_a = rand_bytes[0] << 4 | rand_bytes[1] >> 4
    rand_b = int.from_bytes(rand_bytes[2:], "big") & ((1 << 62) - 1)

    hi = (timestamp_ms << 16) | (0x7 << 12) | rand_a  # ver=7
    lo = (0b10 << 62) | rand_b  # var=10
    return hi.to_bytes(8, "big") + lo.to_bytes(8, "big")


def crockford32(raw: bytes) -> str:
    """Encode 16 raw bytes as 26 Crockford base32 characters, big-endian.

    See https://github.com/jetify-com/typeid for the specification this
    matches.
    """
    n = int.from_bytes(raw, "big")
    chars = []
    for _ in range(26):
        chars.append(_CROCKFORD_ALPHABET[n & 0x1F])
        n >>= 5
    chars.reverse()
    return "".join(chars)


def new_correlation_id() -> str:
    """Generate a correlation ID for a new Sequence.

    26 characters of Crockford base32 over a UUIDv7: lowercase alphanumeric,
    lexicographically sortable by creation time, and comfortably inside the
    server's 256-byte printable-ASCII bound.
    """
    return crockford32(uuidv7_bytes())
```

**Step 3: Rewire `src/arcjet/_client.py`**

Delete `_CROCKFORD_ALPHABET` and `_uuidv7_bytes()`. Add `from arcjet._ids import crockford32, uuidv7_bytes` to the imports, and reduce `_new_local_request_id()` to:

```python
def _new_local_request_id() -> str:
    """Generate a TypeID-compatible local request ID with ``lreq`` prefix.

    The suffix is a Crockford base32 encoding of a UUIDv7 (26 chars).
    See https://github.com/jetify-com/typeid for the specification.
    """
    return f"lreq_{crockford32(uuidv7_bytes())}"
```

**Step 4: Verify nothing changed behaviorally**

```bash
uv run pytest tests/ -q
```
Expected: same pass count as before the refactor, no new failures.

```bash
uv run python -c "
from arcjet._client import _new_local_request_id
v = _new_local_request_id()
assert v.startswith('lreq_'), v
assert len(v) == 5 + 26, len(v)
assert v[5:].isalnum() and v[5:].islower(), v
print('ok', v)
"
```
Expected: `ok lreq_<26 lowercase alphanumeric chars>`

**Step 5: Commit**

```bash
git add src/arcjet/_ids.py src/arcjet/_client.py
git commit -m "refactor: extract time-ordered id generation into arcjet._ids"
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Tests for `arcjet._ids`

**Verifies:** None — regression cover for the Task 1 refactor. Required because `fail_under = 80` applies to the new module.

**Files:**
- Create: `tests/unit/test_ids.py` (unit)

**Testing:**
Plain `def test_*` functions, no fixtures needed. Cover:
- `uuidv7_bytes()` returns exactly 16 bytes, with the RFC 9562 version nibble equal to `7` and the variant bits equal to `0b10`.
- `crockford32()` returns exactly 26 characters drawn only from `0123456789abcdefghjkmnpqrstvwxyz` (note Crockford omits `i`, `l`, `o`, `u`).
- `new_correlation_id()` returns 26 lowercase alphanumeric characters, and two successive calls differ.
- IDs generated in sequence sort in creation order — assert that a list of several IDs generated in a loop equals its own `sorted()` result. This is the time-ordering property the design relies on.

**Verification:**
```bash
uv run pytest tests/unit/test_ids.py -q
```
Expected: all tests pass.

**Commit:** `test: cover arcjet._ids id generation`
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-6) -->

<!-- START_TASK_3 -->
### Task 3: `src/arcjet/guard/_context.py` — ambient correlation context

**Verifies:** langchain-helper.AC3.1, langchain-helper.AC3.2, langchain-helper.AC3.3, langchain-helper.AC3.4 (first clause)

**Files:**
- Create: `src/arcjet/guard/_context.py`

**Implementation:**

```python
"""Ambient correlation context for Arcjet Sequences.

A Sequence is the joined trace of every decision and capture belonging to one
run.  Joining happens on ``site_id`` plus a correlation ID, so the correlation
ID has to reach every checkpoint along the way.  Threading it through as an
argument means every intermediate function grows a parameter it does not
otherwise care about, so it is carried ambiently instead.

Ambient, not global.  ``arcjet.guard._registry`` explains why *registration*
is a module global: each thread starts with a fresh context, so a value set
once at startup is invisible to a WSGI worker thread.  Correlation is the
opposite problem — it is set per run, on the path that will read it — which is
exactly what a :class:`~contextvars.ContextVar` is for.

Propagation is not universal, and the gaps are documented rather than papered
over.  A value set here is visible inside ``asyncio.create_task()`` and
``asyncio.to_thread()``.  It is **not** visible inside a bare
``ThreadPoolExecutor.submit()``, ``loop.run_in_executor()``, or across a task
broker; for those, read the ID out with :func:`current_correlation_id`, carry
it yourself, and reopen :func:`arcjet_sequence` on the far side.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator, Optional

from arcjet._ids import new_correlation_id
from arcjet._metadata import Metadata

__all__ = [
    "arcjet_sequence",
    "current_correlation_id",
    "current_sequence_metadata",
]

MAX_CORRELATION_ID_BYTES = 256
"""Server-side bound on a correlation ID, matched here so an over-long value
fails loudly at the call site instead of being silently dropped on the wire."""

_correlation_id: ContextVar[Optional[str]] = ContextVar(
    "arcjet_correlation_id", default=None
)
_sequence_metadata: ContextVar[Optional[Metadata]] = ContextVar(
    "arcjet_sequence_metadata", default=None
)


def _validated(correlation_id: str) -> str:
    """Return *correlation_id* if the server will accept it, else raise.

    Rejecting beats truncating.  A truncated ID still looks like an ID and
    still joins *something* — just the wrong Sequence, silently, and only in
    the runs whose IDs happened to be long.
    """
    if not isinstance(correlation_id, str):
        raise TypeError(
            f"correlation_id must be a str, got {type(correlation_id).__name__}"
        )
    if not correlation_id:
        raise ValueError("correlation_id must not be empty")
    if not correlation_id.isascii() or not correlation_id.isprintable():
        raise ValueError(
            "correlation_id must be printable ASCII "
            "(no control characters, no non-ASCII)"
        )
    size = len(correlation_id.encode("utf-8"))
    if size > MAX_CORRELATION_ID_BYTES:
        raise ValueError(
            f"correlation_id must be at most {MAX_CORRELATION_ID_BYTES} bytes, "
            f"got {size}"
        )
    return correlation_id


@contextmanager
def arcjet_sequence(
    *,
    correlation_id: Optional[str] = None,
    metadata: Optional[Metadata] = None,
) -> Iterator[str]:
    """Scope a correlation ID over a block, yielding the active ID.

    Derive the ID from something the application already has — a session id, a
    thread id, a job id — so a Sequence lines up with the thing a human would
    go looking for.  Omit it and a sortable one is generated, which is the
    right answer only for a genuinely new entrypoint.

    Passing *metadata* attaches it to the block; passing ``None`` inherits
    whatever an enclosing block set rather than clearing it, so a nested block
    that only re-declares the ID does not drop the outer metadata.

    Restores the previous values on exit, including when the body raises.

    Args:
        correlation_id: The ID for this Sequence. Validated as at most 256
            bytes of printable ASCII.
        metadata: Optional metadata to associate with the block.

    Yields:
        The active correlation ID.

    Raises:
        TypeError: If *correlation_id* is given and is not a ``str``.
        ValueError: If *correlation_id* is empty, is not printable ASCII, or
            exceeds 256 bytes.

    Example:
        ::

            from arcjet.guard import arcjet_sequence

            with arcjet_sequence(correlation_id=session.id):
                await handle_request()
    """
    resolved = (
        new_correlation_id() if correlation_id is None else _validated(correlation_id)
    )

    # `Token` only becomes a context manager in Python 3.14; on the supported
    # 3.10 floor `try` / `finally` is the whole protocol.
    id_token = _correlation_id.set(resolved)
    metadata_token = None if metadata is None else _sequence_metadata.set(metadata)
    try:
        yield resolved
    finally:
        if metadata_token is not None:
            _sequence_metadata.reset(metadata_token)
        _correlation_id.reset(id_token)


def current_correlation_id() -> Optional[str]:
    """Return the correlation ID of the enclosing sequence, or ``None``.

    ``None`` is an ordinary state, not an error: code outside any sequence
    still evaluates policy, it just produces decisions that join no Sequence.
    """
    return _correlation_id.get()


def current_sequence_metadata() -> Optional[Metadata]:
    """Return the metadata of the enclosing sequence, or ``None``."""
    return _sequence_metadata.get()
```

**Verification:**
```bash
uv run python -c "
from arcjet.guard._context import arcjet_sequence, current_correlation_id
assert current_correlation_id() is None
with arcjet_sequence(correlation_id='abc') as cid:
    assert cid == 'abc' and current_correlation_id() == 'abc'
assert current_correlation_id() is None
print('ok')
"
```
Expected: `ok`

**Commit:** `feat(guard): add ambient correlation context`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Export the three public names from `arcjet.guard`

**Verifies:** None directly — it is the import path every later phase and every test uses.

**Files:**
- Modify: `src/arcjet/guard/__init__.py` (add the import, and add three entries to `__all__`)

**Implementation:**

Add alongside the existing private-module re-exports:

```python
from ._context import arcjet_sequence, current_correlation_id, current_sequence_metadata
```

Add to `__all__`. The list is grouped by kind with comment headers; put these under a new group, keeping each group's entries alphabetical to match the file's existing style:

```python
    # Ambient correlation context
    "arcjet_sequence",
    "current_correlation_id",
    "current_sequence_metadata",
```

Do **not** export `MAX_CORRELATION_ID_BYTES` — publishing it is a compatibility commitment this integration does not need.

**Verification:**
```bash
uv run python -c "
import arcjet.guard as g
for n in ('arcjet_sequence', 'current_correlation_id', 'current_sequence_metadata'):
    assert n in g.__all__, n
    assert hasattr(g, n), n
print('ok')
"
make check
```
Expected: `ok`, then ruff/ty/pyright clean. `make apicheck` reports no breaking change — these are pure additions.

**Commit:** `feat(guard): export ambient correlation context`
<!-- END_TASK_4 -->

<!-- START_TASK_5 -->
### Task 5: Shared sequence-isolation fixture

**Verifies:** None — shared test infrastructure. Phases 3–7 all depend on it.

**Why this is its own task:** Phases 5, 6 and 7 are each told to "reuse the Phase 1 `_reset_sequence_context` fixture" and "the Phase 3 stub client". Nothing can be reused if it is defined inside another test module's body. Two facts make that impossible here: `tests/unit/__init__.py` **does not exist** (only `tests/unit/guard/__init__.py`, `tests/integration/__init__.py`, and `tests/integration/guard/__init__.py` do), so `tests.unit.guard.test_checkpoint` is not an importable module path; and importing helpers out of another test module is bad practice regardless. This task creates the one shared home.

**Files:**
- Create: `tests/guard_doubles.py`
- Modify: `tests/unit/guard/conftest.py` — add the autouse wrapper
- Create: `tests/integration/guard/conftest.py` — same wrapper

**Implementation:**

`tests/` is already on `sys.path` for the suite — `tests/conftest.py` does `from fixtures.protobuf_stubs import ...`, which only resolves because pytest puts the rootdir's `tests/` on the path. So `from guard_doubles import ...` resolves from both `tests/unit/guard/` and `tests/integration/guard/`. (Do not cite `tests/helpers.py` as precedent: it exists but nothing imports it.) Follow that existing convention; do not add `tests/unit/__init__.py` to make a dotted path work, because that would change how pytest roots the whole suite.

`tests/guard_doubles.py` starts with just the fixture; Phase 3 Task 6 adds the stub client to the same module:

```python
"""Shared test doubles and fixtures for the Arcjet guard surfaces.

Imported flat (``from guard_doubles import ...``) because ``tests/`` is on
sys.path for the suite, the same way ``helpers`` and ``fixtures`` already are.
"""

from __future__ import annotations

import pytest

from arcjet.guard._context import _correlation_id, _sequence_metadata


@pytest.fixture
def reset_sequence_context():
    """Guarantee a test starts and ends outside any sequence.

    ``arcjet_sequence`` restores on exit, so a well-behaved test cannot leak.
    A test that sets the ContextVar directly can — and a leaked correlation ID
    surfaces as an unrelated test failing somewhere else entirely.
    """
    id_token = _correlation_id.set(None)
    metadata_token = _sequence_metadata.set(None)
    try:
        yield
    finally:
        _sequence_metadata.reset(metadata_token)
        _correlation_id.reset(id_token)
```

In both `tests/unit/guard/conftest.py` and the new `tests/integration/guard/conftest.py`, make it apply automatically without becoming global:

```python
from guard_doubles import reset_sequence_context  # noqa: F401  (fixture)


@pytest.fixture(autouse=True)
def _reset_sequence_context(reset_sequence_context):
    """Apply sequence isolation to every guard test in this directory."""
```

Scoped per-directory rather than autouse in the root `tests/conftest.py` on purpose: a root autouse fixture would run for `tests/analyze/` and `tests/benchmarks/` too, and the benchmark suite's whole job is to not have per-test overhead added to it.

**Do not disturb `tests/unit/guard/conftest.py`'s existing content** — it deliberately overrides the parent `_ensure_protobuf_mocked` autouse fixture to a no-op. Add to that file, do not replace it.

**Verification:**
```bash
uv run pytest tests/unit/guard/ tests/integration/guard/ -q
```
Expected: the existing guard tests still pass with the new autouse fixture in place.

**Commit:** `test(guard): add a shared sequence-isolation fixture`
<!-- END_TASK_5 -->

<!-- START_TASK_6 -->
### Task 6: Tests for ambient correlation context

**Verifies:** langchain-helper.AC3.1, langchain-helper.AC3.2, langchain-helper.AC3.3, langchain-helper.AC3.4, langchain-helper.AC6.1, langchain-helper.AC6.2, langchain-helper.AC6.3

**Files:**
- Create: `tests/unit/guard/test_context.py` (unit)

**Implementation — isolation:**

Nothing to define. Task 5's autouse fixture in `tests/unit/guard/conftest.py` already applies to every test in this file. Import the three public names from `arcjet.guard` — not from `arcjet.guard._context` — so the tests also prove the Task 4 export path.

**Testing:**
Tests must verify each AC listed above.

- **langchain-helper.AC3.1:** Inside `with arcjet_sequence(correlation_id="corr-1") as cid`, both the yielded `cid` and `current_correlation_id()` equal `"corr-1"`. Add a second case with no argument: the yielded value is a non-empty string and `current_correlation_id()` returns that same value.
- **langchain-helper.AC3.2:** Open an outer block with `"outer"`, assert; open a nested block with `"inner"`, assert it reads `"inner"`; on leaving the nested block assert it reads `"outer"` again; on leaving the outer block assert `None`. Add a second case where the nested block's body raises a caught exception and assert the outer ID is still restored — that is what the `finally` exists for.
- **langchain-helper.AC3.3:** Parametrize over rejected values, asserting `pytest.raises(ValueError)`:
  - `"a" * 257` (over the byte bound)
  - `"a" * 256 + "b"` — and separately assert `"a" * 256` is *accepted*, pinning the boundary as inclusive
  - a value containing a non-ASCII printable such as `"café"` (proves `isprintable()` alone is insufficient — `"é".isprintable()` is `True`)
  - a value containing a control character such as `"a\tb"` and `"a\nb"`
  - the empty string `""`
  Also assert a non-`str` (e.g. `123`) raises `TypeError`.
  Critically: assert the ID is **rejected**, not truncated. After each `pytest.raises`, assert `current_correlation_id() is None` — nothing was set.
- **langchain-helper.AC3.4:** With no enclosing block, `current_correlation_id()` and `current_sequence_metadata()` both return `None`.
- **langchain-helper.AC6.1:** A plain `def test_*` that calls `asyncio.run(...)` on an inner coroutine which opens `arcjet_sequence(correlation_id="task-1")`, awaits `asyncio.create_task(reader())`, and asserts the task's captured value is `"task-1"`. Do not write `async def test_*` — this repo has no async test plugin.
- **langchain-helper.AC6.2:** Same shape, asserting `await asyncio.to_thread(current_correlation_id) == "thread-1"`.
- **langchain-helper.AC6.3:** Two assertions in one test, matching the measured table:
  - `ThreadPoolExecutor.submit(current_correlation_id).result() is None` inside an open sequence — correlation does **not** cross.
  - `ThreadPoolExecutor.submit(copy_context().run, current_correlation_id).result()` equals the active ID — the documented idiom does cross.
  Use a fresh `copy_context()` per submission; re-entering one `Context` concurrently raises `RuntimeError`.
  Add a third assertion for `loop.run_in_executor(pool, current_correlation_id)` returning `None`, since Phase 7 documents that gap too.

**Metadata coverage** (no AC, but the function is public and coverage is gated at 80%): assert `current_sequence_metadata()` returns what a block passed; assert a nested block passing `metadata=None` inherits the outer metadata rather than clearing it; assert a nested block passing its own metadata replaces it and the outer value is restored on exit.

**Verification:**
```bash
uv run pytest tests/unit/guard/test_context.py -q
```
Expected: all tests pass.

```bash
make test
make check
```
Expected: full suite passes, coverage stays at or above 80%, ruff/ty/pyright clean, `make apicheck` reports no breaking change.

**Commit:** `test(guard): cover ambient correlation context`
<!-- END_TASK_6 -->

<!-- END_SUBCOMPONENT_B -->

---

## Phase 1 done when

- `arcjet_sequence`, `current_correlation_id`, and `current_sequence_metadata` are importable from `arcjet.guard`.
- Tests prove nesting restores the outer ID (including when the inner body raises), an invalid ID is rejected rather than truncated, correlation survives `asyncio.create_task()` and `asyncio.to_thread()`, a bare `ThreadPoolExecutor.submit()` does not inherit it while the `copy_context()` idiom does, and a fresh context reads `None`.
- `make test` passes at ≥80% coverage and `make check` is clean, including `make apicheck` reporting no breaking change.
