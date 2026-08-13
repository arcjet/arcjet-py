# LangChain Framework Helper — Phase 7: End-to-end example and documentation

**Goal:** A design partner can instrument a LangChain workflow by reading one example.

**Architecture:** A new `examples/fastapi-langchain-guard/` runs the full path the design describes — HTTP entrypoint opens a sequence, an agent runs, a guarded tool executes, work crosses a background boundary carrying the correlation ID in its payload, and the worker reopens the sequence before guarding an external action. Every decision and capture shares one `site_id` + `correlation_id`, which is what the Console joins into a Sequence. The repository README gains the surfaces, the two extras, the fail-closed default, and the propagation gaps.

**Tech Stack:** FastAPI, LangChain, `arcjet` (editable), uv.

**Scope:** Phase 7 of 7 from `docs/design-plans/2026-08-13-langchain-helper.md`.

**Dependencies:** Phases 1–6.

**Codebase verified:** 2026-08-13

---

## Acceptance Criteria Coverage

This phase implements and tests:

### langchain-helper.AC6: Correlation crosses boundaries
- **langchain-helper.AC6.4 Success:** A worker resuming an explicit correlation ID produces decisions and captures on the same Sequence as the originating request.

### langchain-helper.AC9: Deliverable and gates
- **langchain-helper.AC9.1 Success:** The example runs end to end — HTTP entrypoint through agent, guarded tool, background boundary, external action — producing one joined Sequence.
- **langchain-helper.AC9.2 Success:** `make check` and `make test` pass at ≥80% coverage, and `griffe check arcjet -s src --against origin/main` reports no breaking change.

**On `langchain-helper.AC9.1`:** running against a real key and eyeballing one joined Sequence in the Console is **human verification** — it needs a live account and a live backend. Task 3 automates the mechanism it depends on (`langchain-helper.AC6.4`) in-process, and Task 4 records the manual steps. Do not claim `langchain-helper.AC9.1` from a green test run.

**On `langchain-helper.AC9.2`:** the design quotes `griffe check arcjet -s src --against origin/main`, which omits the `-e tools/griffe_extensions.py:IgnoreProtobufDescriptors` flag this repo requires. `make apicheck` (`Makefile:18`) is the real gate and is what satisfies this criterion.

---

## Existing example layout to match

`examples/` holds `fastapi`, `flask`, `fastapi-langchain`, `flask-langchain`, `fastapi-guard-policy`, `fastapi-rampart`. Read `examples/fastapi-langchain/` first and match it: `example.env`, `main.py`, `pyproject.toml`, `README.md`, `uv.lock`.

Its `pyproject.toml` is the template:

```toml
[project]
name = "example-fastapi-langchain"
version = "0.1.0"
description = "Arcjet Python SDK Example FastAPI + LangChain Application"
readme = "README.md"
requires-python = ">=3.10"
dependencies = [
    "arcjet",
    "fastapi[standard]==0.141.1",
    "langchain==1.3.14",
    "langchain-openai==1.4.1",
]

[tool.uv]
exclude-newer = "7 days"

[tool.uv.sources]
arcjet = { path = "../../", editable = true }
```

Note `examples/` escapes all four root gates, but by two different mechanisms — worth knowing before assuming a fifth tool would also skip it. It is named in `[tool.ruff] exclude` and `[tool.ty.src] exclude`. It is **not** named in `[tool.coverage.run] omit` or `[tool.pyright] exclude`; it escapes those because `addopts` measures only `--cov=src/arcjet` and pyright's `include` is `["src", "tests"]`. So example code is not linted or measured by the root gates. That is not licence to write it badly — it is the reference a design partner copies.

The existing `fastapi-langchain` example guards only the HTTP request via `aj.protect()` and leaves the LLM call unguarded. This new example is the one that guards the agent path, so it is additive rather than a replacement. Leave the existing example alone.

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: Scaffold `examples/fastapi-langchain-guard/`

**Verifies:** None — infrastructure, verified operationally.

**Files:**
- Create: `examples/fastapi-langchain-guard/pyproject.toml`
- Create: `examples/fastapi-langchain-guard/example.env`
- Create: `examples/fastapi-langchain-guard/uv.lock` (generated)

**Step 1: Write `pyproject.toml`**

Copy the template above, renaming to `example-fastapi-langchain-guard`, describing it as the guarded agent example, and depending on the **`langchain-agents`** extra so the middleware is available:

```toml
dependencies = [
    "arcjet[langchain-agents]",
    "fastapi[standard]==0.141.1",
    "langchain==1.3.14",
    "langchain-openai==1.4.1",
]
```

Keep `[tool.uv] exclude-newer` and the editable `[tool.uv.sources]` path exactly as the sibling example has them.

**Step 2: Write `example.env`**

Match the sibling's shape. Placeholders only — never a real key:

```
ARCJET_KEY=ajkey_yourkey
OPENAI_API_KEY=sk-yourkey
```

**Step 3: Generate the lock**

```bash
cd examples/fastapi-langchain-guard && uv lock
```
Expected: resolves, producing `uv.lock`. If `arcjet[langchain-agents]` does not resolve, Phase 5 Task 1's extra is missing or misnamed — fix it there.

**Step 4: Commit**

```bash
git add examples/fastapi-langchain-guard/
git commit -m "docs: scaffold the guarded LangChain example"
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: `main.py` and `worker.py`

**Verifies:** langchain-helper.AC9.1 (mechanism; human-verified in Task 4)

**Files:**
- Create: `examples/fastapi-langchain-guard/main.py`
- Create: `examples/fastapi-langchain-guard/worker.py`

**Implementation:**

`main.py` must show, in order, the five things the design's data-flow paragraph describes:

1. **Startup.** `register_arcjet(launch_arcjet(key=os.environ["ARCJET_KEY"]))` once, at application start.
2. **Entrypoint opens a sequence.** In the route handler, `with arcjet_sequence(correlation_id=session_id):` where `session_id` comes from the request — a header, a body field, or a cookie. Show it being **derived**, and comment why: a generated ID makes a Sequence nobody goes looking for. This is the Eve ADR's rule and the single most-copied line in the file.
3. **The agent runs**, with `ArcjetMiddleware` configured for one tool, and `ArcjetCaptureHandler` passed as a callback so the chain and model lifecycle land on the same Sequence.
4. **A guarded tool.** Wire the tool through `ArcjetMiddleware`'s `policies`, and show `guard_tool` in a comment as the alternative for a bare tool or an LCEL chain, so a reader knows both routes exist and when each applies.
5. **The background boundary.** Read `current_correlation_id()`, put it in the job payload explicitly, and hand off. Comment that `contextvars` do not cross a broker, a `ThreadPoolExecutor`, or a `ProcessPoolExecutor`, so the ID travels as data — this is the point of the whole file.

`worker.py` is the far side: it takes a payload containing the correlation ID, reopens `with arcjet_sequence(correlation_id=payload["correlation_id"]):`, and calls `guard_action` for the external effect. Keep it runnable without a broker — a plain function `main.py` can hand to `asyncio.to_thread` or a FastAPI `BackgroundTasks`, with a comment naming Celery/RQ/Dramatiq as where this shape goes in production. A reader must be able to run the example without standing up Redis.

**Wire the actual policy rules.** The design's Definition of Done requires prompt injection and sensitive info to be wired as policy inputs, and this example is where a partner sees what that looks like. The guarded tool's checkpoint must carry `DetectPromptInjection()(...)` bound to the user's message, and a sensitive-info rule bound to whatever the tool is about to send outward. Without them the example demonstrates plumbing rather than security, and the DoD item is unmet. Comment that **sensitive info denies rather than redacting** at the call site, so nobody assumes the value is being scrubbed on the way through.

Use `security_metadata(...)` on at least one checkpoint so the vocabulary appears in the reference a partner copies.

Show `on_guard_error` explicitly at one call site with a comment naming the default and the opt-out, since a fail-closed default is the one place Arcjet diverges from its platform-wide convention.

Call `await flush()` before the process exits, or the example will drop the very capture events it exists to demonstrate.

**Verification:**
```bash
cd examples/fastapi-langchain-guard
uv run python -c "import ast,pathlib; [ast.parse(p.read_text()) for p in pathlib.Path('.').glob('*.py')]; print('parse ok')"
```
Expected: `parse ok`.

Then confirm the app is importable and its routes are wired, without needing a server, a port, or shell job control (which is unavailable in a non-interactive shell):

```bash
ARCJET_KEY=ajkey_placeholder OPENAI_API_KEY=sk-placeholder \
  uv run python -c "
from main import app
paths = sorted(r.path for r in app.routes)
print(paths)
assert any(p != '/openapi.json' for p in paths), 'no application routes registered'
print('import ok')
"
```
Expected: the route list, then `import ok`. If module import requires live keys, the example is validating credentials at import time — move that into the startup handler so the file stays readable and testable.

Full behavior needs real keys — Task 4.

**Commit:** `docs: add the guarded FastAPI + LangChain example`
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-4) -->

<!-- START_TASK_3 -->
### Task 3: Test the background-boundary resume

**Verifies:** langchain-helper.AC6.4

**Files:**
- Create: `tests/unit/guard/test_sequence_boundary.py` (unit)

**Why a test and not just the example:** `langchain-helper.AC6.4` is the one Phase 7 criterion that is a claim about behavior rather than about a document, and it is the mechanism `langchain-helper.AC9.1` rests on. It is fully testable in-process with no key, no broker, and no LangChain.

**Testing:**
Use `register_test_client()` so both guards and captures are recorded on one object, and the shared autouse fixture from Phase 1 Task 5 (already active in this directory).

- **langchain-helper.AC6.4:** Model the whole hop in one test.
  1. Open `arcjet_sequence(correlation_id="req-1")`. Inside, run a checkpoint via `guard_action_sync` (with `on_guard_error="allow"`, since the test client fails open) and read `payload = {"correlation_id": current_correlation_id()}` — the explicit export.
  2. **Leave the sequence.** Assert `current_correlation_id() is None`, proving the resume is doing real work rather than reading a value that leaked.
  3. In a *separate thread* — a bare `ThreadPoolExecutor.submit`, so nothing is inherited — reopen `arcjet_sequence(correlation_id=payload["correlation_id"])` and run a second checkpoint plus a `capture_action`.
  4. Assert every recorded guard **and** every recorded capture, from both sides of the boundary, carries `correlation_id == "req-1"`. One Sequence is exactly the claim.
- **The negative control:** the same worker function run *without* reopening the sequence produces a guard whose `correlation_id is None`. Without this, the positive test could pass on inherited context and prove nothing.

**Verification:**
```bash
uv run pytest tests/unit/guard/test_sequence_boundary.py -q
```
Expected: passes.

**Commit:** `test(guard): cover correlation resume across a worker boundary`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Documentation, and the manual end-to-end run

**Verifies:** langchain-helper.AC9.1 (human), langchain-helper.AC9.2

**Files:**
- Create: `examples/fastapi-langchain-guard/README.md`
- Modify: `README.md` (repository root)

**Implementation:**

The example README follows the sibling's structure: title `Arcjet Python SDK Example FastAPI + LangChain Guard Application`, a one-line description, setup (`cp example.env .env`, set keys), then each endpoint with a `curl` and its expected response. Add a short "What to look for" section pointing the reader at the single joined Sequence in the Console and naming the correlation ID to search for.

The root `README.md` gains, in the Guard section:

- **The surfaces**, and when each applies: `guard_action` / `guard_action_sync` for any Python code including workers with no LangChain; `guard_tool` for wrapping a `BaseTool` or an LCEL chain; `ArcjetMiddleware` for `create_agent` applications, which sees parsed arguments; `ArcjetCaptureHandler` for observe-only lifecycle capture.
- **The two extras**, and exactly what each unlocks: `arcjet[langchain]` → `guard_tool` and the callback handlers, `langchain-core` only. `arcjet[langchain-agents]` → adds `ArcjetMiddleware`, and pulls LangGraph. Say why they are separate.
- **The fail-closed default.** Name both the `on_guard_error="deny"` default and the `"allow"` opt-out, and state that a `DENY` blocks regardless. This is the one documented divergence from Arcjet's platform-wide fail-open convention and the ADR makes documenting it an obligation.
- **Correlation and Sequences.** `arcjet_sequence()`, `current_correlation_id()`, and the precedence rule: explicit argument → `RunnableConfig` → ambient → none.
- **The propagation gaps**, as the measured table. Do not soften it:

  | Boundary | Propagates? |
  |---|---|
  | `asyncio.create_task()` | Yes |
  | `asyncio.to_thread()` | Yes |
  | `ThreadPoolExecutor.submit()` / `loop.run_in_executor()` | **No** — use `copy_context()` |
  | `ProcessPoolExecutor` | **No** — serialize explicitly |
  | Generators, async generators | **No** — by design, per PEP 568 |
  | Celery / RQ / Dramatiq | **No** — carry the ID in the job payload |

  Show the `copy_context()` idiom, and note that one `Context` cannot be entered twice concurrently — a fresh `copy_context()` per submission.
- **Redaction is a named future phase.** State plainly that sensitive info currently **denies** rather than redacting, that no surface mutates content, and that redaction would require an explicit carve-out from the no-mutation rule in the checkpoint ADR. A reader must not assume redaction is coming for free.

**Step: run the example end to end (human verification for `langchain-helper.AC9.1`)**

This needs a real `ARCJET_KEY` and `OPENAI_API_KEY` and cannot be automated here. Record in the PR's verification comment — not the PR description:

1. `cd examples/fastapi-langchain-guard && cp example.env .env`, fill both keys.
2. `uv run fastapi dev main.py`
3. `curl` the guarded endpoint with a known session id, e.g. `sess-verify-001`.
4. Confirm the tool ran and the background action completed.
5. In the Arcjet Console, search that correlation ID and confirm **one** Sequence containing: the tool checkpoint's decision, its `outcome="success"` capture, the chain/model lifecycle captures, and the worker's decision and capture — all on one `site_id` + `correlation_id`.
6. Repeat with a prompt-injection payload in the user message and confirm the denial appears on the same Sequence with `outcome="denied"` and that the tool did not run.
7. Repeat with a value that trips the sensitive-info rule and confirm it is **denied, not redacted** — the tool did not run, and the value was not silently rewritten and passed through.

**Step: the gates (`langchain-helper.AC9.2`)**

```bash
make check
make test
```
Expected: ruff, `ty`, and `pyright` clean; `make apicheck` reports no breaking change; the full suite passes with coverage at or above `fail_under = 80`.

If `make apicheck` reports a break, do not add the `breaking` label to route around it — every change in this plan is additive by construction, so a reported break means something was renamed or dropped by accident. The likeliest cause is a public name lost in Phase 4's module-to-package conversion.

**Commit:** `docs: document the guard surfaces, extras, and correlation propagation`
<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_B -->

---

## Phase 7 done when

- The example runs end to end against a real key and produces a single joined Sequence (human-verified).
- A worker resuming an exported correlation ID lands on the originating request's Sequence, proven by an automated test with a negative control.
- The README documents the surfaces, the two extras, the fail-closed default and its opt-out, the correlation precedence, the propagation gaps with the `copy_context()` idiom, and redaction as a named future phase.
- `make check` and `make test` pass at ≥80% coverage, and `make apicheck` reports no breaking change.
