# AGENTS.md — Coding Agent Onboarding Guide

This document provides essential information for coding agents working on the
arcjet-py repository for the first time.

**Last verified:** 2026-08-13

## Repository overview

**Project**: Arcjet Python SDK
**Purpose**: Security SDK for Python applications providing bot detection, rate
limiting, email validation, Shield WAF, and attack protection for Flask,
FastAPI, and other Python web frameworks.
**Language**: Python 3.10+
**Package manager**: uv

## Quick start

### Environment setup

1. **Python version**: 3.10+ (see `.python-version`)
2. **Install uv** (if not already installed):
   ```bash
   pip install uv
   ```
3. **Install [just](https://just.systems)** (the command runner), if not
   already installed:
   ```bash
   uv tool install rust-just
   ```
4. **Install dependencies**:
   ```bash
   just install
   ```
   This creates a virtual environment in `.venv` and installs all dependencies
   from `uv.lock`.

### Development workflow

Common tasks are wrapped in the `justfile`. Run `just --list` to see every
recipe:

```bash
just pre-commit  # Format, run all checks, then the full test suite
just check       # All lint + type + API-break checks
just format      # Auto-fix imports and format code
just test        # All tests (unit + integration + analyze, with coverage)
just bench       # Run benchmarks
```

Anything not covered by a recipe should be prefixed with `uv run`.

## Build, test, and lint commands

### Testing

Run all tests with a single command:

```bash
uv run pytest
```

This runs both unit tests (in `tests/unit/`) and integration tests (in
`tests/fastapi/`, `tests/flask/`, etc.) together.

**Test organization**: Tests use pytest fixtures for protobuf mocking, allowing
all tests to run together without cross-contamination. See
`tests/TESTING_PATTERNS.md` for detailed testing conventions.

**Async tests**: There is no async pytest plugin configured — no
`pytest-asyncio`, and `anyio` is present only as a transitive dependency, not
enabled as a plugin. An `async def test_*` function therefore **fails** with
"async def functions are not natively supported". Test async behavior from a
plain `def test_*` that calls `asyncio.run(...)`. Every test in `tests/` follows
this; the two `async def test_*` examples in `tests/TESTING_PATTERNS.md` are
imported boilerplate that does not reflect this repository — do not copy them.

**Guard test doubles**: `tests/guard_doubles.py` holds the shared
`StubGuardClient`, decision builders, and `reset_sequence_context`. pytest puts
`tests/` on `sys.path`, so import it flat (`from guard_doubles import ...`).
Prefer these over hand-rolled stubs.

**Coverage**: Both test suites enforce an 80% minimum coverage threshold
(`fail_under = 80` in `pyproject.toml`). Generated code (protobuf and witgen
output) is excluded from coverage via `[tool.coverage.run] omit`.

WASM binding tests are in `tests/analyze/` and run as part of the main test suite.

### Linting, formatting, and type checking

```bash
uv run ruff check --select I --fix  # Sort imports
uv run ruff format                  # Format code
uv run ruff check                   # Lint
uv run ty check                     # ty type checker
uv run pyright                      # Pyright type checker
```

Pyright is gating: it exits non-zero and fails `make check`.

`ty` is **not** gating — it exits 0 even when it reports diagnostics, so
`make check` passes regardless and the diagnostic *count* is the only signal.
The baseline is exactly one pre-existing diagnostic, an
`unused-type-ignore-comment` at `src/arcjet/_analyze/_imports.py:36`. Compare
against that number; "Found 1 diagnostic" means you added nothing.

Some test files are excluded from type checking (see `[tool.pyright]` and
`[tool.ty.src]` in `pyproject.toml`).

Suppression comments:
- `# type: ignore[error-code]` — Recognized by both pyright and ty.
- `# pyright: ignore[rule]` — Pyright-specific.
- `# ty: ignore[rule]` — ty-specific (e.g., conditional stdlib imports on 3.10).

### API breaking change detection

```bash
uv run griffe check arcjet -s src --against origin/main
```

PRs with breaking changes must be labeled with `breaking` label to be merged.

**IMPORTANT**: Always run this check before committing changes. Breaking changes
must be avoided unless absolutely necessary. Whenever there is a breaking
change, existing code must not break — we must maintain backward compatibility
and provide clear migration paths. This can be docs, deprecation warnings, and
keeping the existing API surface intact with internal changes.

## Code organization

### Source structure

- `src/arcjet/` — Main SDK package. Public API in `__init__.py`, client in
  `_client.py`, rules in `_rules.py`, local WASM evaluation in `_local.py`.
  Protobuf code in `proto/` is **generated — do not edit**.
- `src/arcjet/guard/` — Arcjet Guard: protection for code paths with no HTTP
  request (agent tool calls, workers, MCP handlers). Public API in
  `__init__.py`. Framework-agnostic core; `_checkpoint.py` is the single
  evaluation engine that every Guard surface delegates to, so behavior changes
  belong there rather than in a per-framework wrapper.
- `src/arcjet/guard/langchain/` — Optional LangChain integration, the only part
  of the tree that imports LangChain. `_tool.py` (`guard_tool`) and
  `_callbacks.py` (the capture handlers) need only `langchain-core`;
  `_middleware.py` needs the full `langchain` package and LangGraph, so
  `__init__.py` resolves its two names lazily rather than importing it. See the
  package docstring for the correlation-ID resolution contract.
- `src/arcjet/guard/crewai/` — Optional CrewAI integration (`arcjet[crewai]`).
  Independent of LangChain: it must not import `arcjet.guard.langchain`.
  `register_arcjet_hooks` is the invoke-wide PRE_TOOL_CALL gate (deny via
  `HookAborted` only; CrewAI swallows every other exception, so an Arcjet
  error raised from a hook *runs* the tool). `guard_tool` wraps a standalone
  `BaseTool` you call yourself and is the only path that raises
  `ArcjetDeniedError` / `ArcjetUnavailableError`. POST_TOOL_CALL is not
  registered: it fires on blocked calls and receives a different context
  object, so PRE→POST state is unmatchable once a tool runs a nested crew.
  Two invariants the tests pin, both fail-open if broken: only the wrapped
  *copy* carries the `_arcjet_guarded` brand (branding the original makes the
  hook skip an unguarded tool), and re-entrancy is tracked per tool instance
  (a global flag skips a guarded tool called from inside another one).
- `src/arcjet/guard/openai_agents/` — Optional OpenAI Agents integration
  (`arcjet[openai-agents]`, peer `openai-agents>=0.19.0,<1`). Independent of
  LangChain and CrewAI: it must not import either. `guard_tool` prepends a
  `ToolInputGuardrail` onto an authored `FunctionTool` so invoke never runs
  on DENY; the deny is `reject_content` of a JSON `ArcjetDenialResult`, not
  `raise_exception` and not an Arcjet error raised from `on_invoke_tool`
  (the SDK `default_tool_error_function` would swallow that into a generic
  string). `openai_agents_context` reads a caller-owned id and never mints,
  never reads `trace_id`, and never constructs a session. `needs_approval`
  is HITL and is not wrapped. Already-branded tools are skipped.
- `src/arcjet/guard/claude_agent_sdk/` — Optional Claude Agent SDK
  integration (`arcjet[claude-agent-sdk]`, peer `claude-agent-sdk>=0.2.127,<1`).
  Independent of LangChain, CrewAI, and OpenAI Agents: it must not import
  any of them. `guard_tool` wraps an authored `@tool` / `SdkMcpTool`
  `.handler`; on DENY it returns
  `{content: [{type: text, text: json.dumps(ArcjetDenialResult)}], is_error: True}`
  and does not throw (the SDK swallows into `str(e)`) and does not set
  `structuredContent` (`create_sdk_mcp_server` drops it).   `guard_hooks`
  denies unwrapped built-ins / MCP on `PreToolUse`
  (`permissionDecision: "deny"`), captures on `PostToolUse`
  (`claude.phase: after`; `exclude` does not skip it), and screens inbound
  on `UserPromptSubmit` (`{decision: "block"}` via `inbound=` — there is
  no `guard_inbound`). Tool-hook `rules` / `actor` / `inputs` / `metadata`
  receive `tool_input` plus `tool_name`. `actor=` / `inputs=` do not
  register a tool hook by themselves; pass `tools=True` for the default
  `{tool_name}.invoked` gate. Wrap-time `session_id=` / `correlation_id=`
  must be a UUID. Wrapped tools are excluded from PreToolUse by the
  `mcp__{server}__{name}` name. `claude_agent_context` reads a caller-owned
  UUID `session_id` and never mints, never reads `trace_id`.   `can_use_tool`
  is HITL and is not wrapped. Already-branded tools are skipped.
- `src/arcjet/guard/claude_managed_agents/` — Optional Claude Managed
  Agents integration (`arcjet[claude-managed-agents]`, peer
  `anthropic>=0.92.0,<2`). Hosted REST+SSE, beta
  `managed-agents-2026-04-01`. Independent of LangChain, CrewAI, OpenAI
  Agents, and the Claude Agent SDK: it must not import any of them.
  There is no PreToolUse. `guard_custom_tool` runs Guard before the app
  executes on `agent.custom_tool_use`; on DENY it does not run the tool
  and sends `user.custom_tool_result` (`is_error` is on that schema).
  `guard_events` gates `user.message` / `initial_events` before
  `sessions.events.send`. `claude_managed_agents_context` reads a
  caller-owned id and never mints, never reads Anthropic session/event
  `id`, never reads `trace_id`. Default `always_allow` cannot be gated.
  `web_search` / `web_fetch` always run on Anthropic. Do not export
  `guard_tool`, `guard_hooks`, or `guard_inbound`.
- `src/arcjet/_analyze/` — WASM component integration with typed Python bindings.
  See `docs/WITGEN.md` for binding generation and
  `docs/WASMTIME.md` for wasmtime-py details.
- `tools/witgen/` — WIT-to-Python code generator (configured by `witgen.toml`).
- `tests/` — Unit tests (`tests/unit/`), integration tests
  (`tests/integration/`, `tests/fastapi/`, `tests/flask/`), WASM binding tests
  (`tests/analyze/`), and benchmarks (`tests/benchmarks/`). See
  `tests/TESTING_PATTERNS.md`.
- `examples/` — Standalone runnable examples, each with its own
  `pyproject.toml` and lockfile. **Excluded from every root gate**: named in
  `[tool.ruff] exclude` and `[tool.ty.src] exclude`, and outside pyright's
  `include` and coverage's `--cov` target. `make check` and `make test` prove
  nothing about `examples/`; run an example's own project to verify it.

### Optional dependency extras

Framework integrations are optional extras in `pyproject.toml`. Two are
deliberately kept apart and **must not be merged**:

- `langchain` → `langchain-core` only. Enough for `guard_tool`.
- `langchain-agents` → the full `langchain` package, which hard-depends on
  LangGraph. Required only for agent middleware.
- `openai-agents` → `openai-agents>=0.19.0,<1`. Enough for
  `arcjet.guard.openai_agents`. No chromadb. Like CrewAI, it is in no
  dependency group so `uv.lock` does not pull its transitive tree into every
  `uv sync`; install it ad hoc for integration tests — see CONTRIBUTING.
- `claude-agent-sdk` → `claude-agent-sdk>=0.2.127,<1`. Enough for
  `arcjet.guard.claude_agent_sdk`. No chromadb. Same lockfile policy as
  openai-agents. The floor is 0.2.127 (0.2.83 was mcp CVE + timeout
  fail-close; 0.2.127 includes that and the background-task PreToolUse
  stdin fix). Verified on 0.2.148.
- `claude-managed-agents` → `anthropic>=0.92.0,<2`. Enough for
  `arcjet.guard.claude_managed_agents`. No chromadb. Same lockfile
  policy as openai-agents. The floor is 0.92.0 (first
  `client.beta.agents` / `sessions` / `environments`). This is not the
  Claude Agent SDK extra.
There is deliberately **no `crewai` extra and no CrewAI dependency group**.
`crewai` hard-depends on `chromadb~=1.1.0`, and chromadb 1.0.0–1.5.9 all carry
an unpatched critical RCE (CVE-2026-45829). No fixed version exists and
crewai's `~=1.1.0` pin could not reach one, so declaring it would put an
unpatchable critical CVE in every `arcjet[crewai]` install and in `uv.lock`.
`arcjet.guard.crewai` imports CrewAI lazily and enforces its own floor
(`>=1.15.3`) in `_import.py`. Install it ad hoc to run the integration suite —
see CONTRIBUTING.

Folding the second into the first would push LangGraph onto every `guard_tool`
user. Both LangChain extras are in the `dev` group so tests can exercise either
surface, which means a test passing locally does not prove the extra it needs
is correct — check the import against the extra that ships it.

Nothing outside `src/arcjet/guard/langchain/` may import LangChain. Using
Arcjet Guard must never require LangChain to be installed. Nothing outside
`src/arcjet/guard/crewai/` may import CrewAI. Nothing outside
`src/arcjet/guard/openai_agents/` may import the OpenAI Agents SDK
(`agents`). Nothing outside `src/arcjet/guard/claude_agent_sdk/` may
import the Claude Agent SDK (`claude_agent_sdk`). Nothing outside
`src/arcjet/guard/claude_managed_agents/` may import the Anthropic SDK
(`anthropic`). `claude_managed_agents` must not import
`arcjet.guard.claude_agent_sdk`.

## Coding conventions

### Python style

1. **Future imports**: Always use `from __future__ import annotations`.

2. **Python version**: >=3.10. Do not use features from 3.11+ (e.g.
   `typing.Self`, `ExceptionGroup`).

3. **Type hints**: Fully type-annotated codebase.
   - Use modern type syntax (e.g., `list[str]` not `List[str]`).
   - Use `Union` instead of `X | Y` in runtime-evaluated type aliases (the
     latter works in annotations with `from __future__ import annotations`
     but not in runtime-evaluated positions on 3.10).

4. **Dataclasses**: Prefer `@dataclass(frozen=True, slots=True)` for immutable
   data structures.

5. **Enums**: Use `str, Enum` pattern for string enums:
   ```python
   class Mode(str, Enum):
       DRY_RUN = "DRY_RUN"
       LIVE = "LIVE"
   ```

6. **Private modules**: Prefix with underscore (e.g., `_enums.py`,
   `_logging.py`) for internal-only modules.

### Framework support

The SDK is **framework-agnostic** with explicit support for ASGI (Starlette,
FastAPI), Flask/Werkzeug, and Django. The `src/arcjet/_context.py` module
provides `coerce_request_context()` to convert framework requests to a common
`RequestContext` type.

Note the name collision: `src/arcjet/guard/_context.py` is unrelated. It holds
Guard's ambient correlation context (`arcjet_sequence` and the `ContextVar` it
sets), not request coercion.

### Environment variables

- `ARCJET_KEY` — API key (passed to `arcjet()` or `arcjet_sync()`)
- `ARCJET_ENV` — Set to `"development"` for development mode
- `ARCJET_LOG_LEVEL` — Log level (`debug`, `info`, `warning`, `error`)
- `ARCJET_BASE_URL` — Override Decide API endpoint
- `FLY_APP_NAME` — Automatically detected; uses internal Fly.io Arcjet API URL

## WASM component integration

### SDK integration

Local WASM evaluation is wired into the main SDK at `src/arcjet/_local.py`:

- **Lazy singleton:** `_get_component()` loads the WASM binary once, latches on
  permanent errors, retries on transient errors. Protected by `_component_lock`.
- **Bot detection:** `evaluate_bot_locally()` runs `detect-bot` and returns a
  proto `RuleResult`.
- **Email validation:** `evaluate_email_locally()` runs `is-valid-email` and
  maps blocked reasons to proto `EmailType` values.
- **Client integration:** `_run_local_rules()` in `client.py` runs bot/email
  rules locally before the remote Decide API call; short-circuits on DENY in
  LIVE mode.
- **Reporting:** Fire-and-forget `ReportRequest` sent on local DENY so
  decisions appear in the Arcjet dashboard.

### Thread safety

`AnalyzeComponentBase` uses a per-instance `threading.Lock` around `_call()`.
The lock provides defensive safety at negligible cost (WASM calls are 1–5ms).
`AnalyzeComponent` (in `_overrides.py`) extends this with per-call callback
swapping under the same lock, and wraps construction, calls, and `close()` in
`wasmtime_section()` so wasmtime-py's process-global function slab cannot be
re-entered by a `__del__` finalizer (arcjet-py#154).

For detailed wasmtime-py reference (linker setup, type mapping, known bugs),
see [docs/WASMTIME.md](docs/WASMTIME.md).

## Key design patterns

### 1. Dual client pattern

- `arcjet()` / `Arcjet` — Async client for FastAPI, async frameworks
- `arcjet_sync()` / `ArcjetSync` — Sync client for Flask, Django

### 2. Decision-based API

The `.protect()` method returns a `Decision` object with:
- `decision.is_denied()` — Simple allow/deny check
- `decision.reason_v2` — Detailed reason for the decision
- `decision.ip` — IP analysis helpers (`.is_vpn()`, `.is_hosting()`, etc.)
- `decision.results` — Per-rule results

## Known limitations

- **Local evaluation timing not captured:** Remote Decide logs timing metrics;
  local decisions do not.
- **No caching of local decisions:** Remote decisions use `DecisionCache`;
  local DENY decisions bypass it entirely.
- **WASM binary sync:** The `.component.wasm` file is copied from
  `arcjet/arcjet-analyze` manually. After updating, regenerate bindings with
  `uv run python -m tools.witgen`.

## Summary checklist for new changes

Before submitting a PR:
- [ ] Run `just pre-commit`, which formats the code, runs all lint, type, and
      API-break checks, then runs all tests
- [ ] Add `breaking` label if introducing intentional API breaking changes
- [ ] Ensure all new code is fully type-annotated and follows coding conventions
- [ ] Add new tests to aim for 80%+ coverage (current threshold)
