# AGENTS.md — Coding Agent Onboarding Guide

This document provides essential information for coding agents working on the
arcjet-py repository for the first time.

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
3. **Install dependencies**:
   ```bash
   uv sync
   ```
   This creates a virtual environment in `.venv` and installs all dependencies
   from `uv.lock`.

### Development workflow

Always prefix commands with `uv run`. Common tasks are wrapped in the
`Makefile`:

```bash
make check       # All lint + type + API-break checks (single command)
make format      # Auto-fix imports and format code
make test        # All tests (unit + integration + analyze, with coverage)
make bench       # Run benchmarks
```

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

Both type checkers must pass. Some test files are excluded from type checking
(see `[tool.pyright]` and `[tool.ty.src]` in `pyproject.toml`).

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
  `client.py`, rules in `rules.py`, local WASM evaluation in `_local.py`.
  Protobuf code in `proto/` is **generated — do not edit**.
- `src/arcjet/_analyze/` — WASM component integration with typed Python bindings.
  See `docs/WITGEN.md` for binding generation and
  `docs/WASMTIME.md` for wasmtime-py details.
- `tools/witgen/` — WIT-to-Python code generator (configured by `witgen.toml`).
- `tests/` — Unit tests (`tests/unit/`), integration tests
  (`tests/fastapi/`, `tests/flask/`), WASM binding tests (`tests/analyze/`),
  and benchmarks (`tests/benchmarks/`). See `tests/TESTING_PATTERNS.md`.

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
FastAPI), Flask/Werkzeug, and Django. The `context.py` module provides
`coerce_request_context()` to convert framework requests to a common
`RequestContext` type.

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
swapping under the same lock.

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

- **`skip_custom_detect` hardcoded to `False`:** `BotDetection` has no
  corresponding field for the WASM component's config flag.
- **Local evaluation timing not captured:** Remote Decide logs timing metrics;
  local decisions do not.
- **No caching of local decisions:** Remote decisions use `DecisionCache`;
  local DENY decisions bypass it entirely.
- **WASM binary sync:** The `.component.wasm` file is copied from
  `arcjet/arcjet-analyze` manually. After updating, regenerate bindings with
  `uv run python -m tools.witgen`.

## Summary checklist for new changes

Before submitting a PR:
- [ ] Run `make format` to fix imports and format code
- [ ] Run `make check` to run all lint, type, and API-break checks
- [ ] Run `make test` to run all tests
- [ ] Add `breaking` label if introducing intentional API breaking changes
- [ ] Ensure all new code is fully type-annotated and follows coding conventions
- [ ] Add new tests to aim for 80%+ coverage (current threshold)
