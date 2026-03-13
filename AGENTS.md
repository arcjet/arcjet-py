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
make test        # SDK tests (unit + integration, with coverage)
make test-analyze  # arcjet-analyze WASM binding tests
make test-all    # Both test suites
```

Individual checks can still be run directly:

```bash
uv run ruff check            # Lint
uv run ty check              # ty type checker
uv run pyright               # Pyright type checker
uv run griffe check arcjet -s src --against origin/main  # API breaking changes
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
all tests to run together without cross-contamination. The `tests/unit/`
directory contains unit tests with mocked dependencies, while
`tests/fastapi/`, `tests/flask/`, etc. contain integration tests. See
`tests/TESTING_PATTERNS.md` for detailed testing conventions.

**Coverage**: Both test suites enforce an 80% minimum coverage threshold
(`fail_under = 80` in `pyproject.toml`). Generated code (protobuf and witgen
output) is excluded from coverage via `[tool.coverage.run] omit`.

The `arcjet-analyze` package has its own test suite with separate coverage:

```bash
make test-analyze  # or:
uv run pytest arcjet-analyze/tests/ -o "addopts=-q --cov-report=term-missing" --cov=arcjet_analyze
```

### Benchmarks

WASM performance benchmarks live in `benchmarks/` and use `pytest-benchmark`.
They are **not** collected during normal test runs (separate `testpaths` and
`python_files` pattern).

```bash
# Run all benchmarks (table output)
uv run --group benchmarks pytest benchmarks/ --benchmark-only --benchmark-warmup=on --no-cov -v -o "python_files=bench_*.py test_*.py"

# Save results to JSON for comparison
uv run --group benchmarks pytest benchmarks/ --benchmark-only --benchmark-warmup=on --no-cov -o "python_files=bench_*.py test_*.py" --benchmark-json=benchmark-results.json

# Compare against a saved baseline
uv run --group benchmarks pytest benchmarks/ --benchmark-only --benchmark-warmup=on --no-cov -o "python_files=bench_*.py test_*.py" --benchmark-compare=benchmark-results.json
```

**Important**: Always pass `--no-cov` — coverage instrumentation distorts
timing. The `--benchmark-warmup=on` flag lets pytest-benchmark's warmup phase
run before measurement, giving wasmtime-py time to settle its execution
profile. pytest-benchmark auto-calibrates round counts to get stable results.

### Linting and formatting

The project uses multiple tools for code quality. The Ruff rules are configured
to match what GitHub's Python code quality checks enforce, so issues caught
locally will also be caught in CI:

```bash
# Import sorting and formatting with ruff
uv run ruff check --select I --fix  # Sort imports
uv run ruff format                  # Format code

# Linting
uv run ruff check                   # Check for lint errors
```

Ruff rules (configured in `pyproject.toml` under `[tool.ruff.lint]`):
- **F401** — Unused imports. Matches the GitHub Python code quality check.
  Use `# noqa: F401` for intentional re-exports (e.g., pytest fixture imports).
- **I** — Import sorting (isort-compatible).

Some files are excluded from linting (see `pyproject.toml` for exclusions,
including `examples/` and generated protobuf code in `src/arcjet/proto/`).

### Type checking

Two type checkers are used; both must pass:

```bash
uv run ty check      # ty type checker
uv run pyright       # Pyright type checker
```

Some test files are excluded from type checking (see `[tool.pyright]` and
`[tool.ty.src]` sections in `pyproject.toml`).

Suppression comments:
- `# type: ignore[error-code]` — Recognized by both pyright and ty. Use for
  intentional type violations (e.g., passing wrong type in negative tests).
- `# pyright: ignore[rule]` — Pyright-specific suppression.
- `# ty: ignore[rule]` — ty-specific suppression. Use for false positives
  unique to ty (e.g., conditional stdlib imports like `tomllib` on 3.10).

### API breaking change detection

```bash
# Check against main branch
uv run griffe check arcjet -s src --against origin/main

# Check against most recent tag (default)
uv run griffe check arcjet -s src
```

PRs with breaking changes must be labeled with `breaking` label to be merged.

**IMPORTANT**: Always run this check before committing changes. Breaking changes
must be avoided unless absolutely necessary. Whenever there is a breaking
change, existing code must not break — we must maintain backward compatibility
and provide clear migration paths. This can be docs, deprecation warnings, and
keeping the existing API surface intact with internal changes.

## Code organization

### Source structure

```
src/arcjet/
├── __init__.py          # Public API exports
├── client.py            # Main Arcjet client (async and sync)
├── decision.py          # Decision and result types
├── rules.py             # Rule definitions (bot detection, rate limiting, etc.)
├── context.py           # Request context utilities (framework-agnostic)
├── cache.py             # Decision caching
├── dataclasses.py       # Reason types and data structures
├── _enums.py            # Enums (Mode, etc.)
├── _errors.py           # Exception types
├── _logging.py          # Logging configuration
├── _convert.py          # Protobuf conversion utilities
└── proto/               # Generated protobuf code (DO NOT EDIT)
    └── decide/v1alpha1/
```

### WASM bindings (`arcjet-analyze/`)

The `arcjet-analyze` package contains the WASM component integration. It hosts
pre-built WebAssembly components and typed Python bindings generated by witgen
and driven via wasmtime-py.

```
arcjet-analyze/
├── arcjet_analyze/                       # Typed host-side bindings package
│   ├── __init__.py                       # Public API re-exports (GENERATED)
│   ├── _types.py                         # Frozen dataclasses for all WIT types (GENERATED)
│   ├── _convert.py                       # wasmtime Record/Variant ↔ Python (GENERATED)
│   ├── _imports.py                       # Import wiring with defaults + callbacks (GENERATED)
│   ├── _component.py                     # AnalyzeComponentBase with 6 typed methods (GENERATED)
│   ├── _overrides.py                     # AnalyzeComponent subclass with per-call callback override (NOT generated)
│   ├── _import_defaults.py               # Domain-specific default callbacks (NOT generated)
│   └── wasm/                             # WASM binary (included in wheel)
│       └── arcjet_analyze_js_req.component.wasm
├── tests/                                # Tests for all exports + imports
├── WITGEN.md                             # witgen architecture, config, and usage
└── pyproject.toml
```

The typed Python bindings (`_types.py`, `_convert.py`, `_component.py`,
`_imports.py`, `__init__.py`) are generated by `witgen` (`tools/witgen/`,
configured by `witgen.toml`). See **[arcjet-analyze/WITGEN.md](arcjet-analyze/WITGEN.md)**
for architecture, configuration, and usage.

### Code generation tool (`tools/witgen/`)

```
tools/witgen/
├── __main__.py          # CLI entry point: uv run python -m tools.witgen
├── config.py            # witgen.toml loader
├── wit_parser.py        # WIT text → IR parser
├── ir.py                # Intermediate representation types
├── naming.py            # Naming conventions (kebab→snake, etc.)
├── generate.py          # IR → Python source files
└── tests/               # Unit tests for witgen
```

### Test structure

```
tests/
├── conftest.py          # Shared fixtures for all tests
├── helpers.py           # Test utility functions
├── TESTING_PATTERNS.md  # Detailed testing conventions
├── fixtures/            # Pytest fixtures and test data
│   ├── protobuf_stubs.py  # Protobuf mocking fixtures
│   └── __init__.py
├── unit/                # Unit tests with mocked dependencies
│   ├── conftest.py      # Makes protobuf mocking autouse for unit tests
│   ├── test_client_async.py
│   ├── test_client_sync.py
│   └── test_*.py        # Other unit tests
├── fastapi/             # FastAPI integration tests
│   ├── test_fastapi.py
│   └── test_reason_v2.py
├── flask/               # Flask integration tests
│   └── test_flask.py
└── test_convert.py      # Conversion utility tests
```

### Benchmark structure

```
benchmarks/
├── conftest.py              # Session fixtures: component, configs, contexts, mocked client
├── bench_wasm_init.py       # Cold-start cost (AnalyzeComponent creation)
└── bench_wasm_per_call.py   # Per-call Store+instantiate+invoke for each WASM export
```

## Coding conventions

### Python style

1. **Future imports**: Always use `from __future__ import annotations` at the
   top of files for forward compatibility.

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

6. **Docstrings**: Module-level docstrings for public modules; class/function
   docstrings for public API.

7. **Private modules**: Prefix with underscore (e.g., `_enums.py`,
   `_logging.py`) for internal-only modules.

### Framework support

The SDK is **framework-agnostic** with explicit support for:

- **ASGI** (Starlette, FastAPI) — async client
- **Flask/Werkzeug** — sync client
- **Django** — via `RequestContext`

The `context.py` module provides `coerce_request_context()` to convert framework
requests to a common `RequestContext` type.

### Environment variables

- `ARCJET_KEY` — API key (passed to `arcjet()` or `arcjet_sync()`)
- `ARCJET_ENV` — Set to `"development"` for development mode (enables defaults
  like `127.0.0.1` for missing IPs)
- `ARCJET_LOG_LEVEL` — Log level (`debug`, `info`, `warning`, `error`)
- `ARCJET_BASE_URL` — Override Decide API endpoint (defaults to
  `https://decide.arcjet.com` or Fly.io internal URL)
- `FLY_APP_NAME` — Automatically detected; uses internal Fly.io Arcjet API URL
  when set

## WASM component integration

### Thread safety

`AnalyzeComponentBase` uses a per-instance `threading.Lock` around `_call()`.
While the Rust wasmtime types are `Send + Sync`, the Python wasmtime-py wrapper
has unprotected mutable state (Slab globals, attribute reads). The lock provides
defensive safety at negligible cost (WASM calls are 1–5ms). This is generated
by witgen — see `generate_component()` in `tools/witgen/generate.py`.
`AnalyzeComponent` (in `_overrides.py`) extends this with per-call callback
swapping under the same lock.

### wasmtime-py component model cookbook

#### Object lifetimes and reusability

| Object      | Reusable across calls? | Notes                                     |
|-------------|------------------------|-------------------------------------------|
| `Engine`    | Yes                    | Create once                               |
| `Component` | Yes                    | Load once from `.wasm` file               |
| `Linker`    | Yes                    | Configure once with imports                |
| `Store`     | **No**                 | Must create fresh for each function call   |
| `Instance`  | **No**                 | Tied to a Store; created per call          |

After calling a component function, the Store is spent. A second call produces
`WasmtimeError: wasm trap: cannot enter component instance`. Always create a
fresh `Store` + `linker.instantiate()` per invocation.

#### Linker setup — the correct incantation

```python
from wasmtime import Engine, Store
from wasmtime import component as cm

engine = Engine()
component = cm.Component.from_file(engine, "path/to/component.wasm")
linker = cm.Linker(engine)
linker.allow_shadowing = True

# 1. Trap ALL imports first
linker.define_unknown_imports_as_traps(component)

# 2. Override the specific import(s) you need (shadows the trap)
with linker.root() as root:
    with root.add_instance("arcjet:js-req/filter-overrides") as iface:
        iface.add_func("ip-lookup", my_ip_lookup)

# 3. Each call: fresh Store + instantiate
store = Store(engine)
instance = linker.instantiate(store, component)
func = instance.get_func(store, "match-filters")
result = func(store, request_json, expressions, allow_if_match)
```

#### Three pitfalls and their solutions

**1. LinkerInstance locking.** `linker.root()` and `add_instance()` return
`Managed` objects that lock the linker. If not closed before calling
`define_unknown_imports_as_traps` or `instantiate`, you get:
`WasmtimeError: cannot use linker while it's in use by other instances`.
Always use `with` context managers.

**2. `define_unknown_imports_as_traps` defines ALL imports.** Despite the name,
it defines traps for every import — not just missing ones. If you define your
real function first, the trap overwrites it. And without `allow_shadowing`,
defining the same import twice raises:
`WasmtimeError: map entry '...' defined twice`.
**Fix:** Set `linker.allow_shadowing = True`, call traps FIRST, then override.

**3. Import namespace shape.** WIT imports use a flattened
`package:namespace/interface` string, not a nested hierarchy.
Use `root.add_instance("arcjet:js-req/filter-overrides")` — not nested
`root.add_instance("arcjet:js-req")` → `pkg.add_instance("filter-overrides")`.

#### Host-provided function signature

Functions passed to `add_func` receive the `Store` as an implicit first
argument. Wrap user callbacks to hide this:

```python
def _ip_lookup(_store: Store, ip: str) -> str | None:
    return user_callback(ip)  # user callback doesn't see _store
```

#### Result type mapping

wasmtime-py v40 maps `result<T, E>` without `Ok`/`Err` wrappers:

| WIT result variant | Python type                              | Detection              |
|--------------------|------------------------------------------|------------------------|
| `Ok(record)`       | `wasmtime.component._types.Record`       | `not isinstance(r, E)` |
| `Err(string)`      | Plain `str`                              | `isinstance(r, str)`   |

#### Record field access — kebab-case

Record attributes use **kebab-case** names matching the WIT definition:

```python
result.allowed                                     # works (single word)
getattr(result, "matched-expressions")             # required for kebab-case
getattr(result, "undetermined-expressions")        # required for kebab-case
```

#### Variant type mapping (validated by spike)

How wasmtime-py v40 represents WIT types at runtime:

| WIT type | Python input | Python output | Tagged? |
|----------|-------------|---------------|---------|
| `variant { a(R1), b(R2) }` (both Records) | `Variant("a", Record(...))` | `Variant(tag, payload)` | Yes (overlapping types) |
| `variant { email, custom(string) }` (unit+payload) | `Variant("email")` / `Variant("custom", "x")` | `Variant(tag, payload)` | Yes |
| `variant { allow(list<T>), deny(list<T>) }` | `Variant("allow", [...])` | `Variant(tag, payload)` | Yes (both are list) |
| `enum { valid, invalid }` | `"valid"` (plain str) | `"valid"` (plain str) | N/A |
| `record { field-a: T }` | `Record()` with `__dict__["field-a"]` | Record with kebab attrs | N/A |
| `result<record, string>` | N/A (output) | Record for Ok, `str` for Err | No (different types) |
| `result<string, string>` | N/A (output) | `Variant("ok", str)` / `Variant("err", str)` | Yes (same type) |
| `result<_, string>` | N/A (output) | `None` for Ok, `str` for Err | No |
| `option<T>` | `None` / value | `None` / value | No (None ≠ value) |

**Key rule:** A variant is "tagged" if any two cases have overlapping Python
types (determined by `VariantLikeType._tagged()`). Tagged variants require
`Variant(tag="...", payload=...)` wrapping. Untagged variants pass the raw
value directly.

#### Known wasmtime-py v40 bugs and workarounds

All workarounds are marked with `FIXME(wasmtime-py)` in the source. Reassess
each one when upgrading wasmtime-py.

**1. Private API dependency.** `Record`, `Variant`, `VariantType`,
`VariantLikeType`, `OptionType`, and `ResultType` are only available from
`wasmtime.component._types` — there is no public import path in v40. Both
`_convert.py` and `_imports.py` depend on this private module.

**2. `VariantType.add_classes` MRO bug.** `VariantType`'s MRO is
`VariantType → … → ValType → VariantLikeType`. `ValType` defines `add_classes`
as an abstract no-op (`pass`), which shadows the real implementation on
`VariantLikeType`. This causes `option<variant>` and `result<variant, …>` return
types from import callbacks to fail with *"value not valid for this variant"*
when any non-`None` value is returned. The fix in `_imports.py` monkey-patches
`VariantType`, `OptionType`, and `ResultType` to point directly at
`VariantLikeType.add_classes`. This is guarded with `try/except` so it degrades
gracefully if wasmtime-py restructures these classes.

**3. No public `Record` constructor.** wasmtime-py v40's `Record` class has no
constructor that accepts initial field values. The only way to build a Record
with data is `Record()` followed by `__dict__` mutation. The `_rec()` helper in
`_convert.py` encapsulates this.

#### Import callback gotchas

**`sensitive_info_detect` must return `[None] * len(tokens)`, not `[]`.** The
WIT signature is `detect(tokens) → list<option<sensitive-info-entity>>` — the
returned list must have the same length as the input token list. Each element is
either `None` (no detection) or a `SensitiveInfoEntity`. Returning a
wrong-length list raises a `ValueError` (generated wrappers validate this).

**`ip_lookup` returns a JSON string, not a plain value.** When providing country
enrichment, the callback must return `json.dumps({"country": "US"})`, not just
`"US"`. Returning a non-JSON string causes silent failures in filter expressions
that reference `ip.src.country`.

**`bot_verify` is conditionally invoked.** The WASM component only calls the
`verify` import when it determines a bot is potentially verifiable (based on IP
ranges and bot identity). For most test IPs and common bots (curl, Googlebot
with non-Google IPs), the callback is never reached. Do not write tests that
assert the callback was invoked — instead verify the wiring doesn't crash and
test the `verified`/`spoofed` result fields.

## Key design patterns

### 1. Dual client pattern

The SDK provides both async and sync clients for different frameworks:
- `arcjet()` / `Arcjet` — Async client for FastAPI, async frameworks
- `arcjet_sync()` / `ArcjetSync` — Sync client for Flask, Django

### 2. Framework-agnostic context

`RequestContext` provides a normalized request representation that works across
frameworks. The `coerce_request_context()` function handles conversion from
framework-specific request objects.

### 3. Decision-based API

The `.protect()` method returns a `Decision` object with:
- `decision.is_denied()` — Simple allow/deny check
- `decision.reason_v2` — Detailed reason for the decision
- `decision.ip` — IP analysis helpers (`.is_vpn()`, `.is_hosting()`, etc.)
- `decision.results` — Per-rule results

### 4. Protobuf code generation

The `src/arcjet/proto/` directory contains **generated code**. Do not edit these
files directly. They are generated from protobuf definitions maintained
elsewhere.

## Common errors and workarounds

### 1. uv command not found

**Error**: `bash: uv: command not found`

**Solution**: Install uv first:
```bash
pip install uv
```

### 2. Breaking change CI failure

**Error**: Griffe check fails on PR due to API breaking changes.

**Cause**: Public API changes detected that would break existing users.

**Solutions**:
- Revert the breaking change if unintentional.
- If intentional, add `breaking` label to the PR to allow it to pass CI. Always
  strive to avoid breaking changes and maintain backward compatibility for
  existing APIs. Provide clear migration paths if breaking changes are
  necessary.

### 3. Type check failures

**Error**: Pyright or ty reports type errors.

**Cause**: Missing type annotations or incorrect types.

**Solution**:
- Fix type annotations to match actual usage.
- Use `# type: ignore[error-code]` sparingly and only when necessary.

## Known limitations

- **`skip_custom_detect` hardcoded to `False`:** The WASM component's
  `AllowedBotConfig`/`DeniedBotConfig` accept a `skip_custom_detect` flag, but
  `BotDetection` in the SDK has no corresponding field. To fix: add
  `skip_custom_detect: bool = False` to `BotDetection` and wire it through
  `evaluate_bot_locally`.
- **Local evaluation timing not captured:** The remote Decide path logs
  `prepare_ms`, `api_ms`, and `total_ms`. Local decisions log only the
  conclusion. Adding timing would require passing `t0` into the local evaluation
  path.
- **No caching of local decisions:** Remote decisions are cached by
  `DecisionCache` based on TTL. Local DENY decisions bypass the cache entirely —
  repeat requests re-run WASM evaluation. Whether local decisions should be
  cached (and with what TTL) is a design decision.
- **WASM binary sync:** The `.component.wasm` file is copied from
  `arcjet/arcjet-analyze`. There is no automated sync — the binary must be
  manually updated when the Rust source changes. After updating the binary,
  regenerate bindings with `uv run python -m tools.witgen`.

## Summary checklist for new changes

Before submitting a PR:
- [ ] Run `make format` to fix imports and format code
- [ ] Run `make check` to run all lint, type, and API-break checks
- [ ] Run `make test-all` to run both SDK and arcjet-analyze test suites
- [ ] Add `breaking` label if introducing intentional API breaking changes
- [ ] Update documentation, including docstrings and AGENTS.md if necessary
- [ ] Ensure all new code is fully type-annotated and follows coding conventions
- [ ] Add new tests to aim for 80%+ coverage (current threshold)
