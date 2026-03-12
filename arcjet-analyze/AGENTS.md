# arcjet-analyze

This directory contains the WASM component integration for the Arcjet Python
SDK. It hosts pre-built WebAssembly components and the Python wrapper code that
drives them via wasmtime-py.

## Project conventions

- **Package manager:** `uv`. Always use `uv run` to execute scripts, tests, and
  tools (e.g. `uv run python3 script.py`, `uv run pytest`).
- **Python version:** >=3.10. Do not use features from 3.11+ (e.g. `typing.Self`,
  `ExceptionGroup`). Use `from __future__ import annotations` for forward
  references.
- **Typing:** All code must be fully typed. The repo enforces both Pyright
  (`pythonVersion = "3.10"`) and ty. Use frozen dataclasses with `slots=True`
  for value types. Use `Union` instead of `X | Y` in type aliases (the latter
  works in annotations with `from __future__ import annotations` but not in
  runtime-evaluated positions on 3.10).
- **Linting/formatting:** Ruff. Run `uv run ruff check .` and
  `uv run ruff format .` before committing.
- **CI checks:** `ruff check`, `ruff format --diff`, `ty check`, `pyright`,
  `griffe check`, `pytest`, `pytest tests/mocked`.

## Directory layout

```
arcjet-analyze/
├── filter.wit                            # WIT interface definition (filter subset)
├── arcjet_analyze/                       # Typed host-side bindings package
│   ├── __init__.py                       # Public API re-exports
│   ├── _types.py                         # Frozen dataclasses for all WIT types
│   ├── _convert.py                       # wasmtime Record/Variant <-> Python
│   ├── _imports.py                       # Import wiring with defaults + callbacks
│   ├── _component.py                     # AnalyzeComponent with 6 typed methods
│   └── wasm/                             # WASM binary (included in wheel)
│       └── arcjet_analyze_js_req.component.wasm
├── tests/                                # Tests for all exports + imports
└── bindings/                             # componentize-py generated (guest-side, reference only)
```

## WIT interface

The component implements the `arcjet:filter` package with a `filter` world:

```wit
package arcjet:filter;

interface filter-overrides {
  ip-lookup: func(ip: string) -> option<string>;
}

world filter {
  import filter-overrides;

  record filter-result {
    allowed: bool,
    matched-expressions: list<string>,
    undetermined-expressions: list<string>,
  }

  export match-filters: func(
    request: string,
    expressions: list<string>,
    allow-if-match: bool,
  ) -> result<filter-result, string>;
}
```

The full component (`arcjet_analyze_js_req.component.wasm`) also exports
`detect-bot`, `generate-fingerprint`, `validate-characteristics`,
`is-valid-email`, and `detect-sensitive-info` — plus corresponding import
interfaces for each. The `filter.wit` only describes the filter subset.

## State of Python tooling for WASM component bindings

There is **no working automated tool** to generate Python host-side bindings for
wasmtime-py as of v40. Here is what exists, what was tried, and why none of it
works for our use case:

### wasmtime.bindgen (removed)

`wasmtime-py` v27 shipped `python3 -m wasmtime.bindgen <component.wasm>
--out-dir <dir>` which generated typed Python host bindings from a compiled
component. It was **removed in v40** because it never supported WIT resources
and had no viable path to implement WASI P3 async. The replacement is the raw C
API for components (supports resources, no codegen).

Tracked at: https://github.com/bytecodealliance/wasmtime-py/issues/309

Even when tested against this project's component using v27, it panicked with
`not implemented` at `bindgen.rs:165:39` — likely due to unsupported variant
types.

### wit-bindgen (no Python host generator)

`wit-bindgen` once had a Python host generator (`gen-host-wasmtime-py`) but it
was folded into wasmtime-py and then removed along with `wasmtime.bindgen`.
There is no Python host target in `wit-bindgen` today.

Tracked at: https://github.com/bytecodealliance/wit-bindgen/issues/314

### componentize-py (guest-side only)

`componentize-py` (v0.21.0) generates Python bindings for **implementing** a
component (guest-side), not for **calling** one (host-side). Install with
`uv tool install componentize-py`.

```sh
componentize-py -d filter.wit -w filter bindings ./bindings
```

This generates useful type definitions (`FilterResult` dataclass, `Ok`/`Err`
types, function signatures) that serve as a reference for writing host-side
types. However, the generated code uses `typing.Self` (Python 3.11+), so it
**cannot be directly imported** in this project (targets 3.10).

### What we do instead

Hand-write a typed bindings package (`arcjet_analyze/`) that:
- Defines frozen dataclasses for all ~15 WIT types (no 3.11+ dependency)
- Uses the raw wasmtime-py component model API (`Engine`, `Store`, `Linker`,
  `Component`)
- Hides all linker boilerplate behind an `AnalyzeComponent` class with 6 typed
  export methods and 5 import interfaces with safe defaults

When tooling improves, this can be replaced with generated bindings (see
GENERATOR-NOTE comments in the source files).

## Running tests

```sh
uv run pytest arcjet-analyze/tests/ --no-cov
```

## wasmtime-py component model cookbook

### Object lifetimes and reusability

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

### Linker setup — the correct incantation

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

### Three pitfalls and their solutions

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

### Host-provided function signature

Functions passed to `add_func` receive the `Store` as an implicit first
argument. Wrap user callbacks to hide this:

```python
def _ip_lookup(_store: Store, ip: str) -> str | None:
    return user_callback(ip)  # user callback doesn't see _store
```

### Result type mapping

wasmtime-py v40 maps `result<T, E>` without `Ok`/`Err` wrappers:

| WIT result variant | Python type                              | Detection              |
|--------------------|------------------------------------------|------------------------|
| `Ok(record)`       | `wasmtime.component._types.Record`       | `not isinstance(r, E)` |
| `Err(string)`      | Plain `str`                              | `isinstance(r, str)`   |

### Record field access — kebab-case

Record attributes use **kebab-case** names matching the WIT definition:

```python
result.allowed                                     # works (single word)
getattr(result, "matched-expressions")             # required for kebab-case
getattr(result, "undetermined-expressions")        # required for kebab-case
```

### Component introspection

To discover a component's imports and exports at runtime:

```python
ct = component.type  # property, not method
imports = ct.imports(engine)   # Dict[str, ComponentInstanceType]
exports = ct.exports(engine)   # Dict[str, FuncType | ...]

for name, inst_type in imports.items():
    for func_name, func_type in inst_type.exports(engine).items():
        print(func_type.params, func_type.result)
```

### Variant type mapping (validated by spike)

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

### Known wasmtime-py v40 bugs and workarounds

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

### Import callback gotchas

**`sensitive_info_detect` must return `[None] * len(tokens)`, not `[]`.** The
WIT signature is `detect(tokens) → list<option<sensitive-info-entity>>` — the
returned list must have the same length as the input token list. Each element is
either `None` (no detection) or a `SensitiveInfoEntity`. Returning an empty list
causes the WASM component to panic.

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

### Full bindings package

The `arcjet_analyze` package provides typed Python bindings for all 6 exports
and 5 import interfaces:

```
arcjet_analyze/
├── __init__.py      # Public API re-exports
├── _types.py        # Frozen dataclasses for all WIT types
├── _convert.py      # wasmtime Record/Variant <-> Python dataclass
├── _imports.py      # Import wiring with defaults + user callbacks
└── _component.py    # AnalyzeComponent class with 6 typed methods
```

Usage:
```python
from arcjet_analyze import AnalyzeComponent, AllowedBotConfig, Ok
ac = AnalyzeComponent("path/to/arcjet_analyze_js_req.component.wasm")
result = ac.detect_bot(request_json, AllowedBotConfig(entities=[], skip_custom_detect=False))
```

## Plan: Full Python bindings for the WASM component

### Background

The JavaScript SDK (`arcjet-js/analyze-wasm`) uses jco to auto-generate bindings
from the same WASM components built in `arcjet/arcjet-analyze`. jco produces
~997 lines of low-level marshalling code that manually manages linear memory,
UTF-8 encode/decode, variant discriminants, and array layout.

Python does **not** need to replicate this. wasmtime-py v40 operates at the
Component Model level — it loads `.component.wasm` directly and handles all
Canonical ABI marshalling automatically. The existing `filter_component.py`
proves this pattern for `match-filters`. The task is to extend that pattern to
all 6 exported functions and all 5 import interfaces.

### Reference material

| Resource | Location | Purpose |
|---|---|---|
| WIT definitions (full) | `arcjet/arcjet-analyze/bindings_js_req/wit/js-req.wit` | Canonical source of types and function signatures |
| jco JS bindings | `arcjet-js/analyze-wasm/wasm/arcjet_analyze_js_req.component.js` | Reference for type shapes, calling conventions, result handling |
| jco TS type defs | `arcjet-js/analyze-wasm/wasm/arcjet_analyze_js_req.component.d.ts` | Concise view of all types and interfaces |
| JS SDK wrapper | `arcjet-js/analyze/index.ts` | How the JS SDK consumes the bindings (default imports, public API) |
| Python prototype | `filter_component.py` | Working example of the pattern for one function |
| componentize-py output | `bindings/wit_world/__init__.py` | Guest-side generated types (useful as type reference) |

### Architecture

```
arcjet_analyze/
├── __init__.py      # Public API re-exports
├── _types.py        # Frozen dataclasses for all WIT types
├── _convert.py      # wasmtime Record/Variant <-> Python dataclass
├── _imports.py      # Import wiring with defaults + user callbacks
└── _component.py    # AnalyzeComponent with 6 typed methods
```

A single `AnalyzeComponent` class wraps the full
`arcjet_analyze_js_req.component.wasm` and exposes all 6 exports as typed
Python methods. Each method creates a fresh `Store` + instance per call.

### Completed work

- **Phase 0:** Variant discovery spike (wasmtime-py v40 type mapping)
- **Phase 1:** Tests for all 6 exports + import callbacks (31 tests)
- **Phase 2:** `_types.py` — frozen dataclasses for all ~15 WIT types
- **Phase 3:** `_convert.py` — wasmtime Record/Variant ↔ Python dataclass
- **Phase 4:** `_imports.py` — 5 import interfaces wired with defaults + callbacks
- **Phase 5:** `_component.py` — `AnalyzeComponent` with 6 typed methods
- **Phase 6: Packaging** — `arcjet-analyze/pyproject.toml` created; WASM binary
  moved inside the package at `arcjet_analyze/wasm/` so hatchling includes it
  in the wheel automatically. `arcjet-analyze` is a required dependency of the
  main `arcjet` package via `[tool.uv.sources]` path reference.
- **Phase 7: SDK integration** — Local WASM evaluation wired into the main SDK:
  - `src/arcjet/_local.py`: lazy singleton for `AnalyzeComponent`, request
    serialization, `evaluate_bot_locally()` and `evaluate_email_locally()`
  - `src/arcjet/client.py`: `_run_local_rules()` runs bot/email rules locally
    before the remote Decide API call; short-circuits on DENY in LIVE mode
  - Fire-and-forget `ReportRequest` sent on local DENY so decisions appear in
    the Arcjet dashboard (mirrors the cache-hit report pattern)
  - 25 tests in `tests/test_local.py` covering serialization, singleton,
    bot/email evaluation, `_run_local_rules`, and report building

### Known limitations

- **`skip_custom_detect` hardcoded to `False`:** The WASM component's
  `AllowedBotConfig`/`DeniedBotConfig` accept a `skip_custom_detect` flag, but
  `BotDetection` in the SDK has no corresponding field. This means custom bot
  detection cannot be skipped via SDK configuration. To fix: add
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
- **Merge coordination with PR #60:** PR #60 (quinn/extract-shared-client-helpers)
  refactors `client.py` to extract shared helpers from `Arcjet`/`ArcjetSync`.
  Both PRs modify the same `protect()` methods. Whoever merges second will need
  to rebase and integrate the local evaluation wiring into the refactored helper
  structure.

### Remaining work

- **Code generator (witgen):** Build the Approach B code generator to replace
  hand-written bindings. The existing test suite becomes the acceptance suite —
  generated code must pass all tests unchanged.
- **WASM binary sync:** The `.component.wasm` file is copied from
  `arcjet/arcjet-analyze`. There is no automated sync — the binary must be
  manually updated when the Rust source changes.
