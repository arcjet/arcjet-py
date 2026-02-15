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
├── arcjet_analyze_js_req.component.wasm  # Full WASM component (instantiate this)
├── arcjet_analyze_js_req.component.core.wasm
├── arcjet_analyze_bindings_filter.wasm
├── filter.wit                            # WIT interface definition
├── filter_component.py                   # Typed host-side wrapper
├── hacky-wasmtime-filter-rule.py         # Original prototype (reference only)
└── bindings/                             # componentize-py generated (guest-side)
    ├── componentize_py_types.py
    └── wit_world/
        ├── __init__.py                   # FilterResult, WitWorld protocol
        └── imports/filter_overrides.py   # ip_lookup stub
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

Hand-write a small typed wrapper (`filter_component.py`) that:
- Defines `FilterResult`, `Ok`, `Err`, `Result` locally (no 3.11+ dependency)
- Uses the raw wasmtime-py component model API (`Engine`, `Store`, `Linker`,
  `Component`)
- Hides all linker boilerplate behind a `FilterComponent` class

When tooling improves, this can be replaced with generated bindings.

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
├── component.py          # AnalyzeComponent class (Engine, Component, Linker setup)
├── types.py              # Python dataclasses for all WIT types
├── imports.py            # Default import implementations
└── __init__.py           # Public API: init + per-function helpers
```

A single `AnalyzeComponent` class wraps the full
`arcjet_analyze_js_req.component.wasm` and exposes all 6 exports as typed
Python methods. Each method creates a fresh `Store` + instance per call (same
pattern as `FilterComponent`).

### Todos

#### Phase 1: Discover variant/complex type representation (estimate: 0.5 days)

The prototype only passes simple types (strings, lists of strings, bools).
Before writing real bindings, we need to determine how wasmtime-py v40
represents WIT variants, enums, options, and nested records for both **input
arguments** and **return values**.

- [ ] Write a throwaway script that calls `detect-bot` with a minimal
  `BotConfig` variant. Try passing Python dicts (`{"tag": "allowed-bot-config",
  "val": {...}}`), tuples, and `wasmtime.component` types to discover what
  wasmtime-py accepts as a variant input.
- [ ] Write a throwaway script that calls `is-valid-email` to test enum inputs
  and option types.
- [ ] Write a throwaway script that calls `detect-sensitive-info` to test nested
  variant inputs (`SensitiveInfoEntities` containing
  `list<SensitiveInfoEntity>`).
- [ ] Test how wasmtime-py represents enum return values (e.g.,
  `EmailValidity`: `"valid"` / `"invalid"` — string? int? object?).
- [ ] Test how wasmtime-py represents variant return values within records
  (e.g., `DetectedSensitiveInfoEntity.identified-type` which is a
  `SensitiveInfoEntity` variant).
- [ ] Document findings in this file under a new "### Variant type mapping"
  section in the cookbook.

#### Phase 2: Define Python types (estimate: 0.5 days)

Hand-write Python dataclasses for all WIT types used by the 6 exported
functions. Use frozen dataclasses with `slots=True` per project conventions.

- [ ] Define result types: `Ok[T]`, `Err[E]`, `Result` (already exists in
  `filter_component.py` — extract and generalize).
- [ ] Define `FilterResult` (already exists — extract).
- [ ] Define `BotResult` with fields: `allowed: list[str]`,
  `denied: list[str]`, `verified: bool`, `spoofed: bool`.
- [ ] Define `BotConfig` as a tagged union: `AllowedBotConfig` /
  `DeniedBotConfig`, each with `entities: list[str]`,
  `skip_custom_detect: bool`.
- [ ] Define `EmailValidationResult` with fields: `validity: EmailValidity`,
  `blocked: list[str]`.
- [ ] Define `EmailValidity` enum: `valid`, `invalid`.
- [ ] Define `EmailValidationConfig` as a tagged union:
  `AllowEmailValidationConfig` / `DenyEmailValidationConfig`, each with
  `require_top_level_domain: bool`, `allow_domain_literal: bool`,
  `allow: list[str]` or `deny: list[str]`.
- [ ] Define `SensitiveInfoEntity` as a tagged union: `email`, `phone-number`,
  `ip-address`, `credit-card-number`, `custom(str)`.
- [ ] Define `SensitiveInfoEntities` as a tagged union: `allow` / `deny`, each
  containing `list[SensitiveInfoEntity]`.
- [ ] Define `SensitiveInfoConfig` with fields: `entities`,
  `context_window_size: int | None`, `skip_custom_detect: bool`.
- [ ] Define `DetectedSensitiveInfoEntity` with fields: `start: int`,
  `end: int`, `identified_type: SensitiveInfoEntity`.
- [ ] Define `SensitiveInfoResult` with fields:
  `allowed: list[DetectedSensitiveInfoEntity]`,
  `denied: list[DetectedSensitiveInfoEntity]`.
- [ ] Define `ValidatorResponse` enum: `yes`, `no`, `unknown` (used by import
  interfaces).
- [ ] Ensure all types pass Pyright and ty checks.

#### Phase 3: Implement import interfaces (estimate: 0.5 days)

Define the 5 import namespaces that the WASM component requires. Each needs a
default (no-op) implementation and the ability to accept user-provided
callbacks.

- [ ] `arcjet:js-req/filter-overrides` — `ip-lookup(ip) -> option<string>`.
  Default: return `None`. (Already implemented in prototype.)
- [ ] `arcjet:js-req/bot-identifier` — `detect(request) -> list<bot-entity>`.
  Default: return `[]`.
- [ ] `arcjet:js-req/verify-bot` — `verify(bot-id, ip) -> validator-response`.
  Default: return `"unverifiable"`. Need to confirm wasmtime-py accepts string
  enums or requires integer discriminants.
- [ ] `arcjet:js-req/email-validator-overrides` — 4 functions:
  `is-free-email(domain)`, `is-disposable-email(domain)`,
  `has-mx-records(domain)`, `has-gravatar(email)`, each returning
  `validator-response`. Default: return `"unknown"`.
- [ ] `arcjet:js-req/sensitive-information-identifier` —
  `detect(tokens) -> list<option<sensitive-info-entity>>`. Default: return list
  of `None`. Need to confirm how wasmtime-py represents `option<variant>` in
  return values from host functions.
- [ ] Wire all 5 namespaces into the linker, using the trap-then-shadow pattern.

#### Phase 4: Implement the AnalyzeComponent wrapper (estimate: 1 day)

Extend the `FilterComponent` pattern to cover all 6 exports with proper type
conversion between wasmtime-py Record objects and Python dataclasses.

- [ ] Extract shared `Engine`/`Component`/`Linker` setup into `AnalyzeComponent`
  constructor, accepting optional callbacks for each import interface.
- [ ] Implement `match_filters(request, local_fields, expressions,
  allow_if_match) -> Result[FilterResult, str]`. Note: the full component's
  `match-filters` takes an extra `local-fields: string` parameter compared to
  the filter-only component.
- [ ] Implement `detect_bot(request, options) -> BotResult`. Must convert
  `BotConfig` Python dataclass to wasmtime-py variant input and convert
  Record output to `BotResult` dataclass.
- [ ] Implement `generate_fingerprint(request, characteristics) -> str`. Simple
  types, just handle `result<string, string>`.
- [ ] Implement `validate_characteristics(request, characteristics) -> None`.
  Handle `result<_, string>`, raise on error.
- [ ] Implement `is_valid_email(candidate, options) -> EmailValidationResult`.
  Must convert `EmailValidationConfig` variant input and handle
  `EmailValidity` enum in output.
- [ ] Implement `detect_sensitive_info(content, options) ->
  SensitiveInfoResult`. Most complex: nested variant inputs and outputs.
- [ ] Add a `_convert_record` helper to handle kebab-case → snake_case field
  mapping generically (or per-type converters if a generic approach is too
  fragile).
- [ ] Add a `_to_wasm_variant` helper (or per-type converters) to convert Python
  dataclasses to whatever wasmtime-py accepts as variant input.

#### Phase 5: Tests (estimate: 0.5 days)

- [ ] Test `match_filters` Ok and Err paths (port from prototype's `__main__`).
- [ ] Test `detect_bot` with allowed-bot-config and denied-bot-config variants.
- [ ] Test `generate_fingerprint` with valid and invalid characteristics.
- [ ] Test `validate_characteristics` success and error cases.
- [ ] Test `is_valid_email` with allow and deny configs.
- [ ] Test `detect_sensitive_info` with allow/deny entity lists and custom
  entities.
- [ ] Test that user-provided import callbacks are invoked (e.g., custom
  `ip_lookup`, custom `bot-identifier.detect`).
- [ ] Test that the component can be called multiple times (fresh Store per
  call).
- [ ] Ensure all tests run with `uv run pytest`.

#### Phase 6: Integration with arcjet-py SDK (estimate: 0.5 days)

- [ ] Create a public module API (e.g., `from arcjet_analyze import
  AnalyzeComponent`) with proper `__init__.py` exports.
- [ ] Wire the `AnalyzeComponent` into the existing arcjet-py SDK's rule
  evaluation pipeline, replacing or augmenting the remote Decide API calls
  with local WASM evaluation where appropriate.
- [ ] Ensure the WASM binary is bundled correctly in the package (check
  `pyproject.toml` package data).
- [ ] Run full CI checks: `ruff check`, `ruff format`, `ty check`, `pyright`,
  `pytest`.

### Estimate summary

| Phase | Description | Estimate |
|---|---|---|
| 1 | Discover variant/complex type representation | 0.5 days |
| 2 | Define Python types | 0.5 days |
| 3 | Implement import interfaces | 0.5 days |
| 4 | Implement AnalyzeComponent wrapper | 1 day |
| 5 | Tests | 0.5 days |
| 6 | Integration with arcjet-py SDK | 0.5 days |
| **Total** | | **3.5 days** |

Phase 1 is the highest-risk item. If wasmtime-py's variant representation is
straightforward (e.g., dicts or tuples), the rest is mechanical. If it requires
undocumented API usage or has bugs with complex types, phase 1 could expand to
1-2 days and may require reading wasmtime-py source code or filing issues
upstream.

### Key risks

1. **wasmtime-py variant input representation is undocumented.** The prototype
   only passes simple types. Complex variant inputs (BotConfig,
   EmailValidationConfig, SensitiveInfoConfig) may require a representation
   that can only be discovered by experimentation or reading wasmtime-py
   internals.

2. **`define_unknown_imports_as_traps` is brittle.** If any trapped import is
   actually called at runtime (because the default no-op wasn't wired up
   correctly), the component will abort with a wasm trap. This will manifest
   as confusing runtime errors.

3. **Kebab-case field access.** Every Record field with a hyphen requires
   `getattr(record, "field-name")`. A systematic conversion layer is needed
   to avoid this leaking into the public API.

4. **Store-per-call overhead.** Creating a fresh Store + instance for every
   function call has overhead. For hot paths, this may need optimization
   (e.g., pooling, or waiting for wasmtime-py to fix Store reuse).

5. **WASM binary versioning.** The `.component.wasm` file is copied from
   `arcjet/arcjet-analyze`. There is no automated sync — the binary must be
   manually updated when the Rust source changes.
