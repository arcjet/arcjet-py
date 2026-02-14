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
