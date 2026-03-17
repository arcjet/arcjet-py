# wasmtime-py component model cookbook

Reference guide for working with wasmtime-py v40 in the `arcjet._analyze` subpackage.
For binding generation, see [WITGEN.md](WITGEN.md).

## Object lifetimes and reusability

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

## Linker setup — the correct incantation

```python
from wasmtime import Engine, Store
from wasmtime import component as cm

engine = Engine()
component = cm.Component.from_file(engine, "path/to/component.wasm")
linker = cm.Linker(engine)
linker.allow_shadowing = True

# 1. Define traps for all imports (including functions inside instances)
linker.define_unknown_imports_as_traps(component)

# 2. Shadow the specific import(s) you need with real implementations
with linker.root() as root:
    with root.add_instance("arcjet:js-req/filter-overrides") as iface:
        iface.add_func("ip-lookup", my_ip_lookup)

# 3. Each call: fresh Store + instantiate
store = Store(engine)
instance = linker.instantiate(store, component)
func = instance.get_func(store, "match-filters")
result = func(store, request_json, local_fields_json, expressions, allow_if_match)
```

## Three pitfalls and their solutions

**1. LinkerInstance locking.** `linker.root()` and `add_instance()` return
`Managed` objects that lock the linker. If not closed before calling
`define_unknown_imports_as_traps` or `instantiate`, you get:
`WasmtimeError: cannot use linker while it's in use by other instances`.
Always use `with` context managers.

**2. `define_unknown_imports_as_traps` overwrites functions inside instances.**
The Rust implementation skips top-level items that are already defined, but
always recurses into component instances — defining traps for every function
inside them, even if you already wired real implementations. If you define your
real functions first, the traps overwrite them. Without `allow_shadowing`,
defining the same import twice raises:
`WasmtimeError: map entry '...' defined twice`.
**Fix:** Set `linker.allow_shadowing = True`, call traps FIRST, then override.

**3. Import namespace shape.** WIT imports use a flattened
`package:namespace/interface` string, not a nested hierarchy.
Use `root.add_instance("arcjet:js-req/filter-overrides")` — not nested
`root.add_instance("arcjet:js-req")` → `pkg.add_instance("filter-overrides")`.

## Host-provided function signature

Functions passed to `add_func` receive the `Store` as an implicit first
argument. Wrap user callbacks to hide this:

```python
def _ip_lookup(_store: Store, ip: str) -> str | None:
    return user_callback(ip)  # user callback doesn't see _store
```

## Result type mapping

wasmtime-py v40 maps `result<T, E>` without `Ok`/`Err` wrappers:

| WIT result variant | Python type                              | Detection              |
|--------------------|------------------------------------------|------------------------|
| `Ok(record)`       | `wasmtime.component._types.Record`       | `not isinstance(r, E)` |
| `Err(string)`      | Plain `str`                              | `isinstance(r, str)`   |

## Record field access — kebab-case

Record attributes use **kebab-case** names matching the WIT definition:

```python
result.allowed                                     # works (single word)
getattr(result, "matched-expressions")             # required for kebab-case
getattr(result, "undetermined-expressions")        # required for kebab-case
```

## Variant type mapping (validated by spike)

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

## Known wasmtime-py v40 bugs and workarounds

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

## Import callback gotchas

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

## Benchmarks

WASM performance benchmarks live in `tests/benchmarks/` and use
`pytest-benchmark`. They measure cold-start costs, per-call overhead, and
end-to-end `protect()` latency to catch performance regressions in the WASM
integration layer. They are **not** collected during normal test runs (benchmark
files use `bench_*.py` naming, and `python_files = ["test_*.py"]` in config).

```bash
# Run all benchmarks (table output)
make bench

# Or directly with options
uv run pytest tests/benchmarks/ --benchmark-only --benchmark-warmup=on --no-cov -v
```

**Important**: Always pass `--no-cov` — coverage instrumentation distorts
timing. The `--benchmark-warmup=on` flag lets pytest-benchmark's warmup phase
run before measurement, giving wasmtime-py time to settle its execution
profile. pytest-benchmark auto-calibrates round counts to get stable results.

### Benchmark structure

```
tests/benchmarks/
├── conftest.py              # Session fixtures: component, configs, contexts, mocked client
├── bench_wasm_init.py       # Cold-start cost (AnalyzeComponent creation)
├── bench_wasm_per_call.py   # Per-call Store+instantiate+invoke for each WASM export
├── bench_protect.py         # Full protect() path comparison (baseline vs WASM)
├── bench_local_evaluators.py # evaluate_bot_locally / evaluate_email_locally
└── bench_serialization.py   # Python-side JSON/proto serialization
```
