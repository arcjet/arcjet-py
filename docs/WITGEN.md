# witgen — WIT-to-Python code generator

`witgen` reads a WIT world extracted from a WASM component binary and generates
typed Python host-side bindings for wasmtime-py v40. It lives in `tools/witgen/`
and is configured by `witgen.toml` at the repo root.

## Why witgen exists

There is no working upstream tool to generate Python host-side bindings for
wasmtime-py v40:

- **wasmtime.bindgen** was removed in v40 (never supported WIT resources).
- **wit-bindgen** has no Python host target.
- **componentize-py** generates guest-side bindings only.

## Architecture

```
witgen.toml          ← configuration (paths, class names, field overrides)
tools/witgen/
├── __main__.py      ← CLI entry point
├── config.py        ← Config dataclass + TOML loader
├── wit_parser.py    ← WIT text → IR (WitWorld, WitInterface, etc.)
├── ir.py            ← Intermediate representation dataclasses
├── naming.py        ← kebab-to-snake/pascal naming helpers
└── generate.py      ← IR → Python source (5 output files)
```

### Generated files

| File             | Contents                                             |
|------------------|------------------------------------------------------|
| `_types.py`      | Frozen dataclasses for all WIT records/variants      |
| `_convert.py`    | `to_wasm_*` / `from_wasm_*` conversion functions     |
| `_imports.py`    | `ImportCallbacks` dataclass + `wire_imports()` function |
| `_component.py`  | `AnalyzeComponentBase` class with typed export methods |
| `__init__.py`    | Public API re-exports                                |

### Hand-maintained files

| File                  | Contents                                          |
|-----------------------|---------------------------------------------------|
| `_import_defaults.py` | Domain-specific default callbacks for imports     |
| `_overrides.py`       | `AnalyzeComponent(AnalyzeComponentBase)` subclass |

## Configuration (`witgen.toml`)

```toml
[witgen]
wasm_path = "src/arcjet/_analyze/wasm/arcjet_analyze_js_req.component.wasm"
output_dir = "src/arcjet/_analyze"
component_class = "AnalyzeComponentBase"   # class name in _component.py
overrides_module = "_overrides"            # module re-exporting AnalyzeComponent

[field_overrides]
# variant-name.case-name = "field_name"
"sensitive-info-entities.allow" = "entities"
"sensitive-info-entities.deny" = "entities"

[import_callback_names]
# interface-short-name.func-name = "callback_field_name"
"sensitive-information-identifier.detect" = "sensitive_info_detect"
"filter-overrides.ip-lookup" = "ip_lookup"
"bot-identifier.detect" = "bot_detect"
"verify-bot.verify" = "bot_verify"
```

### Key config fields

- **`component_class`**: Name of the generated class (default: `"AnalyzeComponent"`).
  Set to `"AnalyzeComponentBase"` when using an overrides module.
- **`overrides_module`**: If set, `__init__.py` imports `AnalyzeComponent` from
  this module instead of `_component`. This allows a hand-maintained subclass
  to extend the generated base.
- **`import_callback_names`**: Maps `interface-short-name.func-name` to a Python
  field name for the `ImportCallbacks` dataclass. Without this, the default is
  `kebab_to_snake(func.name)` which can be ambiguous when multiple interfaces
  have functions with the same name (e.g., both `bot-identifier` and
  `sensitive-information-identifier` have a `detect` function).
- **`field_overrides`**: Maps `variant-name.case-name` to a field name for
  variant case dataclasses (default is `"value"`).

## Usage

```sh
# Regenerate bindings:
uv run python -m tools.witgen
uv run ruff check --select I --fix && uv run ruff format

# Verify:
uv run pytest tests/analyze/ --no-cov -q
uv run pyright src/arcjet/_analyze/ tools/witgen/
```

## Design: generic generator + hand-maintained overrides

The generator is fully generic — it contains no arcjet-specific string literals.
All customization is driven by `witgen.toml`. The inheritance pattern is:

1. **`_component.py`** (generated): `AnalyzeComponentBase` with all export
   methods as plain pass-through calls.
2. **`_overrides.py`** (hand-maintained): `AnalyzeComponent(AnalyzeComponentBase)`
   adds the per-call callback override for `detect_sensitive_info` via linker
   shadowing (`allow_shadowing = True`).
3. **`__init__.py`** (generated): re-exports `AnalyzeComponent` from
   `_overrides`, so consumers see the enriched class.

### Import conversion wrappers

When an import function's return type contains a WIT variant, the generated
`wire_imports()` creates a named wrapper function that applies `to_wasm_*`
conversion. This replaces the previous special-case code for
`sensitive_info_detect` with a generic mechanism.
