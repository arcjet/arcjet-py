"""Generate _component.py content."""

from __future__ import annotations

from ..config import Config
from ..ir import (
    WitFunc,
    WitRecord,
    WitRef,
    WitTypeDef,
    WitVariant,
    WitWorld,
)
from ..naming import kebab_to_snake
from .helpers import (
    GENERATED_HEADER,
    _build_type_map,
    _collect_annotation_type_refs,
    _py_type_annotation,
    _record_has_variant_fields,
)


def generate_component(world: WitWorld, config: Config) -> str:
    """Generate _component.py content."""
    type_map = _build_type_map(world)
    class_name = config.component_class
    lines: list[str] = [GENERATED_HEADER]
    lines.append("from __future__ import annotations\n")
    lines.append("import threading")
    lines.append("from typing import Any\n")
    lines.append("from wasmtime import Engine, Store")
    lines.append("from wasmtime import component as cm\n")

    # Collect imports needed
    convert_imports = _collect_convert_imports(world, type_map)
    type_imports_for_component = _collect_component_type_imports(world, type_map)

    lines.append("from ._convert import (")
    for name in sorted(convert_imports, key=str.casefold):
        lines.append(f"    {name},")
    lines.append(")")

    lines.append("from ._imports import ImportCallbacks, wire_imports")

    lines.append("from ._types import (")
    for name in sorted(type_imports_for_component, key=str.casefold):
        lines.append(f"    {name},")
    lines.append(")\n")

    # Class definition
    lines.append("")
    lines.append(f"class {class_name}:")
    lines.append(
        '    """Reusable wrapper around the full arcjet-analyze WASM component."""\n'
    )

    # __init__
    lines.append("    def __init__(")
    lines.append("        self,")
    lines.append("        wasm_path: str,")
    lines.append("        callbacks: ImportCallbacks | None = None,")
    lines.append("    ) -> None:")
    lines.append("        self._engine = Engine()")
    lines.append(
        "        self._component = cm.Component.from_file(self._engine, wasm_path)"
    )
    lines.append("        self._linker = cm.Linker(self._engine)")
    lines.append("        self._linker.allow_shadowing = True")
    lines.append("")
    lines.append("        wire_imports(self._linker, self._component, callbacks)")
    lines.append("")
    lines.append(
        "        # Lock for thread safety: wasmtime-py wrappers have unprotected"
    )
    lines.append(
        "        # mutable state (Slab globals, attribute reads). A per-instance"
    )
    lines.append(
        "        # lock around _call() provides defensive safety at negligible"
    )
    lines.append("        # cost (WASM calls are 1-5ms).")
    lines.append("        self._call_lock = threading.Lock()")
    lines.append("        self._closed = False")

    # _call
    lines.append("")
    lines.append("    def _call(self, export_name: str, *args: Any) -> Any:")
    lines.append('        """Call a named export with a fresh Store."""')
    lines.append("        if self._closed:")
    lines.append('            raise RuntimeError("AnalyzeComponent is closed")')
    lines.append("        with self._call_lock:")
    lines.append("            store = Store(self._engine)")
    lines.append(
        "            instance = self._linker.instantiate(store, self._component)"
    )
    lines.append("            func = instance.get_func(store, export_name)")
    lines.append("            if func is None:")
    lines.append(
        '                raise RuntimeError(f"{export_name} export not found in component")'
    )
    lines.append("            return func(store, *args)")

    # close + context manager
    lines.append("")
    lines.append("    def close(self) -> None:")
    lines.append('        """Release WASM engine resources."""')
    lines.append("        self._closed = True")
    lines.append("")
    lines.append(f"    def __enter__(self) -> {class_name}:")
    lines.append('        """Support use as a context manager."""')
    lines.append("        return self")
    lines.append("")
    lines.append("    def __exit__(self, *args: Any) -> None:")
    lines.append('        """Close on context manager exit."""')
    lines.append("        self.close()")

    # Export methods
    for export in world.exports:
        lines.append("")
        lines.extend(_gen_export_method(export, type_map))

    lines.append("")
    return "\n".join(lines)


def _gen_export_method(export: WitFunc, type_map: dict[str, WitTypeDef]) -> list[str]:
    """Generate a method for a single export."""
    method_name = kebab_to_snake(export.name)
    lines: list[str] = []

    # Build parameter list
    params: list[str] = ["self"]
    for p in export.params:
        py_name = kebab_to_snake(p.name)
        py_type = _py_type_annotation(p.type, type_map)
        params.append(f"{py_name}: {py_type}")

    # Return type
    if export.result is not None:
        ret_type = _py_type_annotation(export.result, type_map)
    else:
        ret_type = "None"

    # Method signature
    param_str = ",\n        ".join(params)
    lines.append(f"    def {method_name}(")
    lines.append(f"        {param_str},")
    lines.append(f"    ) -> {ret_type}:")
    lines.append(f'        """Run ``{export.name}`` on the component."""')

    # Build call arguments
    call_args: list[str] = []
    for p in export.params:
        py_name = kebab_to_snake(p.name)
        if isinstance(p.type, WitRef):
            defn = type_map.get(p.type.name)
            if isinstance(defn, WitVariant):
                converter = f"to_wasm_{kebab_to_snake(p.type.name)}"
                call_args.append(f"{converter}({py_name})")
                continue
            elif isinstance(defn, WitRecord) and _record_has_variant_fields(
                defn, type_map
            ):
                converter = f"to_wasm_{kebab_to_snake(p.type.name)}"
                call_args.append(f"{converter}({py_name})")
                continue
        call_args.append(py_name)

    args_str = ", ".join(call_args)

    # Generate call + conversion
    if export.result is not None:
        converter_name = f"from_wasm_{method_name}"
        lines.append(f'        raw = self._call("{export.name}", {args_str})')
        lines.append(f"        return {converter_name}(raw)")
    else:
        lines.append(f'        self._call("{export.name}", {args_str})')

    return lines


def _collect_convert_imports(
    world: WitWorld, type_map: dict[str, WitTypeDef]
) -> set[str]:
    """Collect from_wasm/to_wasm function names needed in _component.py."""
    names: set[str] = set()
    for export in world.exports:
        method_name = kebab_to_snake(export.name)
        names.add(f"from_wasm_{method_name}")
        for p in export.params:
            if isinstance(p.type, WitRef):
                defn = type_map.get(p.type.name)
                if isinstance(defn, WitVariant):
                    names.add(f"to_wasm_{kebab_to_snake(p.type.name)}")
                elif isinstance(defn, WitRecord) and _record_has_variant_fields(
                    defn, type_map
                ):
                    names.add(f"to_wasm_{kebab_to_snake(p.type.name)}")
    return names


def _collect_component_type_imports(
    world: WitWorld, type_map: dict[str, WitTypeDef]
) -> set[str]:
    """Collect type names needed in _component.py.

    Uses shallow collection -- only the names that appear directly in
    method signatures, not the inner members of union/variant types.
    """
    names: set[str] = set()
    for export in world.exports:
        # Return type
        if export.result is not None:
            _collect_annotation_type_refs(export.result, type_map, names)
        # Param types
        for p in export.params:
            _collect_annotation_type_refs(p.type, type_map, names)
    return names
