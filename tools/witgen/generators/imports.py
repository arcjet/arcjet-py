"""Generate _imports.py content."""

from __future__ import annotations

from ..config import Config
from ..ir import (
    WitFunc,
    WitList,
    WitOption,
    WitRef,
    WitType,
    WitTypeDef,
    WitVariant,
    WitWorld,
)
from ..naming import kebab_to_snake
from .helpers import (
    GENERATED_HEADER,
    _build_type_map,
    _collect_type_refs,
    _py_type_annotation,
    _resolve_type,
)


def generate_imports(world: WitWorld, config: Config) -> str:
    """Generate _imports.py content."""
    type_map = _build_type_map(world)
    lines: list[str] = [GENERATED_HEADER]
    lines.append("from __future__ import annotations\n")
    lines.append("from dataclasses import dataclass")
    lines.append("from typing import Callable\n")
    # Check if any import returns a variant (needing Variant type + conversion)
    converter_names: set[str] = set()
    for imp in world.imports:
        for func in imp.funcs:
            if func.result is not None:
                _collect_variant_converters(func.result, type_map, converter_names)
    needs_variant_wiring = len(converter_names) > 0

    if needs_variant_wiring:
        lines.append("from wasmtime import Store")
    lines.append("from wasmtime import component as cm\n")

    if needs_variant_wiring:
        # FIXME comment and imports
        lines.append(
            "# FIXME(wasmtime-py): v40 does not export these from a public path;"
        )
        lines.append(
            "# wasmtime.component._types is the only way to access them.  Revisit when"
        )
        lines.append("# wasmtime-py exposes a public API for component-model types.")
        lines.append("from wasmtime.component._types import (")
        lines.append("    OptionType,")
        lines.append("    ResultType,")
        lines.append("    VariantLikeType,")
        lines.append("    VariantType,")
        lines.append(")\n")

    # Import from _convert (generically collected converters)
    if converter_names:
        lines.append("from ._convert import (")
        for name in sorted(converter_names, key=str.casefold):
            lines.append(f"    {name},")
        lines.append(")")

    # Import from _types (generically collected type refs)
    type_names: set[str] = set()
    for imp in world.imports:
        for func in imp.funcs:
            for p in func.params:
                _collect_type_refs(p.type, type_map, type_names)
            if func.result is not None:
                _collect_type_refs(func.result, type_map, type_names)
    if type_names:
        lines.append("from ._types import (")
        for name in sorted(type_names, key=str.casefold):
            lines.append(f"    {name},")
        lines.append(")")
    lines.append("")

    if needs_variant_wiring:
        # MRO fix
        lines.append(
            "# FIXME(wasmtime-py): v40 MRO bug workaround — remove when fixed upstream."
        )
        lines.append("try:")
        lines.append("    _real_add_classes = VariantLikeType.add_classes")
        lines.append("    for _cls in (VariantType, OptionType, ResultType):")
        lines.append("        if _cls.add_classes is not _real_add_classes:")
        lines.append(
            "            _cls.add_classes = _real_add_classes  # type: ignore[assignment]"
        )
        lines.append("except (AttributeError, TypeError):")
        lines.append(
            "    pass  # Future wasmtime-py may fix this or restructure these classes"
        )

    # ImportCallbacks dataclass
    lines.append("")
    lines.append("")
    lines.append("@dataclass(frozen=True, slots=True)")
    lines.append("class ImportCallbacks:")
    lines.append('    """User-provided callbacks for component import interfaces."""\n')
    # Generate one field per import function
    for imp in world.imports:
        for func in imp.funcs:
            field_name = _import_callback_field_name(imp.name, func, config)
            cb_type = _import_callback_type(func, type_map)
            lines.append(f"    {field_name}: {cb_type} | None = None")

    # wire_imports
    lines.append("")
    lines.append("")
    lines.append("def wire_imports(")
    lines.append("    linker: cm.Linker,")
    lines.append("    component: cm.Component,")
    lines.append("    callbacks: ImportCallbacks | None = None,")
    lines.append(") -> None:")
    lines.append(
        '    """Wire all import interfaces into *linker* using trap-then-shadow."""'
    )
    lines.append("    cb = callbacks or ImportCallbacks()")
    lines.append("")
    lines.append("    # 1. Trap everything first")
    lines.append("    linker.define_unknown_imports_as_traps(component)")
    lines.append("")

    # Import default implementations
    default_names: list[str] = []
    for imp in world.imports:
        for func in imp.funcs:
            default_names.append(_import_default_func_name(imp.name, func, config))
    lines.append("    from ._import_defaults import (")
    for name in sorted(default_names, key=str.casefold):
        lines.append(f"        {name},")
    lines.append("    )\n")

    # Resolve callbacks with defaults
    for imp in world.imports:
        for func in imp.funcs:
            field_name = _import_callback_field_name(imp.name, func, config)
            default_name = _import_default_func_name(imp.name, func, config)
            local_name = f"{field_name}_fn"
            lines.append(f"    {local_name} = cb.{field_name} or {default_name}")
    lines.append("")

    # Wire imports
    lines.append("    # 2. Override with real implementations")
    lines.append("    with linker.root() as root:")
    for imp in world.imports:
        iface_name = imp.name
        lines.append(f'        with root.add_instance("{iface_name}") as iface:')
        for func in imp.funcs:
            field_name = _import_callback_field_name(imp.name, func, config)
            local_name = f"{field_name}_fn"
            wit_func_name = func.name

            # Check if this import needs a conversion wrapper
            conversion_expr = None
            if func.result is not None:
                conversion_expr = _gen_return_to_wasm_expr(
                    "results", func.result, type_map
                )

            if conversion_expr is not None:
                # Named wrapper for imports with variant return types
                wrapper_name = f"_wrap_{field_name}"
                typed_params = [
                    f"{kebab_to_snake(p.name)}: {_py_type_annotation(p.type, type_map)}"
                    for p in func.params
                ]
                param_names = [kebab_to_snake(p.name) for p in func.params]
                store_params = ", ".join(["_store: Store"] + typed_params)
                call_args = ", ".join(param_names)

                # Detect list->list pattern for length validation:
                # if return type is list and there's exactly one list param,
                # validate that the callback returns the expected number of
                # elements (a mismatch would cause a WASM trap).
                length_check_param: str | None = None
                assert func.result is not None  # guarded by outer `if`
                resolved_result = _resolve_type(func.result, type_map)
                if isinstance(resolved_result, WitList):
                    list_params = [
                        p
                        for p in func.params
                        if isinstance(_resolve_type(p.type, type_map), WitList)
                    ]
                    if len(list_params) == 1:
                        length_check_param = kebab_to_snake(list_params[0].name)

                lines.append("")
                lines.append(f"            def {wrapper_name}({store_params}):")
                lines.append(f"                results = {local_name}({call_args})")
                if length_check_param is not None:
                    lines.append(
                        f"                if len(results) != len({length_check_param}):"
                    )
                    lines.append(
                        f"                    raise ValueError("
                        f'"callback returned %d results, expected %d"'
                        f" % (len(results), len({length_check_param})))"
                    )
                lines.append(f"                return {conversion_expr}")
                lines.append("")
                lines.append(
                    f'            iface.add_func("{wit_func_name}", {wrapper_name})'
                )
            else:
                # Standard wiring with lambda
                param_count = len(func.params)
                if param_count == 1:
                    lines.append(
                        f"            iface.add_func("
                        f'"{wit_func_name}", '
                        f"lambda _store, a: {local_name}(a))"
                    )
                elif param_count == 2:
                    lines.append(
                        f"            iface.add_func("
                        f'"{wit_func_name}", '
                        f"lambda _store, a, b: {local_name}(a, b))"
                    )
                else:
                    lines.append(
                        f"            iface.add_func("
                        f'"{wit_func_name}", '
                        f"lambda _store, *args: {local_name}(*args))"
                    )

        lines.append("")

    lines.append("")
    return "\n".join(lines)


def _gen_return_to_wasm_expr(
    var: str, ty: WitType, type_map: dict[str, WitTypeDef]
) -> str | None:
    """Generate an expression to convert a callback return value to wasmtime format.

    Returns None if no conversion is needed.
    """
    if isinstance(ty, WitRef):
        defn = type_map.get(ty.name)
        if isinstance(defn, WitVariant):
            return f"to_wasm_{kebab_to_snake(ty.name)}({var})"
        return None
    if isinstance(ty, WitOption):
        inner = _gen_return_to_wasm_expr(var, ty.inner, type_map)
        if inner is not None:
            return f"None if {var} is None else {inner}"
        return None
    if isinstance(ty, WitList):
        inner = _gen_return_to_wasm_expr("_r", ty.element, type_map)
        if inner is not None:
            return f"[{inner} for _r in {var}]"
        return None
    return None


def _collect_variant_converters(
    ty: WitType, type_map: dict[str, WitTypeDef], names: set[str]
) -> None:
    """Recursively collect to_wasm_* converter names needed for a type."""
    if isinstance(ty, WitRef):
        defn = type_map.get(ty.name)
        if isinstance(defn, WitVariant):
            names.add(f"to_wasm_{kebab_to_snake(ty.name)}")
    elif isinstance(ty, WitOption):
        _collect_variant_converters(ty.inner, type_map, names)
    elif isinstance(ty, WitList):
        _collect_variant_converters(ty.element, type_map, names)


def _import_callback_field_name(iface_name: str, func: WitFunc, config: Config) -> str:
    """Generate the ImportCallbacks field name for an import function."""
    short_iface = iface_name.split("/")[-1] if "/" in iface_name else iface_name
    key = f"{short_iface}.{func.name}"
    if key in config.import_callback_names:
        return config.import_callback_names[key]
    return kebab_to_snake(func.name)


def _import_default_func_name(iface_name: str, func: WitFunc, config: Config) -> str:
    """Generate the default function name for an import function."""
    field = _import_callback_field_name(iface_name, func, config)
    return f"_default_{field}"


def _import_callback_type(
    func: WitFunc,
    type_map: dict[str, WitTypeDef],
) -> str:
    """Generate the Callable type annotation for an import callback."""
    param_types: list[str] = []
    for p in func.params:
        param_types.append(_py_type_annotation(p.type, type_map))

    # Return type
    if func.result is not None:
        ret = _py_type_annotation(func.result, type_map)
    else:
        ret = "None"

    params = ", ".join(param_types)
    return f"Callable[[{params}], {ret}]"
