"""Generate _convert.py content."""

from __future__ import annotations

from ..ir import (
    WitFunc,
    WitList,
    WitPrimitive,
    WitRecord,
    WitRef,
    WitResult,
    WitType,
    WitTypeDef,
    WitVariant,
    WitWorld,
)
from ..naming import kebab_to_pascal, kebab_to_snake, variant_case_class_name
from .helpers import (
    GENERATED_HEADER,
    _build_type_map,
    _is_unit_variant_case,
    _record_has_variant_fields,
    _record_needs_from_wasm,
    _resolve_type,
    _variant_has_overlapping_record_cases,
    _variant_payload_field_name,
)


def generate_convert(world: WitWorld) -> str:
    """Generate _convert.py content."""
    type_map = _build_type_map(world)
    lines: list[str] = [GENERATED_HEADER]
    lines.append("from __future__ import annotations\n")
    lines.append("from typing import Any\n")

    # FIXME comment and imports
    lines.append(
        "# FIXME(wasmtime-py): v40 does not export Record/Variant from a public path;"
    )
    lines.append(
        "# wasmtime.component._types is the only way to access them.  Revisit when"
    )
    lines.append("# wasmtime-py exposes a public API for component-model types.")
    lines.append("from wasmtime.component._types import Record, Variant\n")

    # Import types from _types
    type_imports = _collect_type_imports(world, type_map)
    if type_imports:
        lines.append("from ._types import (")
        for name in sorted(type_imports, key=str.casefold):
            lines.append(f"    {name},")
        lines.append(")\n")

    # _rec helper
    lines.append("")
    lines.append("def _rec(**kwargs: Any) -> Record:")
    lines.append('    """Build a wasmtime Record with kebab-case attributes."""')
    lines.append("    r = Record()")
    lines.append("    r.__dict__.update(kwargs)")
    lines.append("    return r")

    # Discover all types needing to_wasm/from_wasm converters
    to_wasm_needed: list[str] = []  # type names in dependency order
    from_wasm_needed: list[str] = []

    def _discover_to_wasm(ty: WitType, seen: set[str]) -> None:
        """Recursively find all types needing to_wasm converters."""
        if isinstance(ty, WitRef):
            if ty.name in seen:
                return
            defn = type_map.get(ty.name)
            if isinstance(defn, WitVariant):
                # First discover sub-types
                for case in defn.cases:
                    if case.payload is not None:
                        _discover_to_wasm(case.payload, seen)
                if ty.name not in seen:
                    seen.add(ty.name)
                    to_wasm_needed.append(ty.name)
            elif isinstance(defn, WitRecord):
                if _record_has_variant_fields(defn, type_map):
                    for f in defn.fields:
                        _discover_to_wasm(f.type, seen)
                    if ty.name not in seen:
                        seen.add(ty.name)
                        to_wasm_needed.append(ty.name)
        elif isinstance(ty, WitList):
            _discover_to_wasm(ty.element, seen)

    def _discover_from_wasm(ty: WitType, seen: set[str]) -> None:
        """Recursively find all types needing from_wasm converters."""
        if isinstance(ty, WitRef):
            if ty.name in seen:
                return
            defn = type_map.get(ty.name)
            if isinstance(defn, WitVariant):
                if not _variant_has_overlapping_record_cases(defn, type_map):
                    seen.add(ty.name)
                    from_wasm_needed.append(ty.name)
            elif isinstance(defn, WitRecord):
                if _record_needs_from_wasm(defn, type_map):
                    # First discover field types
                    for f in defn.fields:
                        _discover_from_wasm(f.type, seen)
                    if ty.name not in seen:
                        seen.add(ty.name)
                        from_wasm_needed.append(ty.name)
        elif isinstance(ty, WitList):
            _discover_from_wasm(ty.element, seen)
        elif isinstance(ty, WitResult):
            if ty.ok:
                _discover_from_wasm(ty.ok, seen)

    to_seen: set[str] = set()
    from_seen: set[str] = set()
    for export in world.exports:
        for param in export.params:
            _discover_to_wasm(param.type, to_seen)
        if export.result is not None:
            _discover_from_wasm(export.result, from_seen)

    # Generate to_wasm functions (dependency order)
    emitted: set[str] = set()
    for type_name in to_wasm_needed:
        defn = type_map[type_name]
        func_name = f"to_wasm_{kebab_to_snake(type_name)}"
        if func_name not in emitted:
            emitted.add(func_name)
            lines.append("")
            lines.append("")
            if isinstance(defn, WitVariant):
                lines.extend(_gen_to_wasm_variant(defn, type_map))
            elif isinstance(defn, WitRecord):
                lines.extend(_gen_to_wasm_record(defn, type_map))

    # Generate from_wasm functions for nested types (dependency order)
    for type_name in from_wasm_needed:
        defn = type_map[type_name]
        func_name = f"from_wasm_{kebab_to_snake(type_name)}"
        if func_name not in emitted:
            emitted.add(func_name)
            lines.append("")
            lines.append("")
            if isinstance(defn, WitVariant):
                lines.extend(_gen_from_wasm_variant(defn, type_map))
            elif isinstance(defn, WitRecord):
                lines.extend(_gen_from_wasm_standalone_record(defn, type_map))

    # Generate from_wasm functions for export results
    for export in world.exports:
        if export.result is not None:
            lines.append("")
            lines.append("")
            lines.extend(_gen_from_wasm_export(export, type_map))

    lines.append("")
    return "\n".join(lines)


def _collect_type_imports(world: WitWorld, type_map: dict[str, WitTypeDef]) -> set[str]:
    """Collect all Python type names needed in _convert.py."""
    names: set[str] = {"Ok", "Err", "Result"}
    for typedef in world.types:
        if isinstance(typedef, WitRecord):
            names.add(kebab_to_pascal(typedef.name))
        elif isinstance(typedef, WitVariant):
            if _variant_has_overlapping_record_cases(typedef, type_map):
                names.add(kebab_to_pascal(typedef.name))
                for case in typedef.cases:
                    assert isinstance(case.payload, WitRef)
                    names.add(kebab_to_pascal(case.payload.name))
            else:
                names.add(kebab_to_pascal(typedef.name))
                for case in typedef.cases:
                    cls = variant_case_class_name(typedef.name, case.name)
                    names.add(cls)
    for imp in world.imports:
        for typedef in imp.types:
            if isinstance(typedef, WitVariant):
                names.add(kebab_to_pascal(typedef.name))
                for case in typedef.cases:
                    cls = variant_case_class_name(typedef.name, case.name)
                    names.add(cls)
    return names


def _gen_to_wasm_variant(
    variant: WitVariant, type_map: dict[str, WitTypeDef]
) -> list[str]:
    """Generate to_wasm function for a variant type."""
    func_name = f"to_wasm_{kebab_to_snake(variant.name)}"
    py_type = kebab_to_pascal(variant.name)
    lines: list[str] = []

    # Check if this is a record-reference variant
    if _variant_has_overlapping_record_cases(variant, type_map):
        lines.append(f"def {func_name}(config: {py_type}) -> Variant:")
        lines.append(f'    """Convert {py_type} union to a wasmtime Variant."""')
        for i, case in enumerate(variant.cases):
            assert isinstance(case.payload, WitRef)
            record_def = type_map.get(case.payload.name)
            assert isinstance(record_def, WitRecord)
            cls = kebab_to_pascal(case.payload.name)
            prefix = "if" if i == 0 else "elif"
            lines.append(f"    {prefix} isinstance(config, {cls}):")
            lines.append(f"        return Variant(")
            lines.append(f'            "{case.name}",')
            lines.append(f"            {_gen_record_to_rec(record_def, 'config')},")
            lines.append(f"        )")
        lines.append(
            f'    raise TypeError(f"Expected {py_type}, got {{type(config).__name__}}")'
        )
        return lines

    # Mixed variant (unit + payload cases)
    lines.append(f"def {func_name}(entity: {py_type}) -> Variant:")
    lines.append(f'    """Convert a {py_type} to a wasmtime Variant."""')
    for case in variant.cases:
        cls = variant_case_class_name(variant.name, case.name)
        if _is_unit_variant_case(case):
            lines.append(f"    if isinstance(entity, {cls}):")
            lines.append(f'        return Variant("{case.name}")')
        else:
            assert case.payload is not None
            field_name = _variant_payload_field_name(
                variant.name, case.name, case.payload, type_map
            )
            # Check if the payload needs conversion
            value_expr = f"entity.{field_name}"
            value_expr = _gen_field_to_wasm(value_expr, case.payload, type_map)
            lines.append(f"    if isinstance(entity, {cls}):")
            lines.append(f'        return Variant("{case.name}", {value_expr})')
    # Fallback (should be unreachable)
    lines.append(f'    raise TypeError(f"Unknown {py_type}: {{type(entity)}}")')
    return lines


def _gen_field_to_wasm(
    expr: str,
    ty: WitType,
    type_map: dict[str, WitTypeDef],
) -> str:
    """Generate expression to convert a field to wasmtime format."""
    if isinstance(ty, WitRef):
        defn = type_map.get(ty.name)
        if isinstance(defn, WitVariant):
            converter = f"to_wasm_{kebab_to_snake(ty.name)}"
            return f"{converter}({expr})"
    elif isinstance(ty, WitList):
        if isinstance(ty.element, WitRef):
            defn = type_map.get(ty.element.name)
            if isinstance(defn, WitVariant):
                converter = f"to_wasm_{kebab_to_snake(ty.element.name)}"
                return f"[{converter}(e) for e in {expr}]"
    return expr


def _gen_from_wasm_variant(
    variant: WitVariant, type_map: dict[str, WitTypeDef]
) -> list[str]:
    """Generate from_wasm function for a variant with mixed cases."""
    func_name = f"from_wasm_{kebab_to_snake(variant.name)}"
    py_type = kebab_to_pascal(variant.name)
    lines: list[str] = []
    lines.append(f"def {func_name}(raw: Any) -> {py_type}:")
    lines.append(f'    """Convert a wasmtime Variant to {py_type}."""')
    lines.append("    if not isinstance(raw, Variant):")
    lines.append(
        f'        raise TypeError(f"expected Variant for {variant.name}, got {{type(raw)}}")'
    )
    lines.append("    tag = raw.tag")
    for case in variant.cases:
        cls = variant_case_class_name(variant.name, case.name)
        if _is_unit_variant_case(case):
            lines.append(f'    if tag == "{case.name}":')
            lines.append(f"        return {cls}()")
        else:
            assert case.payload is not None
            resolved_payload = _resolve_type(case.payload, type_map)
            if (
                isinstance(resolved_payload, WitPrimitive)
                and resolved_payload.name == "string"
            ):
                payload_expr = "str(raw.payload)"
            else:
                payload_expr = "raw.payload"
            lines.append(f'    if tag == "{case.name}":')
            lines.append(f"        return {cls}({payload_expr})")
    lines.append(f'    raise ValueError(f"Unknown {variant.name} tag: {{tag}}")')
    return lines


def _gen_from_wasm_standalone_record(
    record: WitRecord, type_map: dict[str, WitTypeDef]
) -> list[str]:
    """Generate from_wasm function for a standalone record."""
    func_name = f"from_wasm_{kebab_to_snake(record.name)}"
    cls = kebab_to_pascal(record.name)
    lines: list[str] = []
    lines.append(f"def {func_name}(raw: Any) -> {cls}:")
    lines.append(f'    """Convert a wasmtime Record to {cls}."""')
    lines.append(f"    return {cls}(")
    for field in record.fields:
        py_name = kebab_to_snake(field.name)
        kebab_name = field.name
        if "-" in kebab_name:
            accessor = f'getattr(raw, "{kebab_name}")'
        else:
            accessor = f"raw.{kebab_name}"
        value_expr = _gen_field_from_wasm(accessor, field.type, type_map)
        lines.append(f"        {py_name}={value_expr},")
    lines.append(f"    )")
    return lines


def _gen_record_to_rec(record: WitRecord, var: str) -> str:
    """Generate a _rec(...) call to convert a Python record to wasmtime Record."""
    parts: list[str] = []
    for field in record.fields:
        py_name = kebab_to_snake(field.name)
        kebab_name = field.name
        if "-" in kebab_name:
            parts.append(f'**{{"{kebab_name}": {var}.{py_name}}}')
        else:
            parts.append(f"{kebab_name}={var}.{py_name}")
    args = ", ".join(parts)
    return f"_rec({args})"


def _gen_to_wasm_record(
    record: WitRecord, type_map: dict[str, WitTypeDef]
) -> list[str]:
    """Generate to_wasm function for a record with variant fields."""
    func_name = f"to_wasm_{kebab_to_snake(record.name)}"
    py_type = kebab_to_pascal(record.name)
    lines: list[str] = []
    lines.append(f"def {func_name}(config: {py_type}) -> Record:")
    lines.append(f'    """Convert {py_type} to a wasmtime Record."""')
    lines.append(f"    return _rec(")
    for field in record.fields:
        py_name = kebab_to_snake(field.name)
        kebab_name = field.name
        resolved = _resolve_type(field.type, type_map)
        # Check if this field needs conversion
        value_expr = f"config.{py_name}"
        if isinstance(resolved, WitRef):
            defn = type_map.get(resolved.name)
            if isinstance(defn, WitVariant):
                converter = f"to_wasm_{kebab_to_snake(resolved.name)}"
                value_expr = f"{converter}({value_expr})"
        if "-" in kebab_name:
            lines.append(f'        **{{"{kebab_name}": {value_expr}}},')
        else:
            lines.append(f"        {kebab_name}={value_expr},")
    lines.append(f"    )")
    return lines


def _gen_from_wasm_export(
    export: WitFunc, type_map: dict[str, WitTypeDef]
) -> list[str]:
    """Generate from_wasm function for an export's result type."""
    func_name = f"from_wasm_{kebab_to_snake(export.name)}"
    result_type = export.result
    assert result_type is not None

    lines: list[str] = []

    if isinstance(result_type, WitResult):
        return _gen_from_wasm_result(func_name, export.name, result_type, type_map)
    elif isinstance(result_type, WitRef):
        # Direct record return (no result wrapper)
        defn = type_map.get(result_type.name)
        if isinstance(defn, WitRecord):
            return _gen_from_wasm_direct_record(func_name, export.name, defn, type_map)

    return lines


def _gen_from_wasm_result(
    func_name: str,
    export_name: str,
    result: WitResult,
    type_map: dict[str, WitTypeDef],
) -> list[str]:
    lines: list[str] = []
    ok_type = result.ok
    err_type = result.err

    # Determine dispatch strategy
    ok_is_record = False
    ok_is_string = False
    ok_is_none = ok_type is None
    err_is_string = isinstance(err_type, WitPrimitive) and err_type.name == "string"

    if ok_type is not None:
        resolved_ok = _resolve_type(ok_type, type_map)
        if isinstance(resolved_ok, WitRef):
            defn = type_map.get(resolved_ok.name)
            ok_is_record = isinstance(defn, WitRecord)
        elif isinstance(resolved_ok, WitPrimitive) and resolved_ok.name == "string":
            ok_is_string = True

    # Determine Python return type annotation
    if ok_is_none:
        ret_ann = "Result[None, str]"
    elif ok_is_string:
        ret_ann = "Result[str, str]"
    elif ok_is_record and isinstance(ok_type, WitRef):
        ret_ann = f"Result[{kebab_to_pascal(ok_type.name)}, str]"
    else:
        ret_ann = "Any"

    lines.append(f"def {func_name}(raw: Any) -> {ret_ann}:")
    lines.append(f'    """Convert {export_name} result."""')

    if ok_is_none and err_is_string:
        # result<_, string> -> untagged: None=Ok, str=Err
        lines.append("    if raw is None:")
        lines.append("        return Ok(None)")
        lines.append("    if not isinstance(raw, str):")
        lines.append(
            f'        raise TypeError(f"expected str error from {export_name}, got {{type(raw)}}")'
        )
        lines.append("    return Err(raw)")
    elif ok_is_string and err_is_string:
        # result<string, string> -> tagged: Variant("ok"/"err", str)
        lines.append("    if not isinstance(raw, Variant):")
        lines.append(
            f'        raise TypeError(f"expected Variant from {export_name}, got {{type(raw)}}")'
        )
        lines.append("    if not isinstance(raw.payload, str):")
        lines.append(
            f'        raise TypeError(f"expected str payload in {export_name} result, got {{type(raw.payload)}}")'
        )
        lines.append('    if raw.tag == "ok":')
        lines.append("        return Ok(raw.payload)")
        lines.append('    if raw.tag == "err":')
        lines.append("        return Err(raw.payload)")
        lines.append(
            f'    raise ValueError(f"Unknown {export_name} result tag: {{raw.tag}}")'
        )
    elif ok_is_record and err_is_string:
        # result<record, string> -> untagged: Record=Ok, str=Err
        assert isinstance(ok_type, WitRef)
        record_def = type_map.get(ok_type.name)
        assert isinstance(record_def, WitRecord)
        lines.append("    if isinstance(raw, str):")
        lines.append("        return Err(raw)")
        # Delegate to standalone converter if one exists for this record
        if _record_needs_from_wasm(record_def, type_map):
            converter = f"from_wasm_{kebab_to_snake(ok_type.name)}"
            lines.append(f"    return Ok({converter}(raw))")
        else:
            lines.append("    return Ok(")
            lines.extend(_gen_record_from_raw(record_def, type_map, indent=8))
            lines.append("    )")
    else:
        lines.append("    return raw  # TODO: unhandled result type")

    return lines


def _gen_record_from_raw(
    record: WitRecord,
    type_map: dict[str, WitTypeDef],
    indent: int = 8,
) -> list[str]:
    """Generate record construction from raw wasmtime value."""
    pad = " " * indent
    cls = kebab_to_pascal(record.name)
    lines: list[str] = []
    lines.append(f"{pad}{cls}(")
    for field in record.fields:
        py_name = kebab_to_snake(field.name)
        kebab_name = field.name
        # Access via getattr for multi-word, direct for single-word
        if "-" in kebab_name:
            accessor = f'getattr(raw, "{kebab_name}")'
        else:
            accessor = f"raw.{kebab_name}"

        value_expr = _gen_field_from_wasm(accessor, field.type, type_map)
        lines.append(f"{pad}    {py_name}={value_expr},")
    lines.append(f"{pad})")
    return lines


def _gen_field_from_wasm(
    accessor: str,
    ty: WitType,
    type_map: dict[str, WitTypeDef],
) -> str:
    """Generate expression to convert a field value from wasmtime."""
    if isinstance(ty, WitRef):
        defn = type_map.get(ty.name)
        if isinstance(defn, WitRecord):
            if _record_needs_from_wasm(defn, type_map):
                converter = f"from_wasm_{kebab_to_snake(ty.name)}"
                return f"{converter}({accessor})"
        elif isinstance(defn, WitVariant):
            converter = f"from_wasm_{kebab_to_snake(ty.name)}"
            return f"{converter}({accessor})"
    elif isinstance(ty, WitList):
        if isinstance(ty.element, WitRef):
            defn = type_map.get(ty.element.name)
            if isinstance(defn, WitRecord) and _record_needs_from_wasm(defn, type_map):
                converter = f"from_wasm_{kebab_to_snake(ty.element.name)}"
                return f"[{converter}(e) for e in {accessor}]"
    return accessor


def _gen_from_wasm_direct_record(
    func_name: str,
    export_name: str,
    record: WitRecord,
    type_map: dict[str, WitTypeDef],
) -> list[str]:
    """Generate from_wasm for a direct record return (no result wrapper)."""
    cls = kebab_to_pascal(record.name)
    standalone = f"from_wasm_{kebab_to_snake(record.name)}"
    lines: list[str] = []
    lines.append(f"def {func_name}(raw: Any) -> {cls}:")
    lines.append(f'    """Convert {export_name} result (direct Record)."""')
    # Delegate to standalone converter if one exists and has a different name
    if _record_needs_from_wasm(record, type_map) and standalone != func_name:
        lines.append(f"    return {standalone}(raw)")
    else:
        lines.append(f"    return {cls}(")
        for field in record.fields:
            py_name = kebab_to_snake(field.name)
            kebab_name = field.name
            if "-" in kebab_name:
                accessor = f'getattr(raw, "{kebab_name}")'
            else:
                accessor = f"raw.{kebab_name}"
            value_expr = _gen_field_from_wasm(accessor, field.type, type_map)
            lines.append(f"        {py_name}={value_expr},")
        lines.append(f"    )")
    return lines
