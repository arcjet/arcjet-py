"""Generate _types.py content."""

from __future__ import annotations

from ..ir import (
    WitEnum,
    WitRecord,
    WitRef,
    WitTypeAlias,
    WitTypeDef,
    WitVariant,
    WitWorld,
)
from ..naming import kebab_to_pascal, kebab_to_snake, variant_case_class_name
from .helpers import (
    GENERATED_HEADER,
    _build_type_map,
    _is_unit_variant_case,
    _py_type_annotation,
    _variant_has_overlapping_record_cases,
    _variant_payload_field_name,
)


def generate_types(world: WitWorld) -> str:
    """Generate _types.py content."""
    type_map = _build_type_map(world)
    lines: list[str] = [GENERATED_HEADER]
    lines.append("from __future__ import annotations\n")
    lines.append("from dataclasses import dataclass")
    lines.append("from typing import Generic, TypeVar, Union\n")
    lines.append('T = TypeVar("T")')
    lines.append('E = TypeVar("E")\n')

    # Result wrappers (always emitted)
    lines.append("")
    lines.append("")
    lines.append("@dataclass(frozen=True, slots=True)")
    lines.append("class Ok(Generic[T]):")
    lines.append('    """Wraps the success value from a WIT ``result<T, E>``."""\n')
    lines.append("    value: T\n")
    lines.append("")
    lines.append("@dataclass(frozen=True, slots=True)")
    lines.append("class Err(Generic[E]):")
    lines.append('    """Wraps the error value from a WIT ``result<T, E>``."""\n')
    lines.append("    value: E\n")
    lines.append("")
    lines.append("Result = Union[Ok[T], Err[E]]")

    # Collect all types to emit (world types + imported variant/record types)
    all_types = list(world.types)
    for imp in world.imports:
        for t in imp.types:
            # Only emit non-enum, non-alias types from imports
            if isinstance(t, (WitRecord, WitVariant)):
                all_types.append(t)

    for typedef in all_types:
        lines.append("")
        lines.append("")
        if isinstance(typedef, WitRecord):
            lines.extend(_gen_record(typedef, type_map))
        elif isinstance(typedef, WitVariant):
            lines.extend(_gen_variant(typedef, type_map))
        elif isinstance(typedef, WitEnum):
            lines.extend(_gen_enum(typedef))
        elif isinstance(typedef, WitTypeAlias):
            pass  # Expand inline, no Python type emitted

    lines.append("")
    return "\n".join(lines)


def _gen_record(record: WitRecord, type_map: dict[str, WitTypeDef]) -> list[str]:
    lines: list[str] = []
    cls_name = kebab_to_pascal(record.name)
    lines.append("@dataclass(frozen=True, slots=True)")
    lines.append(f"class {cls_name}:")
    lines.append(f'    """WIT ``{record.name}`` record."""\n')
    for field in record.fields:
        py_name = kebab_to_snake(field.name)
        py_type = _py_type_annotation(field.type, type_map)
        lines.append(f"    {py_name}: {py_type}")
    if not record.fields:
        lines.append("    pass")
    return lines


def _gen_variant(variant: WitVariant, type_map: dict[str, WitTypeDef]) -> list[str]:
    lines: list[str] = []

    # Check if this is a "record-reference" variant (all cases point to named records)
    if _variant_has_overlapping_record_cases(variant, type_map):
        # Emit as Union of the referenced record types
        case_types = []
        for case in variant.cases:
            assert isinstance(case.payload, WitRef)
            case_types.append(kebab_to_pascal(case.payload.name))
        union_name = kebab_to_pascal(variant.name)
        members = ", ".join(case_types)
        lines.append(f"{union_name} = Union[{members}]")
        return lines

    # Mixed variant: some unit cases, some payload cases
    case_classes: list[str] = []
    for case in variant.cases:
        cls_name = variant_case_class_name(variant.name, case.name)
        case_classes.append(cls_name)
        if _is_unit_variant_case(case):
            lines.append("@dataclass(frozen=True, slots=True)")
            lines.append(f"class {cls_name}:")
            lines.append(
                f'    """WIT ``{variant.name}::{case.name}`` (unit variant case)."""'
            )
            lines.append("")
            lines.append("")
        else:
            assert case.payload is not None
            # Determine field name from config override or default
            field_name = _variant_payload_field_name(
                variant.name, case.name, case.payload, type_map
            )
            py_type = _py_type_annotation(case.payload, type_map)
            lines.append("@dataclass(frozen=True, slots=True)")
            lines.append(f"class {cls_name}:")
            lines.append(f'    """WIT ``{variant.name}::{case.name}`` variant case."""')
            lines.append("")
            lines.append(f"    {field_name}: {py_type}")
            lines.append("")
            lines.append("")

    # Emit Union type alias
    union_name = kebab_to_pascal(variant.name)
    if len(case_classes) == 1:
        lines.append(f"{union_name} = {case_classes[0]}")
    else:
        members = ",\n    ".join(case_classes)
        lines.append(f"{union_name} = Union[")
        lines.append(f"    {members},")
        lines.append("]")
    return lines


def _gen_enum(enum: WitEnum) -> list[str]:
    lines: list[str] = []
    lines.append(f"# WIT enum ``{enum.name}``: {', '.join(enum.cases)}")
    lines.append(f"# Represented as plain str at runtime (no Python class needed).")
    return lines
