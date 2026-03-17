"""Generate __init__.py content."""

from __future__ import annotations

from ..config import Config
from ..ir import (
    WitRecord,
    WitRef,
    WitVariant,
    WitWorld,
)
from ..naming import kebab_to_pascal, variant_case_class_name
from .helpers import (
    GENERATED_HEADER,
    _build_type_map,
    _variant_has_overlapping_record_cases,
)


def generate_init(world: WitWorld, config: Config) -> str:
    """Generate __init__.py content."""
    type_map = _build_type_map(world)
    lines: list[str] = [GENERATED_HEADER]
    lines.append("from ._imports import ImportCallbacks")
    if config.overrides_module:
        lines.append(f"from .{config.overrides_module} import AnalyzeComponent")
    else:
        lines.append("from ._component import AnalyzeComponent")
    if config.singleton_module:
        lines.append(
            f"from .{config.singleton_module} import get_component, reset_component"
        )

    # Collect all public type names
    all_names: list[str] = []
    all_names.extend(["Ok", "Err", "Result"])

    for typedef in world.types:
        if isinstance(typedef, WitRecord):
            all_names.append(kebab_to_pascal(typedef.name))
        elif isinstance(typedef, WitVariant):
            if _variant_has_overlapping_record_cases(typedef, type_map):
                all_names.append(kebab_to_pascal(typedef.name))
                for case in typedef.cases:
                    assert isinstance(case.payload, WitRef)
                    all_names.append(kebab_to_pascal(case.payload.name))
            else:
                all_names.append(kebab_to_pascal(typedef.name))
                for case in typedef.cases:
                    all_names.append(variant_case_class_name(typedef.name, case.name))
    # Import types (e.g., sensitive-info-entity variant)
    for imp in world.imports:
        for typedef in imp.types:
            if isinstance(typedef, WitVariant):
                all_names.append(kebab_to_pascal(typedef.name))
                for case in typedef.cases:
                    all_names.append(variant_case_class_name(typedef.name, case.name))

    # Generate import statement
    lines.append("from ._types import (")
    for name in sorted(set(all_names), key=str.casefold):
        lines.append(f"    {name},")
    lines.append(")\n")

    # __all__
    all_exports = ["AnalyzeComponent", "ImportCallbacks"] + sorted(set(all_names))
    if config.singleton_module:
        all_exports = [
            "AnalyzeComponent",
            "ImportCallbacks",
            "get_component",
            "reset_component",
        ] + sorted(set(all_names))
    lines.append("__all__ = [")
    for name in all_exports:
        lines.append(f'    "{name}",')
    lines.append("]")

    lines.append("")
    return "\n".join(lines)
