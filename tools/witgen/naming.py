"""Naming conventions: kebab-case ↔ snake_case / PascalCase."""

from __future__ import annotations


def kebab_to_snake(name: str) -> str:
    """Convert kebab-case to snake_case."""
    return name.replace("-", "_")


def kebab_to_pascal(name: str) -> str:
    """Convert kebab-case to PascalCase."""
    return "".join(part.capitalize() for part in name.split("-"))


def variant_case_class_name(variant_name: str, case_name: str) -> str:
    """Build the Python class name for a variant case.

    E.g., variant_case_class_name("sensitive-info-entity", "email")
    → "SensitiveInfoEntityEmail"
    """
    return kebab_to_pascal(variant_name) + kebab_to_pascal(case_name)
