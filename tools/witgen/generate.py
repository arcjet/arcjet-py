"""Code generation: IR -> Python source files.

This module re-exports from the ``generators`` sub-package so that existing
call sites (e.g. ``from .generate import generate_types``) continue to work.
"""

from __future__ import annotations

from .generators import (
    generate_component,
    generate_convert,
    generate_imports,
    generate_init,
    generate_types,
    init_field_overrides,
)

__all__ = [
    "generate_component",
    "generate_convert",
    "generate_imports",
    "generate_init",
    "generate_types",
    "init_field_overrides",
]
