"""Code generation: IR -> Python source files (split into submodules)."""

from __future__ import annotations

from .component import generate_component
from .convert import generate_convert
from .helpers import init_field_overrides
from .imports import generate_imports
from .init import generate_init
from .types import generate_types

__all__ = [
    "generate_component",
    "generate_convert",
    "generate_imports",
    "generate_init",
    "generate_types",
    "init_field_overrides",
]
