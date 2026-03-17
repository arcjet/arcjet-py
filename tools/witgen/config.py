"""Load witgen.toml configuration."""

from __future__ import annotations

try:
    import tomllib  # pyright: ignore[reportMissingImports]  # ty: ignore[unresolved-import]
except ModuleNotFoundError:
    import tomli as tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Config:
    wasm_path: str
    output_dir: str
    field_overrides: dict[str, str] = field(default_factory=dict)
    component_class: str = "AnalyzeComponent"
    overrides_module: str | None = None
    singleton_module: str | None = None
    import_callback_names: dict[str, str] = field(default_factory=dict)


def load_config(path: str | Path = "witgen.toml") -> Config:
    """Load configuration from a TOML file."""
    with open(path, "rb") as f:
        raw = tomllib.load(f)

    witgen = raw.get("witgen", {})
    return Config(
        wasm_path=witgen["wasm_path"],
        output_dir=witgen["output_dir"],
        field_overrides=raw.get("field_overrides", {}),
        component_class=witgen.get("component_class", "AnalyzeComponent"),
        overrides_module=witgen.get("overrides_module"),
        singleton_module=witgen.get("singleton_module"),
        import_callback_names=raw.get("import_callback_names", {}),
    )
