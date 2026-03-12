"""CLI entry point: uv run python -m tools.witgen"""

from __future__ import annotations

import sys
from pathlib import Path

from .config import load_config
from .generate import (
    generate_component,
    generate_convert,
    generate_imports,
    generate_init,
    generate_types,
    init_field_overrides,
)
from .wit_parser import extract_wit, parse_wit


def main() -> None:
    config_path = "witgen.toml"
    if not Path(config_path).exists():
        print(f"Error: {config_path} not found", file=sys.stderr)
        sys.exit(1)

    config = load_config(config_path)
    init_field_overrides(config.field_overrides)

    print(f"Extracting WIT from {config.wasm_path}...")
    wit_text = extract_wit(config.wasm_path)

    print("Parsing WIT...")
    world, interfaces = parse_wit(wit_text)

    print(
        f"World: {world.name}, {len(world.exports)} exports, {len(world.types)} types"
    )

    output_dir = Path(config.output_dir)

    files = {
        "_types.py": generate_types(world),
        "_convert.py": generate_convert(world),
        "_component.py": generate_component(world),
        "_imports.py": generate_imports(world),
        "__init__.py": generate_init(world),
    }

    for filename, content in files.items():
        path = output_dir / filename
        path.write_text(content)
        print(f"  wrote {path}")

    print("Done.")


if __name__ == "__main__":
    main()
