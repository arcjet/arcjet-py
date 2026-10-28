"""Assert that the two distributions are versioned and pinned in lockstep.

`arcjet` and `arcjet-sensitive-info-rampart` release together at one version
and pin each other exactly (`==`). Release Please bumps six places for that
(two versions, two pins, two `uv.lock` entries), and an updater that stops
matching only logs a warning, so CI runs this on every change, including the
release pull request, to fail before a mismatched pair is tagged.

Usage: `uv run python tools/check_release_lockstep.py [EXPECTED_VERSION]`.
Without an argument the `arcjet` version is the expected one. It needs only the
standard library on Python 3.11+ (`tomllib`), and `tomli` from the dev
dependency group on 3.10, the same fallback as `tools/witgen/config.py`.
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import tomllib  # pyright: ignore[reportMissingImports]  # ty: ignore[unresolved-import]
except ModuleNotFoundError:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parent.parent
CORE = "arcjet"
BACKEND = "arcjet-sensitive-info-rampart"


def _load(path: str) -> dict:
    with (ROOT / path).open("rb") as handle:
        return tomllib.load(handle)


def _pin(path: str, requirements: list[str], name: str) -> str | None:
    """Return the version of the exact `name==` pin in `requirements`."""
    for requirement in requirements:
        normalized = requirement.replace(" ", "")
        if normalized.startswith(f"{name}=="):
            return normalized.removeprefix(f"{name}==")
    print(f"::error file={path}::no exact `{name}==` pin found.")
    return None


def main(argv: list[str]) -> int:
    core = _load("pyproject.toml")
    backend = _load("sensitive-info-rampart/pyproject.toml")
    lock = _load("uv.lock")

    expected = argv[1] if len(argv) > 1 else core["project"]["version"]

    editable = {
        package["name"]: package["version"]
        for package in lock.get("package", [])
        if "editable" in package.get("source", {})
    }

    found: list[tuple[str, str | None]] = [
        ("pyproject.toml: project.version", core["project"]["version"]),
        (
            f"pyproject.toml: {BACKEND}== pin",
            _pin(
                "pyproject.toml",
                core["project"]["optional-dependencies"]["sensitive-info-rampart"],
                BACKEND,
            ),
        ),
        (
            "sensitive-info-rampart/pyproject.toml: project.version",
            backend["project"]["version"],
        ),
        (
            f"sensitive-info-rampart/pyproject.toml: {CORE}== pin",
            _pin(
                "sensitive-info-rampart/pyproject.toml",
                backend["project"]["dependencies"],
                CORE,
            ),
        ),
        (f"uv.lock: {CORE} version", editable.get(CORE)),
        (f"uv.lock: {BACKEND} version", editable.get(BACKEND)),
    ]

    failed = False
    for where, actual in found:
        if actual != expected:
            print(f"::error::{where} is '{actual}', expected '{expected}'.")
            failed = True
    if failed:
        return 1
    print(f"All six release locations are at {expected}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
