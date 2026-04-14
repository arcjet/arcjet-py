"""Griffe extension to respect ``__all__`` for submodule visibility.

By default, griffe treats every non-underscore-prefixed submodule as public,
regardless of ``__all__``.  This extension walks the loaded tree and marks
submodules as **non-public** when the parent package defines ``__all__`` and
the submodule is not listed in it.

Usage (CLI)::

    griffe check arcjet -s src -e tools/griffe_extensions.py --against origin/main
"""

from __future__ import annotations

from griffe import Extension, Module


class _PublicPackageApiOnly(Extension):
    """Mark submodules that are not in their parent's ``__all__`` as non-public."""

    def on_package(self, *, pkg: Module, **kwargs: object) -> None:  # noqa: ARG002
        _apply_all_filter(pkg)


def _apply_all_filter(mod: Module) -> None:
    """Recursively mark non-exported submodules as non-public."""
    if mod.exports is not None:
        for name, member in mod.all_members.items():
            if not member.is_alias and member.is_module and name not in mod.exports:
                # ``member.public`` is ``Optional[bool]``; setting it to
                # ``False`` takes priority in griffe's ``is_public`` property,
                # overriding the default "non-underscore module → public" rule.
                member.public = False  # type: ignore[union-attr]

    # Recurse into child subpackages.
    for member in mod.all_members.values():
        if not member.is_alias and member.is_module:
            _apply_all_filter(member)  # type: ignore[arg-type]
