"""Lazy Google ADK imports, so this package works without the extra.

The public module is importable without ``google-adk``: unit tests and
``import arcjet.guard`` must keep working. The helpers duck-type
``before_tool_callback`` so a missing extra does not fail the factory.
The floor is checked when the peer *is* installed, so a too-old SDK is
refused at factory time rather than as an ``AttributeError`` from
inside a callback the runner would wrap as a plugin error.

The floor is 2.0.0 — ADK 2.x, matching JS ``@arcjet/guard/google-adk/v2``
(``@google/adk`` ``>=2 <3``). The version segment names the SDK major.

``importlib`` is used rather than static imports so type checkers do not
need the extra installed either. The distribution is ``google-adk``; the
import package is ``google.adk``.
"""

from __future__ import annotations

import importlib
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Final, Optional

from arcjet._errors import ArcjetMisconfiguration

#: First 2.x release. Below this the extra pin is ``google-adk>=2.0.0,<3``.
MINIMUM_GOOGLE_ADK: Final[tuple[int, int, int]] = (2, 0, 0)

_INSTALL_HINT: Final[str] = (
    'Install it with: pip install "arcjet[google-adk]" (google-adk>=2.0.0,<3)'
)


def _release(raw: str) -> tuple[int, ...]:
    """The numeric release segment of *raw*, e.g. ``"2.0.0rc1"`` → ``(2, 0, 0)``.

    Local parsing rather than ``packaging.version``: that is not an Arcjet
    dependency, and a three-part release is all this comparison needs. Pre-
    release suffixes (``rc1``) are stripped; post-releases (``2.0.0.post1``)
    also compare as ``(2, 0, 0)`` because only the leading digit run is kept.
    A short or non-numeric release such as ``"2.0"`` or ``"2.0.post1"``
    collapses to ``(2, 0)``, which compares less than the three-part floor
    and is refused — not treated as unknown and skipped. An empty parse
    (``"weird"``) is the skip path.
    """
    parts: list[int] = []
    for chunk in raw.split(".")[:3]:
        digits = ""
        for char in chunk:
            if not char.isdigit():
                break
            digits += char
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts)


def _installed_version() -> Optional[str]:
    try:
        return version("google-adk")
    except PackageNotFoundError:  # pragma: no cover - depends on the install
        return None


def _require_google_adk() -> None:
    """Refuse a peer below 2.0.0, before anything is wired.

    Reported at factory time rather than as an ``AttributeError`` from
    inside a callback the runner would wrap as a plugin error.
    """
    installed = _installed_version()
    if installed is None:
        return
    release = _release(installed)
    if release and release < MINIMUM_GOOGLE_ADK:
        floor = ".".join(str(part) for part in MINIMUM_GOOGLE_ADK)
        raise ArcjetMisconfiguration(
            f"arcjet.guard.google_adk needs google-adk >= {floor}, but "
            f"{installed} is installed. Below {floor} this adapter targets "
            f"ADK 2.x LlmAgent / BasePlugin.before_tool_callback. Upgrade "
            f'with: pip install "google-adk>={floor},<3"'
        )


def load_google_adk() -> Any:
    """The ``google.adk`` package, or an error naming what to install."""
    _require_google_adk()
    try:
        return importlib.import_module("google.adk")
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise ImportError(
            f"arcjet.guard.google_adk needs Google ADK. {_INSTALL_HINT}"
        ) from exc


def load_base_plugin() -> type[Any]:
    """ADK's ``BasePlugin``, or an error naming what to install."""
    _require_google_adk()
    try:
        module = importlib.import_module("google.adk.plugins.base_plugin")
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise ImportError(
            f"arcjet.guard.google_adk needs Google ADK. {_INSTALL_HINT}"
        ) from exc
    return module.BasePlugin


def try_load_base_plugin() -> Optional[type[Any]]:
    """``BasePlugin`` when the extra is installed and new enough, else ``None``.

    ``guard_plugin`` subclasses when it can so ``PluginManager`` finds every
    lifecycle method. A missing extra is not an error — the factory duck-types
    the same ``before_tool_callback`` the unit suite calls.
    """
    if not google_adk_present():
        return None
    _require_google_adk()
    try:
        module = importlib.import_module("google.adk.plugins.base_plugin")
    except ImportError:
        return None
    candidate = getattr(module, "BasePlugin", None)
    if isinstance(candidate, type):
        return candidate
    return None


def google_adk_present() -> bool:
    """Whether ``google.adk`` is importable in this process."""
    try:
        importlib.import_module("google.adk")
    except ImportError:
        return False
    return True
