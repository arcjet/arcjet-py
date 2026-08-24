"""Tool-name matching and argument shaping.

CrewAI lowercases, splits camelCase, and replaces disallowed characters before
it matches ``tools=`` filters or looks a tool up. A policy keyed ``Send Email``
must therefore match a call whose ``ctx.tool_name`` is already ``send_email``.

The sanitizer delegates to CrewAI's own function when the extra is installed,
so matching cannot drift as CrewAI changes it. The copy below is the fallback
for a process without the extra, where nothing is matching real tool calls but
unit tests and type checking still have to work.
"""

from __future__ import annotations

import hashlib
import importlib
import re
import threading
import unicodedata
from collections.abc import Mapping
from typing import Any, Callable, Final, Optional, cast

_QUOTE_PATTERN: Final[re.Pattern[str]] = re.compile(r"[\'\"]+")
_CAMEL_LOWER_UPPER: Final[re.Pattern[str]] = re.compile(r"([a-z])([A-Z])")
_CAMEL_UPPER_LOWER: Final[re.Pattern[str]] = re.compile(r"([A-Z]+)([A-Z][a-z])")
_DISALLOWED_CHARS_PATTERN: Final[re.Pattern[str]] = re.compile(r"[^a-zA-Z0-9]+")
_DUPLICATE_UNDERSCORE_PATTERN: Final[re.Pattern[str]] = re.compile(r"_+")
_MAX_TOOL_NAME_LENGTH: Final[int] = 64

# Keys that name an opaque identifier rather than free text a model authored.
# A prompt-injection or sensitive-info rule pointed at one of these scans a
# value no human wrote, which costs a rule evaluation and finds nothing.
_OPAQUE_ID_KEYS: Final[frozenset[str]] = frozenset(
    {
        "id",
        "tool_call_id",
        "run_id",
        "trace_id",
        "span_id",
        "thread_id",
        "session_id",
        "correlation_id",
        "fingerprint",
    }
)

# Resolved on first use, then cached: `_UNRESOLVED` distinguishes "not looked
# up yet" from "looked up, and CrewAI is not installed".
_UNRESOLVED: Final[Any] = object()
_upstream: Any = _UNRESOLVED

# The import runs at most once. Two threads racing here are harmless under the
# GIL — both compute the same function object — but a free-threaded build has
# no such guarantee, and a partially initialized module is exactly what the
# second thread would read.
_upstream_lock = threading.Lock()


def _upstream_sanitizer() -> Optional[Callable[[str], str]]:
    """CrewAI's own ``sanitize_tool_name``, or ``None`` without the extra."""
    global _upstream
    if _upstream is _UNRESOLVED:
        with _upstream_lock:
            if _upstream is _UNRESOLVED:
                try:
                    module = importlib.import_module("crewai.utilities.string_utils")
                    _upstream = module.sanitize_tool_name
                except (ImportError, AttributeError):
                    _upstream = None
    return cast(Optional[Callable[[str], str]], _upstream)


def sanitize_tool_name(name: str, max_length: int = _MAX_TOOL_NAME_LENGTH) -> str:
    """Sanitize *name* the way CrewAI does.

    Delegates to ``crewai.utilities.string_utils.sanitize_tool_name`` when the
    extra is installed, so a policy key and a live ``ctx.tool_name`` are always
    sanitized by the same code. Falls back to the local copy otherwise: NFKD,
    ASCII, camelCase split, lowercase, non-alphanumerics to ``_``, then a hash
    suffix when the result exceeds *max_length* (default 64).
    """
    if max_length == _MAX_TOOL_NAME_LENGTH:
        upstream = _upstream_sanitizer()
        if upstream is not None:
            return upstream(name)
    return _sanitize(name, max_length)


def _sanitize(name: str, max_length: int = _MAX_TOOL_NAME_LENGTH) -> str:
    """The vendored copy of CrewAI's algorithm, for a process without the extra."""
    name = unicodedata.normalize("NFKD", name)
    name = name.encode("ascii", "ignore").decode("ascii")
    name = _CAMEL_UPPER_LOWER.sub(r"\1_\2", name)
    name = _CAMEL_LOWER_UPPER.sub(r"\1_\2", name)
    name = name.lower()
    name = _QUOTE_PATTERN.sub("", name)
    name = _DISALLOWED_CHARS_PATTERN.sub("_", name)
    name = _DUPLICATE_UNDERSCORE_PATTERN.sub("_", name)
    name = name.strip("_")

    if len(name) > max_length:
        name_hash = hashlib.sha256(name.encode()).hexdigest()[:8]
        suffix = f"_{name_hash}"
        name = name[: max_length - len(suffix)].rstrip("_") + suffix

    return name


def free_text_arguments(tool_input: object) -> dict[str, object]:
    """*tool_input* with opaque identifier keys dropped.

    A convenience for a policy that offers tool arguments to a scanning rule:
    ``tool_call_id``, ``trace_id`` and friends are not content, so scanning
    them finds nothing. Nested mappings are walked, and a list keeps its items
    with each mapping filtered the same way.

    Drops **any** key ending in ``_id``, not only the enumerated ones, so an
    argument like ``invoice_id`` or ``document_id`` does not survive either.
    That is the right rule for feeding a scanner and the wrong one if the
    policy needs an id-shaped argument — read those from the mapping a
    resolver is handed, which is unfiltered.

    Nothing applies this for you. A resolver is handed the tool's arguments
    whole, because a resolver reading ``arguments["user_id"]`` is reading the
    tool's own argument, and hiding it would fail a correctly written policy
    closed::

        inputs=lambda arguments, _ctx: {
            "content": server_input.string(json.dumps(free_text_arguments(arguments))),
        }
    """
    if not isinstance(tool_input, Mapping):
        return {}
    return _filter_mapping(cast(Mapping[object, object], tool_input))


def _filter_mapping(value: Mapping[object, object]) -> dict[str, object]:
    filtered: dict[str, object] = {}
    for raw_key, item in value.items():
        if not isinstance(raw_key, str) or _is_opaque_id_key(raw_key):
            continue
        if isinstance(item, Mapping):
            nested = _filter_mapping(cast(Mapping[object, object], item))
            if nested:
                filtered[raw_key] = nested
            continue
        if isinstance(item, list):
            filtered[raw_key] = [
                _filter_mapping(cast(Mapping[object, object], entry))
                if isinstance(entry, Mapping)
                else entry
                for entry in item
            ]
            continue
        filtered[raw_key] = item
    return filtered


def _is_opaque_id_key(key: str) -> bool:
    lowered = key.lower()
    return lowered in _OPAQUE_ID_KEYS or lowered.endswith("_id")
