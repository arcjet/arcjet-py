"""Tool-name sanitization matching CrewAI 1.15.3+.

CrewAI lowercases, splits camelCase, and replaces disallowed characters before
it matches ``tools=`` filters or looks a tool up. A policy keyed ``Send Email``
must therefore hit a call whose ``ctx.tool_name`` has already been sanitized
to ``send_email``. This copy of the algorithm lives here so unit tests (and
typecheck) can exercise matching without importing ``crewai``.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Mapping
from typing import Final, cast

_QUOTE_PATTERN: Final[re.Pattern[str]] = re.compile(r"[\'\"]+")
_CAMEL_LOWER_UPPER: Final[re.Pattern[str]] = re.compile(r"([a-z])([A-Z])")
_CAMEL_UPPER_LOWER: Final[re.Pattern[str]] = re.compile(r"([A-Z]+)([A-Z][a-z])")
_DISALLOWED_CHARS_PATTERN: Final[re.Pattern[str]] = re.compile(r"[^a-zA-Z0-9]+")
_DUPLICATE_UNDERSCORE_PATTERN: Final[re.Pattern[str]] = re.compile(r"_+")
_MAX_TOOL_NAME_LENGTH: Final[int] = 64

# Keys that name an opaque identifier rather than free text the model authored.
# A prompt-injection rule must not be pointed at a tool-call id or a trace id.
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


def sanitize_tool_name(name: str, max_length: int = _MAX_TOOL_NAME_LENGTH) -> str:
    """Sanitize *name* the way CrewAI 1.15.3+ does.

    Mirrors ``crewai.utilities.string_utils.sanitize_tool_name``: NFKD, ASCII,
    camelCase split, lowercase, non-alphanumerics to ``_``, then a hash suffix
    when the result exceeds *max_length* (default 64).
    """
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
    """The model's free-text arguments, with opaque ids stripped.

    ``ctx.tool_input`` is the parsed argument mapping the tool is about to
    receive. Identifier fields (``tool_call_id``, ``trace_id``, …) are not
    content and must not be offered to a prompt-injection or sensitive-info
    rule. Nested mappings are walked; lists of mappings are kept with each
    item filtered the same way.
    """
    if not isinstance(tool_input, dict):
        return {}
    return _filter_mapping(cast(Mapping[object, object], tool_input))


def _filter_mapping(value: Mapping[object, object]) -> dict[str, object]:
    filtered: dict[str, object] = {}
    for raw_key, item in value.items():
        if not isinstance(raw_key, str) or _is_opaque_id_key(raw_key):
            continue
        if isinstance(item, dict):
            nested = _filter_mapping(cast(Mapping[object, object], item))
            if nested:
                filtered[raw_key] = nested
            continue
        if isinstance(item, list):
            filtered[raw_key] = [
                _filter_mapping(cast(Mapping[object, object], entry))
                if isinstance(entry, dict)
                else entry
                for entry in item
            ]
            continue
        filtered[raw_key] = item
    return filtered


def _is_opaque_id_key(key: str) -> bool:
    lowered = key.lower()
    return lowered in _OPAQUE_ID_KEYS or lowered.endswith("_id")
