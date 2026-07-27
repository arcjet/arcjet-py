"""Nested-JSON ``metadata`` encoding shared by ``protect()`` and ``guard()``.

``metadata`` is a mapping of string keys to arbitrary JSON-serializable values
(nested objects, arrays, numbers, booleans, ``None``, strings).  The wire format
is ``map<string, string>``: each **top-level** value is JSON-encoded
independently and stored verbatim, so exact integers and value formatting
survive the round trip.

Encoding is the SDK's only client-side responsibility here.  The limits — 128
top-level keys, 4 KiB per serialized value, 10 levels of nesting, and key-name
validity — are enforced server-side (they are configurable per account and can
be raised), and every key the server drops comes back as a decision warning.
The one drop the SDK must make itself is a value it cannot JSON-encode at all
(a ``datetime``, a set, ``NaN``, a circular reference, a non-string key).  Those
are dropped with an ``AJ1017`` warning reported to the server in
``local_warnings`` so the drop is never silent.

Encoding never raises and never affects a decision: a bad value costs you that
one key, not the call.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping, Union

MetadataValue = Union[
    None,
    bool,
    int,
    float,
    str,
    "list[Any]",
    "tuple[Any, ...]",
    "Mapping[str, Any]",
]
"""A single ``metadata`` value: any JSON-serializable Python value.

Nesting is allowed — ``{"user": {"id": "u_1", "roles": ["admin"]}}`` is one
top-level key whose value is a nested object.
"""

Metadata = Mapping[str, MetadataValue]
"""``metadata`` as passed to ``protect()``, ``guard()``, and rule constructors:
string keys mapped to arbitrary JSON-serializable values."""

METADATA_ENCODE_FAILED_CODE = "AJ1017"
"""Warning code for a metadata key the SDK dropped before sending."""

_MAX_REPORTED_KEY_LENGTH = 64
"""Longest key name echoed into a warning, matching the server's key cap."""

_MAX_REPORTED_KEYS = 10
"""Most key names listed in a single warning before the list is elided."""


@dataclass(frozen=True, slots=True)
class LocalWarning:
    """A client-side validation warning reported to the server in
    ``local_warnings``.  Mirrors the proto ``Warning`` message."""

    code: str
    """Machine-readable code (e.g. ``"AJ1017"``)."""

    message: str
    """Human-readable description.  References only the offending key names,
    never the values, and only after sanitizing them."""


def _needs_escape(code: int) -> bool:
    """Whether a code point must be escaped before it goes in a warning message.

    C0 controls, DEL, the C1 range, and the Unicode line/paragraph separators are
    the characters that can break a log line or a JSON-ish log record.  Everything
    else, including ordinary non-ASCII text, is echoed as-is.

    Kept identical to ``needsEscape`` in arcjet-js so both SDKs render the same
    warning for the same key.
    """
    return code < 0x20 or 0x7F <= code <= 0x9F or code in (0x2028, 0x2029)


def _sanitize_key(key: object) -> str:
    """Render a metadata key for inclusion in a warning message.

    Keys are user-controlled, and warnings end up in application logs and in
    server-side storage, so control characters are escaped (a newline in a key
    could otherwise forge a log entry) and the result is length-bounded.
    """
    text = key if isinstance(key, str) else str(key)
    parts: list[str] = []
    for ch in text:
        code = ord(ch)
        if not _needs_escape(code):
            parts.append(ch)
        elif code <= 0xFF:
            parts.append(f"\\x{code:02x}")
        else:
            parts.append(f"\\u{code:04x}")
    escaped = "".join(parts)
    if len(escaped) > _MAX_REPORTED_KEY_LENGTH:
        return escaped[:_MAX_REPORTED_KEY_LENGTH] + "..."
    return escaped


def encode_metadata(
    metadata: Metadata | None,
    *,
    message_prefix: str = "",
) -> tuple[dict[str, str], list[LocalWarning]]:
    """JSON-encode each top-level value of *metadata* for the wire.

    Args:
        metadata: The user-supplied nested metadata, or ``None``.
        message_prefix: Prepended to warning messages to identify the source
            (e.g. ``"rules[0]."``), matching the server's convention.

    Returns:
        ``(encoded, warnings)`` — *encoded* maps each surviving key to its
        JSON-encoded value, ready for the proto ``metadata_json`` field.
        *warnings* holds **at most one** entry, naming every key that had to be
        dropped, so one call can never flood the warning channel.  Both are
        empty when *metadata* is ``None``, empty, or not a mapping.
    """
    if not metadata or not isinstance(metadata, Mapping):
        return {}, []

    encoded: dict[str, str] = {}
    dropped: list[str] = []

    try:
        # Reading the mapping can fail for a custom Mapping whose __iter__ or
        # __getitem__ raises. Metadata must never fail a call.
        items = list(metadata.items())
    except Exception:
        return {}, []

    for key, value in items:
        if not isinstance(key, str):
            dropped.append(_sanitize_key(key))
            continue
        try:
            # allow_nan=False so NaN/Infinity are dropped here rather than
            # sent as JSON the server will reject (they are not valid JSON).
            # separators/ensure_ascii keep the encoding compact and UTF-8,
            # which is what the per-value byte cap is measured against.
            encoded[key] = json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
            )
        except (TypeError, ValueError, RecursionError):
            dropped.append(_sanitize_key(key))

    if not dropped:
        return encoded, []

    listed = ", ".join(f'"{k}"' for k in dropped[:_MAX_REPORTED_KEYS])
    if len(dropped) > _MAX_REPORTED_KEYS:
        listed += ", ..."
    return encoded, [
        LocalWarning(
            code=METADATA_ENCODE_FAILED_CODE,
            message=(
                f"{message_prefix}metadata: {len(dropped)} key(s) could not be "
                f"JSON-encoded and were dropped: {listed}"
            ),
        )
    ]
