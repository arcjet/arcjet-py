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


@dataclass(frozen=True, slots=True)
class LocalWarning:
    """A client-side validation warning reported to the server in
    ``local_warnings``.  Mirrors the proto ``Warning`` message."""

    code: str
    """Machine-readable code (e.g. ``"AJ1017"``)."""

    message: str
    """Human-readable description.  References only the offending key name,
    never the value."""


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
        *warnings* has one entry per key dropped because it could not be
        encoded.  Both are empty when *metadata* is ``None`` or empty.
    """
    if not metadata:
        return {}, []

    encoded: dict[str, str] = {}
    warnings: list[LocalWarning] = []

    for key, value in metadata.items():
        if not isinstance(key, str):
            warnings.append(
                LocalWarning(
                    code=METADATA_ENCODE_FAILED_CODE,
                    message=(
                        f"{message_prefix}metadata key of type "
                        f"{type(key).__name__} is not a string; key dropped"
                    ),
                )
            )
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
        except (TypeError, ValueError, RecursionError) as exc:
            warnings.append(
                LocalWarning(
                    code=METADATA_ENCODE_FAILED_CODE,
                    message=(
                        f'{message_prefix}metadata value for key "{key}" could '
                        f"not be JSON-encoded ({type(exc).__name__}); key dropped"
                    ),
                )
            )

    return encoded, warnings
