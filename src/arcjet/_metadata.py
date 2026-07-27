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
from typing import Any, Mapping, MutableMapping, Sequence, Union

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

MAX_METADATA_BYTES = 768 * 1024
"""SDK-side ceiling on the total metadata bytes in one request.

This is a **protocol** backstop, not a copy of the server's policy limits, and it
is deliberately well above them: the server caps a metadata map at 128 keys of
4 KiB (~512 KiB) and those caps are per-account and can be raised, so the SDK
must never pre-empt them.

What it protects against is the one immutable limit: a request over 1 MiB is
rejected outright, before any per-key validation runs.  A rejected request means
no decision, which means a fail open — so without this ceiling, oversized
attacker-derived metadata could change the security outcome, contrary to the
guarantee that metadata never affects a decision.  Counted as UTF-8 bytes of keys
plus JSON-encoded values before compression, so the estimate is conservative.
"""


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
    the characters that can break a log line or a JSON-ish log record.  Surrogates
    are escaped because a lone one cannot be encoded as UTF-8 at all, and a warning
    is itself sent over the wire.  Everything else, including ordinary non-ASCII
    text, is echoed as-is.

    Kept identical to ``needsEscape`` in arcjet-js so both SDKs render the same
    warning for the same key.
    """
    return (
        code < 0x20
        or 0x7F <= code <= 0x9F
        or 0xD800 <= code <= 0xDFFF
        or code in (0x2028, 0x2029)
    )


def _sanitize_key(key: object) -> str:
    """Render a metadata key for inclusion in a warning message.

    Keys are user-controlled, and warnings end up in application logs and in
    server-side storage, so control characters are escaped (a newline in a key
    could otherwise forge a log entry) and the result is length-bounded.
    """
    if isinstance(key, str):
        text = key
    else:
        try:
            text = str(key)
        except Exception:
            # A hostile __str__ must not escape the encoder.
            return f"<unprintable {type(key).__name__}>"

    parts: list[str] = []
    length = 0
    for ch in text:
        code = ord(ch)
        if not _needs_escape(code):
            token = ch
        elif code <= 0xFF:
            token = f"\\x{code:02x}"
        else:
            token = f"\\u{code:04x}"
        # Truncate on a whole token so the result is never a half escape
        # sequence or a split surrogate pair.
        if length + len(token) > _MAX_REPORTED_KEY_LENGTH:
            return "".join(parts) + "..."
        parts.append(token)
        length += len(token)
    return "".join(parts)


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
    if not isinstance(metadata, Mapping):
        return {}, []
    try:
        # `len()`/`__bool__` are user code on a custom Mapping and can raise.
        if not metadata:
            return {}, []
    except Exception:
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
            serialized = json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            # A str may hold lone surrogates, which protobuf cannot encode: it
            # raises UnicodeEncodeError and takes the whole request with it.
            # Encoding here turns that into a dropped key. UnicodeEncodeError is
            # a ValueError, so the existing handler catches it.
            key.encode("utf-8")
            serialized.encode("utf-8")
            encoded[key] = serialized
        except (TypeError, ValueError, RecursionError):
            dropped.append(_sanitize_key(key))

    if not dropped:
        return encoded, []

    return encoded, [
        LocalWarning(
            code=METADATA_ENCODE_FAILED_CODE,
            message=_format_dropped(
                message_prefix, "could not be JSON-encoded and were dropped", dropped
            ),
        )
    ]


def _format_dropped(prefix: str, reason: str, keys: list[str]) -> str:
    """Render the key list for a warning, eliding once it gets long."""
    listed = ", ".join(f'"{k}"' for k in keys[:_MAX_REPORTED_KEYS])
    if len(keys) > _MAX_REPORTED_KEYS:
        listed += ", ..."
    return f"{prefix}metadata: {len(keys)} key(s) {reason}: {listed}"


def enforce_metadata_budget(
    maps: Sequence[MutableMapping[str, str]],
) -> list[LocalWarning]:
    """Trim already-encoded metadata maps to :data:`MAX_METADATA_BYTES` in total.

    *maps* are trimmed **in place**, in the order given, and within each map in
    insertion order: keys are kept until the running total would exceed the
    budget, and every key after that is dropped.  Pass the request envelope's map
    first and each rule's map after it, so the order is stable across calls.

    One request can carry several metadata maps (a guard request has one per rule
    plus the envelope), so the ceiling has to be enforced across all of them
    rather than per map.  See :data:`MAX_METADATA_BYTES` for why this exists at
    all.

    Returns at most one warning, naming the keys that were dropped.
    """
    total = 0
    dropped: list[str] = []

    for m in maps:
        over: list[str] = []
        for key, value in m.items():
            if total > MAX_METADATA_BYTES:
                over.append(key)
                continue
            size = len(key.encode("utf-8")) + len(value.encode("utf-8"))
            if total + size > MAX_METADATA_BYTES:
                over.append(key)
                # Nothing further fits either; keep scanning so every dropped
                # key is reported.
                total = MAX_METADATA_BYTES + 1
                continue
            total += size
        for key in over:
            del m[key]
            dropped.append(_sanitize_key(key))

    if not dropped:
        return []
    return [
        LocalWarning(
            code=METADATA_ENCODE_FAILED_CODE,
            message=_format_dropped(
                "",
                f"exceeded the {MAX_METADATA_BYTES}-byte request metadata budget "
                "and were dropped",
                dropped,
            ),
        )
    ]
