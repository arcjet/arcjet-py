"""Time-ordered identifier generation shared across the SDK.

Two callers need a sortable id and nothing else from each other:
``_new_local_request_id`` in the HTTP client, and correlation IDs in
:mod:`arcjet.guard._context`.  One implementation, owned by neither.
"""

from __future__ import annotations

import os
import time

__all__ = ["crockford32", "new_correlation_id", "uuidv7_bytes"]

_CROCKFORD_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"


def uuidv7_bytes() -> bytes:
    """Generate a UUIDv7 as 16 raw bytes (RFC 9562)."""
    timestamp_ms = int(time.time() * 1000)
    rand_bytes = os.urandom(10)
    rand_a = rand_bytes[0] << 4 | rand_bytes[1] >> 4
    rand_b = int.from_bytes(rand_bytes[2:], "big") & ((1 << 62) - 1)

    hi = (timestamp_ms << 16) | (0x7 << 12) | rand_a  # ver=7
    lo = (0b10 << 62) | rand_b  # var=10
    return hi.to_bytes(8, "big") + lo.to_bytes(8, "big")


def crockford32(raw: bytes) -> str:
    """Encode 16 raw bytes as 26 Crockford base32 characters, big-endian.

    See https://github.com/jetify-com/typeid for the specification this
    matches.
    """
    n = int.from_bytes(raw, "big")
    chars = []
    for _ in range(26):
        chars.append(_CROCKFORD_ALPHABET[n & 0x1F])
        n >>= 5
    chars.reverse()
    return "".join(chars)


def new_correlation_id() -> str:
    """Generate a correlation ID for a new Sequence.

    26 characters of Crockford base32 over a UUIDv7: lowercase alphanumeric,
    lexicographically sortable by creation time, and comfortably inside the
    server's 256-byte printable-ASCII bound.
    """
    return crockford32(uuidv7_bytes())
