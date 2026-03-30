"""Unit tests for inline TypeID generation (_new_local_request_id).

Validates that generated local request IDs conform to the TypeID spec
(https://github.com/jetify-com/typeid) and produce valid UUIDv7 payloads.
"""

from __future__ import annotations

import re
import uuid
from unittest.mock import patch

from arcjet.client import (
    _CROCKFORD_ALPHABET,
    _new_local_request_id,
    _uuidv7_bytes,
)

# Valid Crockford base32 characters (excludes i, l, o, u)
_CROCKFORD_RE = re.compile(r"^[0-9a-hj-km-np-tv-z]{26}$")


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_format():
    """ID has lreq_ prefix and 26-char Crockford base32 suffix."""
    rid = _new_local_request_id()
    prefix, sep, suffix = rid.partition("_")
    assert prefix == "lreq"
    assert sep == "_"
    assert _CROCKFORD_RE.match(suffix), f"bad suffix chars: {suffix}"


def test_uuidv7_version_and_variant():
    """Raw bytes encode a valid UUIDv7 (version 7, RFC 4122 variant)."""
    raw = _uuidv7_bytes()
    u = uuid.UUID(bytes=raw)
    assert u.version == 7
    assert u.variant == uuid.RFC_4122


def test_suffix_first_char_max_7():
    """First suffix character must be 0-7 (128-bit value fits in 130-bit encoding)."""
    for _ in range(50):
        suffix = _new_local_request_id().split("_")[1]
        assert suffix[0] in "01234567", f"overflow: first char is '{suffix[0]}'"


def test_ids_are_unique():
    """Consecutive IDs should not collide."""
    ids = {_new_local_request_id() for _ in range(200)}
    assert len(ids) == 200


def test_ids_are_time_sortable():
    """IDs generated later should sort lexicographically after earlier ones."""
    earlier = _new_local_request_id()
    # Advance the clock by at least 1 ms so timestamp differs
    import time

    time.sleep(0.002)
    later = _new_local_request_id()
    assert later > earlier


# ---------------------------------------------------------------------------
# Edge cases / non-happy path
# ---------------------------------------------------------------------------


def test_zero_timestamp():
    """When the clock reads epoch-zero the ID is still well-formed."""
    with patch("arcjet.client.time") as mock_time:
        mock_time.time.return_value = 0.0
        rid = _new_local_request_id()

    prefix, _, suffix = rid.partition("_")
    assert prefix == "lreq"
    assert _CROCKFORD_RE.match(suffix)

    # Timestamp portion (first 10 Crockford chars ≈ 48 bits) should be all zeros
    # when time=0, so the suffix starts with a run of '0's (at least the first
    # several chars).  Just verify it doesn't crash and has valid format.
    assert len(suffix) == 26


def test_max_timestamp():
    """A far-future timestamp still produces a valid 26-char suffix."""
    # Year ~10889 — 48-bit millisecond timestamp near max
    with patch("arcjet.client.time") as mock_time:
        mock_time.time.return_value = (2**48 - 1) / 1000.0
        rid = _new_local_request_id()

    suffix = rid.split("_")[1]
    assert len(suffix) == 26
    assert _CROCKFORD_RE.match(suffix)
    # First char still must be ≤ '7'
    assert suffix[0] in "01234567"


def test_low_entropy_random():
    """All-zero random bytes still produce a structurally valid ID."""
    with patch("arcjet.client.os.urandom", return_value=b"\x00" * 10):
        rid = _new_local_request_id()

    suffix = rid.split("_")[1]
    assert len(suffix) == 26
    assert _CROCKFORD_RE.match(suffix)


def test_max_entropy_random():
    """All-0xFF random bytes still produce a valid ID (no overflow)."""
    with patch("arcjet.client.os.urandom", return_value=b"\xff" * 10):
        rid = _new_local_request_id()

    suffix = rid.split("_")[1]
    assert len(suffix) == 26
    assert _CROCKFORD_RE.match(suffix)
    assert suffix[0] in "01234567"


def test_uuidv7_all_ff_random_preserves_variant():
    """Even with max random bytes, variant bits (10xx) are correctly set."""
    with patch("arcjet.client.os.urandom", return_value=b"\xff" * 10):
        raw = _uuidv7_bytes()
    u = uuid.UUID(bytes=raw)
    assert u.version == 7
    assert u.variant == uuid.RFC_4122


def test_crockford_alphabet_excludes_ambiguous():
    """The alphabet must not contain i, l, o, or u."""
    for ch in "ilou":
        assert ch not in _CROCKFORD_ALPHABET
    assert len(_CROCKFORD_ALPHABET) == 32
