"""Unit tests for time-ordered identifier generation (arcjet._ids).

Validates that the shared UUIDv7 and Crockford base32 implementation
produces sortable, unambiguous IDs suitable for correlation tracking.
"""

from __future__ import annotations

import re
import time
import uuid
from unittest.mock import patch

from hypothesis import given, settings
from hypothesis import strategies as st

from arcjet._ids import (
    _CROCKFORD_ALPHABET,
    crockford32,
    new_correlation_id,
    uuidv7_bytes,
)

_CROCKFORD_RE = re.compile(r"^[0-9a-hj-km-np-tv-z]{26}$")


def _assert_valid_crockford32(encoded: str) -> None:
    """Assert ``encoded`` is 26 Crockford base32 chars with no overflow."""
    assert _CROCKFORD_RE.match(encoded), f"bad chars: {encoded}"
    assert encoded[0] in "01234567", f"overflow: {encoded[0]!r}"


def test_uuidv7_bytes_length():
    """uuidv7_bytes returns exactly 16 bytes."""
    raw = uuidv7_bytes()
    assert isinstance(raw, bytes)
    assert len(raw) == 16


def test_uuidv7_bytes_rfc9562_format():
    """uuidv7_bytes produces valid UUIDv7 per RFC 9562 (version 7, RFC 4122 variant)."""
    raw = uuidv7_bytes()
    u = uuid.UUID(bytes=raw)
    assert u.version == 7, f"expected version 7, got {u.version}"
    assert u.variant == uuid.RFC_4122, f"expected RFC_4122, got {u.variant}"


def test_crockford32_returns_26_chars():
    """crockford32 returns exactly 26 characters."""
    raw = uuidv7_bytes()
    encoded = crockford32(raw)
    assert isinstance(encoded, str)
    assert len(encoded) == 26, f"expected 26 chars, got {len(encoded)}"


def test_crockford_alphabet_excludes_ambiguous():
    """Crockford alphabet excludes ambiguous characters (i, l, o, u)."""
    for ch in "ilou":
        assert ch not in _CROCKFORD_ALPHABET, f"'{ch}' should not be in alphabet"
    assert len(_CROCKFORD_ALPHABET) == 32


def test_crockford32_encodes_domain_extremes():
    """crockford32 encodes domain boundaries correctly (128-bit fits in 130-bit)."""
    # All zeros: smallest possible value
    assert crockford32(b"\x00" * 16) == "0" * 26
    # All ones: largest possible value (2^128 - 1 >> 125 == 7)
    encoded = crockford32(b"\xff" * 16)
    _assert_valid_crockford32(encoded)
    assert encoded[0] == "7"  # 2**128-1 >> 125


def test_new_correlation_id_format():
    """new_correlation_id returns 26 lowercase alphanumeric characters."""
    cid = new_correlation_id()
    assert isinstance(cid, str)
    assert len(cid) == 26, f"expected 26 chars, got {len(cid)}"
    assert cid.isalnum(), f"expected alphanumeric, got {cid}"
    assert cid.islower(), f"expected lowercase, got {cid}"


def test_new_correlation_id_uniqueness():
    """Successive calls to new_correlation_id return different values."""
    cid1 = new_correlation_id()
    cid2 = new_correlation_id()
    assert cid1 != cid2, "correlation IDs should be unique"


def test_new_correlation_id_time_sortable():
    """Correlation IDs generated in sequence are lexicographically sortable by time."""
    ids = []
    for _ in range(5):
        ids.append(new_correlation_id())
        time.sleep(0.001)  # Ensure time advance between generations
    sorted_ids = sorted(ids)
    assert ids == sorted_ids, (
        f"IDs should sort by creation time; got {ids}, sorted {sorted_ids}"
    )


def test_uuidv7_bytes_with_zero_timestamp():
    """uuidv7_bytes handles epoch-zero timestamp gracefully."""
    with patch("arcjet._ids.time.time", return_value=0.0):
        raw = uuidv7_bytes()
        u = uuid.UUID(bytes=raw)
        assert u.version == 7
        assert u.variant == uuid.RFC_4122
        _assert_valid_crockford32(crockford32(raw))


def test_uuidv7_bytes_with_far_future_timestamp():
    """uuidv7_bytes handles far-future timestamps within the 48-bit range."""
    max_timestamp = (2**48 - 1) / 1000.0
    with patch("arcjet._ids.time.time", return_value=max_timestamp):
        raw = uuidv7_bytes()
        u = uuid.UUID(bytes=raw)
        assert u.version == 7
        assert u.variant == uuid.RFC_4122
        _assert_valid_crockford32(crockford32(raw))


def test_uuidv7_bytes_with_zero_random():
    """uuidv7_bytes with all-zero random bytes produces valid UUIDv7."""
    with patch("arcjet._ids.os.urandom", return_value=b"\x00" * 10):
        raw = uuidv7_bytes()
        u = uuid.UUID(bytes=raw)
        assert u.version == 7
        assert u.variant == uuid.RFC_4122
        _assert_valid_crockford32(crockford32(raw))


def test_uuidv7_bytes_with_max_random():
    """uuidv7_bytes with max random bytes (no overflow) preserves variant bits."""
    with patch("arcjet._ids.os.urandom", return_value=b"\xff" * 10):
        raw = uuidv7_bytes()
        u = uuid.UUID(bytes=raw)
        assert u.version == 7
        assert u.variant == uuid.RFC_4122
        _assert_valid_crockford32(crockford32(raw))


def test_new_correlation_id_uses_uuidv7():
    """new_correlation_id encodes a valid UUIDv7."""
    cid = new_correlation_id()
    # Reverse the crockford32 encoding process to validate the encoded UUID
    # The ID is 26 chars of base32, which should decode back to a valid UUIDv7
    alphabet = _CROCKFORD_ALPHABET
    n = 0
    for ch in cid:
        n = (n << 5) | alphabet.index(ch)
    # Convert back to bytes (big-endian)
    raw = n.to_bytes(16, "big")
    u = uuid.UUID(bytes=raw)
    assert u.version == 7
    assert u.variant == uuid.RFC_4122


# ---------------------------------------------------------------------------
# Fuzz tests (hypothesis)
# ---------------------------------------------------------------------------

_MAX_TIMESTAMP_MS = 2**48 - 1

_fuzz_timestamp = st.floats(
    min_value=0, max_value=_MAX_TIMESTAMP_MS / 1000.0, allow_nan=False
)
_fuzz_rand = st.binary(min_size=10, max_size=10)


def _assert_valid_uuidv7(raw: bytes) -> uuid.UUID:
    """Assert ``raw`` is valid UUIDv7 bytes and return the UUID."""
    assert len(raw) == 16
    u = uuid.UUID(bytes=raw)
    assert u.version == 7
    assert u.variant == uuid.RFC_4122
    return u


@given(timestamp=_fuzz_timestamp, rand_bytes=_fuzz_rand)
@settings(max_examples=500)
def test_fuzz_uuidv7_invariants(timestamp: float, rand_bytes: bytes):
    """Any timestamp + random bytes must produce a valid UUIDv7 with valid encoding."""
    with (
        patch("arcjet._ids.time.time", return_value=timestamp),
        patch("arcjet._ids.os.urandom", return_value=rand_bytes),
    ):
        raw = uuidv7_bytes()
        _assert_valid_uuidv7(raw)
        _assert_valid_crockford32(crockford32(raw))


@given(timestamp=_fuzz_timestamp, rand_bytes=_fuzz_rand)
@settings(max_examples=500)
def test_fuzz_roundtrip_timestamp(timestamp: float, rand_bytes: bytes):
    """The embedded timestamp should match the input (truncated to integer ms)."""
    with (
        patch("arcjet._ids.time.time", return_value=timestamp),
        patch("arcjet._ids.os.urandom", return_value=rand_bytes),
    ):
        raw = uuidv7_bytes()

    expected_ms = int(timestamp * 1000)
    actual_ms = int.from_bytes(raw[:6], "big")
    assert actual_ms == expected_ms, f"timestamp mismatch: {actual_ms} != {expected_ms}"
