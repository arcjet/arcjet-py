"""Unit tests for time-ordered identifier generation (arcjet._ids).

Validates that the shared UUIDv7 and Crockford base32 implementation
produces sortable, unambiguous IDs suitable for correlation tracking.
"""

from __future__ import annotations

import time
import uuid
from unittest.mock import patch

from arcjet._ids import (
    _CROCKFORD_ALPHABET,
    crockford32,
    new_correlation_id,
    uuidv7_bytes,
)


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


def test_crockford32_alphabet():
    """crockford32 output contains only valid Crockford base32 characters."""
    # Run multiple times to sample different UUIDs
    for _ in range(10):
        raw = uuidv7_bytes()
        encoded = crockford32(raw)
        for ch in encoded:
            assert ch in _CROCKFORD_ALPHABET, (
                f"character '{ch}' not in Crockford alphabet: {_CROCKFORD_ALPHABET}"
            )


def test_crockford_alphabet_excludes_ambiguous():
    """Crockford alphabet excludes ambiguous characters (i, l, o, u)."""
    for ch in "ilou":
        assert ch not in _CROCKFORD_ALPHABET, f"'{ch}' should not be in alphabet"
    assert len(_CROCKFORD_ALPHABET) == 32


def test_crockford32_no_overflow():
    """First character is 0-7 (128-bit value fits in 130-bit encoding)."""
    # Repeated tests to catch potential overflow in random cases
    for _ in range(50):
        raw = uuidv7_bytes()
        encoded = crockford32(raw)
        first_char = encoded[0]
        assert first_char in "01234567", (
            f"first char overflow: '{first_char}' (expected 0-7)"
        )


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


def test_crockford32_deterministic():
    """crockford32 is deterministic: same input produces same output."""
    raw = uuidv7_bytes()
    encoded1 = crockford32(raw)
    encoded2 = crockford32(raw)
    assert encoded1 == encoded2


def test_uuidv7_bytes_with_zero_timestamp():
    """uuidv7_bytes handles epoch-zero timestamp gracefully."""
    with patch("arcjet._ids.time.time", return_value=0.0):
        raw = uuidv7_bytes()
        u = uuid.UUID(bytes=raw)
        assert u.version == 7
        assert u.variant == uuid.RFC_4122


def test_uuidv7_bytes_with_far_future_timestamp():
    """uuidv7_bytes handles far-future timestamps within the 48-bit range."""
    max_timestamp = (2**48 - 1) / 1000.0
    with patch("arcjet._ids.time.time", return_value=max_timestamp):
        raw = uuidv7_bytes()
        u = uuid.UUID(bytes=raw)
        assert u.version == 7
        assert u.variant == uuid.RFC_4122


def test_uuidv7_bytes_with_zero_random():
    """uuidv7_bytes with all-zero random bytes produces valid UUIDv7."""
    with patch("arcjet._ids.os.urandom", return_value=b"\x00" * 10):
        raw = uuidv7_bytes()
        u = uuid.UUID(bytes=raw)
        assert u.version == 7
        assert u.variant == uuid.RFC_4122


def test_uuidv7_bytes_with_max_random():
    """uuidv7_bytes with max random bytes (no overflow) preserves variant bits."""
    with patch("arcjet._ids.os.urandom", return_value=b"\xff" * 10):
        raw = uuidv7_bytes()
        u = uuid.UUID(bytes=raw)
        assert u.version == 7
        assert u.variant == uuid.RFC_4122


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
