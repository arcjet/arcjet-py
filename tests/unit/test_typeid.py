"""Unit tests for inline TypeID generation (_new_local_request_id).

Validates that generated local request IDs conform to the TypeID spec
(https://github.com/jetify-com/typeid) and produce valid UUIDv7 payloads.
"""

from __future__ import annotations

import re
import uuid
from unittest.mock import patch

from hypothesis import given, settings
from hypothesis import strategies as st

from arcjet._client import (
    _CROCKFORD_ALPHABET,
    _new_local_request_id,
    _uuidv7_bytes,
)

_CROCKFORD_RE = re.compile(r"^[0-9a-hj-km-np-tv-z]{26}$")


def _assert_valid_typeid(rid: str) -> str:
    """Assert ``rid`` is a well-formed ``lreq`` TypeID and return the suffix."""
    prefix, sep, suffix = rid.partition("_")
    assert prefix == "lreq"
    assert sep == "_"
    assert len(suffix) == 26
    assert _CROCKFORD_RE.match(suffix), f"bad suffix chars: {suffix}"
    assert suffix[0] in "01234567", f"overflow: first char is '{suffix[0]}'"
    return suffix


def _assert_valid_uuidv7(raw: bytes) -> uuid.UUID:
    """Assert ``raw`` is valid UUIDv7 bytes and return the UUID."""
    assert len(raw) == 16
    u = uuid.UUID(bytes=raw)
    assert u.version == 7
    assert u.variant == uuid.RFC_4122
    return u


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_format():
    """ID has lreq_ prefix and 26-char Crockford base32 suffix."""
    _assert_valid_typeid(_new_local_request_id())


def test_uuidv7_version_and_variant():
    """Raw bytes encode a valid UUIDv7 (version 7, RFC 4122 variant)."""
    _assert_valid_uuidv7(_uuidv7_bytes())


def test_suffix_first_char_max_7():
    """First suffix character must be 0-7 (128-bit value fits in 130-bit encoding)."""
    for _ in range(50):
        _assert_valid_typeid(_new_local_request_id())


def test_ids_are_unique():
    """Consecutive IDs should not collide."""
    ids = {_new_local_request_id() for _ in range(200)}
    assert len(ids) == 200


def test_ids_are_time_sortable():
    """IDs generated later should sort lexicographically after earlier ones."""
    import time

    earlier = _new_local_request_id()
    time.sleep(0.002)
    later = _new_local_request_id()
    assert later > earlier


# ---------------------------------------------------------------------------
# Edge cases / non-happy path
# ---------------------------------------------------------------------------


def test_zero_timestamp():
    """When the clock reads epoch-zero the ID is still well-formed."""
    with patch("arcjet._client.time.time", return_value=0.0):
        _assert_valid_typeid(_new_local_request_id())


def test_max_timestamp():
    """A far-future timestamp still produces a valid 26-char suffix."""
    with patch("arcjet._client.time.time", return_value=(2**48 - 1) / 1000.0):
        _assert_valid_typeid(_new_local_request_id())


def test_low_entropy_random():
    """All-zero random bytes still produce a structurally valid ID."""
    with patch("arcjet._client.os.urandom", return_value=b"\x00" * 10):
        _assert_valid_typeid(_new_local_request_id())


def test_max_entropy_random():
    """All-0xFF random bytes still produce a valid ID (no overflow)."""
    with patch("arcjet._client.os.urandom", return_value=b"\xff" * 10):
        _assert_valid_typeid(_new_local_request_id())


def test_uuidv7_all_ff_random_preserves_variant():
    """Even with max random bytes, variant bits (10xx) are correctly set."""
    with patch("arcjet._client.os.urandom", return_value=b"\xff" * 10):
        _assert_valid_uuidv7(_uuidv7_bytes())


def test_crockford_alphabet_excludes_ambiguous():
    """The alphabet must not contain i, l, o, or u."""
    for ch in "ilou":
        assert ch not in _CROCKFORD_ALPHABET
    assert len(_CROCKFORD_ALPHABET) == 32


# ---------------------------------------------------------------------------
# Fuzz tests (hypothesis)
# ---------------------------------------------------------------------------

_MAX_TIMESTAMP_MS = 2**48 - 1

_fuzz_timestamp = st.floats(
    min_value=0, max_value=_MAX_TIMESTAMP_MS / 1000.0, allow_nan=False
)
_fuzz_rand = st.binary(min_size=10, max_size=10)


@given(timestamp=_fuzz_timestamp, rand_bytes=_fuzz_rand)
@settings(max_examples=500)
def test_fuzz_typeid_invariants(timestamp: float, rand_bytes: bytes):
    """Any timestamp + random bytes must produce a valid TypeID and UUIDv7."""
    with (
        patch("arcjet._client.time.time", return_value=timestamp),
        patch("arcjet._client.os.urandom", return_value=rand_bytes),
    ):
        _assert_valid_typeid(_new_local_request_id())
        _assert_valid_uuidv7(_uuidv7_bytes())


@given(timestamp=_fuzz_timestamp, rand_bytes=_fuzz_rand)
@settings(max_examples=500)
def test_fuzz_roundtrip_timestamp(timestamp: float, rand_bytes: bytes):
    """The embedded timestamp should match the input (truncated to integer ms)."""
    with (
        patch("arcjet._client.time.time", return_value=timestamp),
        patch("arcjet._client.os.urandom", return_value=rand_bytes),
    ):
        raw = _uuidv7_bytes()

    expected_ms = int(timestamp * 1000)
    actual_ms = int.from_bytes(raw[:6], "big")
    assert actual_ms == expected_ms, f"timestamp mismatch: {actual_ms} != {expected_ms}"
