"""Unit tests for the ``lreq_`` TypeID prefix contract of _new_local_request_id.

Validates that generated local request IDs conform to the TypeID spec
(https://github.com/jetify-com/typeid).
"""

from __future__ import annotations

import re

from arcjet._client import _new_local_request_id

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


def test_format():
    """ID has lreq_ prefix and 26-char Crockford base32 suffix."""
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
