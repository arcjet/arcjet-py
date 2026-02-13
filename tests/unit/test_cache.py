"""Unit tests for decision caching functionality.

Tests the DecisionCache and cache key generation logic.
"""

from __future__ import annotations

import time

from arcjet.cache import DecisionCache, make_cache_key
from arcjet.context import RequestContext
from arcjet.decision import Decision
from arcjet.rules import shield, token_bucket, Mode


def test_cache_set_get_and_expiry(mock_protobuf_modules):
    """Test that cache stores and retrieves decisions with TTL expiry."""
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    cache = DecisionCache()
    d = Decision(
        decide_pb2.Decision(id="d1", conclusion=decide_pb2.CONCLUSION_ALLOW, ttl=1)
    )
    cache.set("k", d, ttl_seconds=1)
    assert cache.get("k") is d
    
    # After expiry
    time.sleep(1.1)
    assert cache.get("k") is None


def test_make_cache_key_characteristics_and_ip_fallback():
    """Test cache key generation with characteristics and IP fallback."""
    ctx = RequestContext(ip="203.0.113.5", extra={"uid": "u-1"})
    rules = [
        shield(mode=Mode.LIVE, characteristics=("uid",)),
        token_bucket(mode=Mode.LIVE, refill_rate=10, interval=60, capacity=20),
    ]
    k1 = make_cache_key(ctx, rules)
    assert isinstance(k1, str) and len(k1) == 64  # sha256 hex

    # Changing the characteristic value changes the key
    ctx2 = RequestContext(ip="203.0.113.5", extra={"uid": "u-2"})
    k2 = make_cache_key(ctx2, rules)
    assert k1 != k2

    # When no characteristics, IP becomes identity;
    # if IP missing and no characteristics, returns None
    ctx3 = RequestContext(ip=None)
    k3 = make_cache_key(
        ctx3, [token_bucket(mode=Mode.LIVE, refill_rate=1, interval=1, capacity=1)]
    )
    assert k3 is None
