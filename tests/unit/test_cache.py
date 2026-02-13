"""Unit tests for decision caching functionality.

Tests the DecisionCache and cache key generation logic.
"""

from __future__ import annotations

import time

from arcjet.cache import DecisionCache, make_cache_key
from arcjet.context import RequestContext
from arcjet.decision import Decision
from arcjet.rules import Mode, shield, token_bucket


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


def test_cache_set_with_zero_ttl():
    """Test that setting with TTL <= 0 doesn't cache."""
    from arcjet.cache import DecisionCache
    from arcjet.decision import Decision
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    cache = DecisionCache()
    d = Decision(
        decide_pb2.Decision(id="d1", conclusion=decide_pb2.CONCLUSION_ALLOW, ttl=0)
    )

    # Setting with ttl=0 should not cache
    cache.set("key1", d, ttl_seconds=0)
    assert cache.get("key1") is None

    # Setting with negative ttl should also not cache
    cache.set("key2", d, ttl_seconds=-1)
    assert cache.get("key2") is None


def test_cache_expired_entry_removal_exception():
    """Test that exceptions during expired entry removal are handled."""
    import time

    from arcjet.cache import DecisionCache
    from arcjet.decision import Decision
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    cache = DecisionCache()
    d = Decision(
        decide_pb2.Decision(id="d1", conclusion=decide_pb2.CONCLUSION_ALLOW, ttl=1)
    )

    # Set an entry with very short TTL
    cache.set("k", d, ttl_seconds=0.01)

    # Wait for it to expire
    time.sleep(0.05)

    # Mock the store to raise an exception on delete
    # This tests the exception handling in lines 46-47
    original_store = cache._store

    class FailingDict(dict):
        def __delitem__(self, key):
            raise KeyError("Delete failed")

    cache._store = FailingDict(original_store)

    # Getting an expired entry should handle the exception gracefully
    result = cache.get("k")
    assert result is None


def test_make_cache_key_with_empty_characteristic():
    """Test cache key generation with empty characteristic value."""
    from arcjet.cache import make_cache_key
    from arcjet.context import RequestContext
    from arcjet.rules import Mode, shield

    # Context with empty characteristic value
    ctx = RequestContext(ip="1.2.3.4", extra={"user_id": ""})
    rules = [shield(mode=Mode.LIVE, characteristics=("user_id",))]

    key = make_cache_key(ctx, rules)
    # Should still generate a key even with empty value
    assert key is not None
    assert isinstance(key, str)
    assert len(key) == 64  # SHA256 hex


def test_make_cache_key_with_non_mapping_extra():
    """Test cache key generation when ctx.extra is not a Mapping."""
    from arcjet.cache import make_cache_key
    from arcjet.context import RequestContext
    from arcjet.rules import Mode, shield

    # Context with non-mapping extra (tests line 78)
    ctx = RequestContext(ip="1.2.3.4", extra=None)
    rules = [shield(mode=Mode.LIVE, characteristics=("user_id",))]

    key = make_cache_key(ctx, rules)
    # Should fall back to IP
    assert key is not None
