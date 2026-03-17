"""Unit tests for decision caching functionality.

Tests the DecisionCache and cache key generation logic, ported from
arcjet-js cache tests with the same semantics:
- Only DENY decisions with TTL > 0 are cached
- ALLOW decisions are never cached (even with TTL > 0)
- DENY decisions with TTL = 0 are not cached
- DRY_RUN results are not cached
"""

from __future__ import annotations

import time

from arcjet.cache import DecisionCache, make_cache_key
from arcjet.context import RequestContext
from arcjet.rules import Mode, shield, token_bucket

# ---------------------------------------------------------------------------
# DecisionCache low-level tests (ported from arcjet-js cache/test/memory.test.ts)
# ---------------------------------------------------------------------------


def test_cache_set_and_get(mock_protobuf_modules):
    """Test that set() stores a value and get() retrieves it."""
    from arcjet.decision import Decision
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    cache = DecisionCache()
    d = Decision(
        decide_pb2.Decision(id="d1", conclusion=decide_pb2.CONCLUSION_DENY, ttl=10)
    )
    cache.set("k", d, ttl_seconds=10)
    assert cache.get("k") is d


def test_cache_get_missing_key(mock_protobuf_modules):
    """Test that get() returns None for a key that was never set."""
    cache = DecisionCache()
    assert cache.get("missing") is None


def test_cache_get_expired_entry(mock_protobuf_modules):
    """Test that get() returns None once the TTL has elapsed."""
    from arcjet.decision import Decision
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    cache = DecisionCache()
    d = Decision(
        decide_pb2.Decision(id="d1", conclusion=decide_pb2.CONCLUSION_DENY, ttl=1)
    )
    cache.set("k", d, ttl_seconds=0.05)
    time.sleep(0.1)
    assert cache.get("k") is None


def test_cache_set_with_zero_ttl(mock_protobuf_modules):
    """Test that set() with TTL <= 0 does not store the entry."""
    from arcjet.decision import Decision
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    cache = DecisionCache()
    d = Decision(
        decide_pb2.Decision(id="d1", conclusion=decide_pb2.CONCLUSION_DENY, ttl=0)
    )

    cache.set("key1", d, ttl_seconds=0)
    assert cache.get("key1") is None

    cache.set("key2", d, ttl_seconds=-1)
    assert cache.get("key2") is None


def test_cache_set_overwrites_existing(mock_protobuf_modules):
    """Test that set() on the same key replaces the previous entry."""
    from arcjet.decision import Decision
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    cache = DecisionCache()
    d1 = Decision(
        decide_pb2.Decision(id="d1", conclusion=decide_pb2.CONCLUSION_DENY, ttl=10)
    )
    d2 = Decision(
        decide_pb2.Decision(id="d2", conclusion=decide_pb2.CONCLUSION_DENY, ttl=10)
    )
    cache.set("k", d1, ttl_seconds=10)
    cache.set("k", d2, ttl_seconds=10)
    assert cache.get("k") is d2


def test_cache_empty_string_key(mock_protobuf_modules):
    """Test that empty string is a valid cache key."""
    from arcjet.decision import Decision
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    cache = DecisionCache()
    d = Decision(
        decide_pb2.Decision(id="d1", conclusion=decide_pb2.CONCLUSION_DENY, ttl=10)
    )
    cache.set("", d, ttl_seconds=10)
    assert cache.get("") is d


def test_cache_expired_entry_removal_exception(mock_protobuf_modules):
    """Test that exceptions during expired entry removal are handled gracefully."""
    from arcjet.decision import Decision
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    cache = DecisionCache()
    d = Decision(
        decide_pb2.Decision(id="d1", conclusion=decide_pb2.CONCLUSION_DENY, ttl=1)
    )

    cache.set("k", d, ttl_seconds=0.01)
    time.sleep(0.05)

    class FailingDict(dict):
        def __delitem__(self, key):
            raise KeyError("Delete failed")

    cache._store = FailingDict(cache._store)
    assert cache.get("k") is None


# ---------------------------------------------------------------------------
# Cache key generation tests
# ---------------------------------------------------------------------------


def test_make_cache_key_characteristics_and_ip_fallback():
    """Test that cache key uses characteristics when available, IP as fallback."""
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

    # No characteristics and no IP → returns None
    ctx3 = RequestContext(ip=None)
    k3 = make_cache_key(
        ctx3, [token_bucket(mode=Mode.LIVE, refill_rate=1, interval=1, capacity=1)]
    )
    assert k3 is None


def test_make_cache_key_with_empty_characteristic():
    """Test that empty characteristic value still generates a key."""
    ctx = RequestContext(ip="1.2.3.4", extra={"user_id": ""})
    rules = [shield(mode=Mode.LIVE, characteristics=("user_id",))]

    key = make_cache_key(ctx, rules)
    assert key is not None
    assert isinstance(key, str)
    assert len(key) == 64


def test_make_cache_key_with_non_mapping_extra():
    """Test that non-mapping extra falls back to characteristics producing a key."""
    ctx = RequestContext(ip="1.2.3.4", extra=None)
    rules = [shield(mode=Mode.LIVE, characteristics=("user_id",))]

    key = make_cache_key(ctx, rules)
    assert key is not None


# ---------------------------------------------------------------------------
# Integration-level caching semantics
# (ported from arcjet-js arcjet/test/arcjet.test.ts)
# ---------------------------------------------------------------------------


def test_should_cache_deny_result_with_ttl(
    mock_protobuf_modules,
    dev_environment,
    monkeypatch,
):
    """Test that a DENY decision with TTL > 0 is cached.

    Second protect() call should return the cached decision without
    calling the remote decide API again.
    (JS: "should cache a deny result w/ `ttl`")
    """
    from arcjet import arcjet_sync
    from arcjet.proto.decide.v1alpha1.decide_connect import DecideServiceClientSync
    from arcjet.rules import token_bucket

    decide_calls = {"count": 0}

    def deny_with_ttl(req):
        decide_calls["count"] += 1
        return mock_protobuf_modules["DecideResponse"](
            mock_protobuf_modules["Decision"](
                id="deny1",
                conclusion=mock_protobuf_modules["pb2"].CONCLUSION_DENY,
                ttl=10,
            )
        )

    monkeypatch.setattr(
        DecideServiceClientSync, "decide_behavior", deny_with_ttl, raising=False
    )

    aj = arcjet_sync(
        key="ajkey_test",
        rules=[token_bucket(refill_rate=1, interval=1, capacity=1)],
    )

    # First call: hits the API
    d1 = aj.protect({"headers": [], "type": "http"})
    assert d1.is_denied()
    assert decide_calls["count"] == 1

    # Second call: should be served from cache, no additional API call
    d2 = aj.protect({"headers": [], "type": "http"})
    assert d2.is_denied()
    assert decide_calls["count"] == 1  # still 1 — no new decide call


def test_should_not_cache_allow_result_with_ttl(
    mock_protobuf_modules,
    dev_environment,
    monkeypatch,
):
    """Test that an ALLOW decision with TTL > 0 is not cached.

    Second protect() call should make another API call.
    (JS: "should not cache an allow result w/ `ttl`")
    """
    from arcjet import arcjet_sync
    from arcjet.proto.decide.v1alpha1.decide_connect import DecideServiceClientSync
    from arcjet.rules import token_bucket

    decide_calls = {"count": 0}

    def allow_with_ttl(req):
        decide_calls["count"] += 1
        return mock_protobuf_modules["DecideResponse"](
            mock_protobuf_modules["Decision"](
                id="allow1",
                conclusion=mock_protobuf_modules["pb2"].CONCLUSION_ALLOW,
                ttl=10,
            )
        )

    monkeypatch.setattr(
        DecideServiceClientSync, "decide_behavior", allow_with_ttl, raising=False
    )

    aj = arcjet_sync(
        key="ajkey_test",
        rules=[token_bucket(refill_rate=1, interval=1, capacity=1)],
    )

    d1 = aj.protect({"headers": [], "type": "http"})
    assert d1.is_allowed()
    assert decide_calls["count"] == 1

    # Second call should NOT use cache — makes another API call
    d2 = aj.protect({"headers": [], "type": "http"})
    assert d2.is_allowed()
    assert decide_calls["count"] == 2


def test_should_not_cache_deny_result_without_ttl(
    mock_protobuf_modules,
    dev_environment,
    monkeypatch,
):
    """Test that a DENY decision with TTL = 0 is not cached.

    Second protect() call should make another API call.
    (JS: "should not cache a deny result w/o `ttl`")
    """
    from arcjet import arcjet_sync
    from arcjet.proto.decide.v1alpha1.decide_connect import DecideServiceClientSync
    from arcjet.rules import token_bucket

    decide_calls = {"count": 0}

    def deny_without_ttl(req):
        decide_calls["count"] += 1
        return mock_protobuf_modules["DecideResponse"](
            mock_protobuf_modules["Decision"](
                id="deny1",
                conclusion=mock_protobuf_modules["pb2"].CONCLUSION_DENY,
                ttl=0,
            )
        )

    monkeypatch.setattr(
        DecideServiceClientSync, "decide_behavior", deny_without_ttl, raising=False
    )

    aj = arcjet_sync(
        key="ajkey_test",
        rules=[token_bucket(refill_rate=1, interval=1, capacity=1)],
    )

    d1 = aj.protect({"headers": [], "type": "http"})
    assert d1.is_denied()
    assert decide_calls["count"] == 1

    # Second call should NOT use cache — makes another API call
    d2 = aj.protect({"headers": [], "type": "http"})
    assert d2.is_denied()
    assert decide_calls["count"] == 2


def test_should_not_cache_error_result_with_ttl(
    mock_protobuf_modules,
    dev_environment,
    monkeypatch,
):
    """Test that an ERROR decision with TTL > 0 is not cached.

    Only DENY decisions are cached, matching JS semantics.
    """
    from arcjet import arcjet_sync
    from arcjet.proto.decide.v1alpha1.decide_connect import DecideServiceClientSync
    from arcjet.rules import token_bucket

    decide_calls = {"count": 0}

    def error_with_ttl(req):
        decide_calls["count"] += 1
        return mock_protobuf_modules["DecideResponse"](
            mock_protobuf_modules["Decision"](
                id="err1",
                conclusion=mock_protobuf_modules["pb2"].CONCLUSION_ERROR,
                ttl=10,
            )
        )

    monkeypatch.setattr(
        DecideServiceClientSync, "decide_behavior", error_with_ttl, raising=False
    )

    aj = arcjet_sync(
        key="ajkey_test",
        rules=[token_bucket(refill_rate=1, interval=1, capacity=1)],
    )

    d1 = aj.protect({"headers": [], "type": "http"})
    assert d1.is_error()
    assert decide_calls["count"] == 1

    d2 = aj.protect({"headers": [], "type": "http"})
    assert d2.is_error()
    assert decide_calls["count"] == 2


# ---------------------------------------------------------------------------
# Async caching tests (same semantics, async client)
# ---------------------------------------------------------------------------


def test_async_should_cache_deny_result_with_ttl(
    mock_protobuf_modules,
    dev_environment,
    monkeypatch,
):
    """Test that async DENY with TTL > 0 is cached."""
    import asyncio

    from arcjet import arcjet
    from arcjet.proto.decide.v1alpha1.decide_connect import DecideServiceClient
    from arcjet.rules import token_bucket

    decide_calls = {"count": 0}

    def deny_with_ttl(req):
        decide_calls["count"] += 1
        return mock_protobuf_modules["DecideResponse"](
            mock_protobuf_modules["Decision"](
                id="deny1",
                conclusion=mock_protobuf_modules["pb2"].CONCLUSION_DENY,
                ttl=10,
            )
        )

    monkeypatch.setattr(
        DecideServiceClient, "decide_behavior", deny_with_ttl, raising=False
    )

    aj = arcjet(
        key="ajkey_test",
        rules=[token_bucket(refill_rate=1, interval=1, capacity=1)],
    )

    d1 = asyncio.run(aj.protect({"headers": [], "type": "http"}))
    assert d1.is_denied()
    assert decide_calls["count"] == 1

    d2 = asyncio.run(aj.protect({"headers": [], "type": "http"}))
    assert d2.is_denied()
    assert decide_calls["count"] == 1  # cached


def test_async_should_not_cache_allow_result_with_ttl(
    mock_protobuf_modules,
    dev_environment,
    monkeypatch,
):
    """Test that async ALLOW with TTL > 0 is not cached."""
    import asyncio

    from arcjet import arcjet
    from arcjet.proto.decide.v1alpha1.decide_connect import DecideServiceClient
    from arcjet.rules import token_bucket

    decide_calls = {"count": 0}

    def allow_with_ttl(req):
        decide_calls["count"] += 1
        return mock_protobuf_modules["DecideResponse"](
            mock_protobuf_modules["Decision"](
                id="allow1",
                conclusion=mock_protobuf_modules["pb2"].CONCLUSION_ALLOW,
                ttl=10,
            )
        )

    monkeypatch.setattr(
        DecideServiceClient, "decide_behavior", allow_with_ttl, raising=False
    )

    aj = arcjet(
        key="ajkey_test",
        rules=[token_bucket(refill_rate=1, interval=1, capacity=1)],
    )

    d1 = asyncio.run(aj.protect({"headers": [], "type": "http"}))
    assert d1.is_allowed()
    assert decide_calls["count"] == 1

    d2 = asyncio.run(aj.protect({"headers": [], "type": "http"}))
    assert d2.is_allowed()
    assert decide_calls["count"] == 2  # not cached
