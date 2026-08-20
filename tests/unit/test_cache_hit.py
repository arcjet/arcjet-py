"""Cache-hit isolation: remaining TTL, deep-copy, rate-limit reset rewrite."""

from __future__ import annotations

from arcjet._decision import Decision, materialize_cached_decision


def test_get_returns_remaining_ttl(mock_protobuf_modules):
    from arcjet._cache import DecisionCache
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    cache = DecisionCache()
    stored = Decision(
        decide_pb2.Decision(id="orig", conclusion=decide_pb2.CONCLUSION_DENY, ttl=60)
    )
    cache.set("k", stored, ttl_seconds=2)
    hit = cache.get("k")
    assert hit is not None
    decision, remaining = hit
    assert decision is stored
    assert 1 <= remaining <= 2


def test_materialize_does_not_mutate_cached_proto(mock_protobuf_modules):
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    proto = decide_pb2.Decision(
        id="orig", conclusion=decide_pb2.CONCLUSION_DENY, ttl=60
    )
    cached = Decision(proto)
    served = materialize_cached_decision(cached, remaining_ttl=12, request_id="lreq_x")

    assert served is not cached
    assert served.id == "lreq_x"
    assert served.ttl == 12
    assert cached.id == "orig"
    assert cached.ttl == 60
    served.to_proto().id = "mutated"
    assert cached.id == "orig"


def test_materialize_rewrites_rate_limit_reset(mock_protobuf_modules):
    from fixtures.protobuf_stubs import StubRateLimitReason

    from arcjet.proto.decide.v1alpha1 import decide_pb2

    rl = StubRateLimitReason(
        max=10, remaining=0, reset_in_seconds=60, window_in_seconds=60
    )
    proto = decide_pb2.Decision(
        id="orig",
        conclusion=decide_pb2.CONCLUSION_DENY,
        ttl=60,
        reason=decide_pb2.Reason(rate_limit=rl),  # type: ignore[arg-type]
    )
    cached = Decision(proto)
    served = materialize_cached_decision(cached, remaining_ttl=7, request_id="lreq_y")

    assert served.ttl == 7
    assert served.to_proto().reason.rate_limit.reset_in_seconds == 7
    assert cached.to_proto().reason.rate_limit.reset_in_seconds == 60


def test_protect_cache_hit_is_isolated(
    mock_protobuf_modules, dev_environment, monkeypatch
):
    from arcjet import arcjet_sync
    from arcjet._rules import Mode, token_bucket
    from arcjet.proto.decide.v1alpha1.decide_connect import DecideServiceClientSync

    def deny_with_ttl(_req):
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
        rules=[token_bucket(mode=Mode.LIVE, refill_rate=1, interval=1, capacity=1)],
    )
    d1 = aj.protect({"headers": [], "type": "http"})
    d2 = aj.protect({"headers": [], "type": "http"})

    assert d1.is_denied() and d2.is_denied()
    assert d1.id == "deny1"
    assert d2.id != d1.id
    assert d2.id.startswith("lreq_")
    assert d2.ttl <= 10
    d2.to_proto().id = "mutated-by-caller"
    assert d1.id == "deny1"


def test_async_protect_cache_hit_is_isolated(
    mock_protobuf_modules, dev_environment, monkeypatch
):
    import asyncio

    from arcjet import arcjet
    from arcjet._rules import Mode, token_bucket
    from arcjet.proto.decide.v1alpha1.decide_connect import DecideServiceClient

    def deny_with_ttl(_req):
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
        rules=[token_bucket(mode=Mode.LIVE, refill_rate=1, interval=1, capacity=1)],
    )

    async def _run() -> None:
        d1 = await aj.protect({"headers": [], "type": "http"})
        d2 = await aj.protect({"headers": [], "type": "http"})
        assert d1.is_denied() and d2.is_denied()
        assert d1.id == "deny1"
        assert d2.id != d1.id
        assert d2.id.startswith("lreq_")
        d2.to_proto().id = "mutated-by-caller"
        assert d1.id == "deny1"

    asyncio.run(_run())
