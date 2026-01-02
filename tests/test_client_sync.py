from __future__ import annotations

import types
import pytest

from arcjet import arcjet_sync
from arcjet._errors import ArcjetMisconfiguration, ArcjetTransportError
from arcjet.rules import token_bucket, validate_email
from arcjet.proto.decide.v1alpha1 import decide_pb2
from arcjet.proto.decide.v1alpha1.decide_connect import DecideServiceClientSync


def make_allow_decision(ttl: int = 0):
    return decide_pb2.Decision(
        id="d-allow", conclusion=decide_pb2.CONCLUSION_ALLOW, ttl=ttl
    )


def test_fail_open_false_raises(monkeypatch):
    # Configure client stub to raise on decide
    def raise_decide(req):
        raise RuntimeError("network down")

    # type: ignore[attr-defined]
    DecideServiceClientSync.decide_behavior = raise_decide

    aj = arcjet_sync(
        key="ajkey_x",
        rules=[token_bucket(refill_rate=1, interval=1, capacity=1)],
        fail_open=False,
    )
    with pytest.raises(ArcjetTransportError):
        aj.protect({"headers": [], "type": "http"})


def test_email_required_for_validate_email_rule():
    aj = arcjet_sync(key="ajkey_x", rules=[validate_email()])
    with pytest.raises(ArcjetMisconfiguration):
        aj.protect({"headers": [], "type": "http"})


def test_fail_open_true_allows(monkeypatch):
    def raise_decide(req):
        raise RuntimeError("boom")

    # type: ignore[attr-defined]
    DecideServiceClientSync.decide_behavior = raise_decide

    aj = arcjet_sync(
        key="ajkey_x",
        rules=[token_bucket(refill_rate=1, interval=1, capacity=1)],
        fail_open=True,
    )
    d = aj.protect({"headers": [], "type": "http"})
    assert d.is_allowed()
    assert d.reason.is_error()


def test_requested_default_and_characteristics_in_extra(monkeypatch):
    captured = {}

    def capture_decide(req):
        # Capture the decided extra fields for assertions
        captured["extra"] = dict(req.details.extra)
        return types.SimpleNamespace(
            HasField=lambda f: True, decision=make_allow_decision()
        )

    # type: ignore[attr-defined]
    DecideServiceClientSync.decide_behavior = capture_decide

    rules = [token_bucket(refill_rate=1, interval=1, capacity=1)]
    aj = arcjet_sync(key="ajkey_x", rules=rules)

    # No requested provided => defaults to 1 when token bucket rule present
    d = aj.protect({"headers": [], "type": "http"}, characteristics={"uid": "123"})
    assert captured["extra"]["requested"] == "1"
    assert captured["extra"]["uid"] == "123"


def test_caching_hits_trigger_background_report(monkeypatch):
    # First call returns decision with TTL so it will be cached
    calls = {"n": 0}

    def decide_once(req):
        calls["n"] += 1
        ttl = 60 if calls["n"] == 1 else 0
        return types.SimpleNamespace(
            HasField=lambda f: True, decision=make_allow_decision(ttl=ttl)
        )

    # type: ignore[attr-defined]
    DecideServiceClientSync.decide_behavior = decide_once

    rules = [token_bucket(refill_rate=1, interval=1, capacity=1)]
    aj = arcjet_sync(key="ajkey_x", rules=rules)

    ctx = {"type": "http", "headers": [(b"host", b"ex")], "client": ("203.0.113.5", 1)}
    d1 = aj.protect(ctx)
    d2 = aj.protect(ctx)

    # Only one decide call due to caching; a report should be scheduled for the cache hit
    # type: ignore[attr-defined]
    assert DecideServiceClientSync.decide_calls == 1
    # type: ignore[attr-defined]
    assert DecideServiceClientSync.report_calls >= 1
