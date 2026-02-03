from __future__ import annotations

import types

import pytest

from arcjet import arcjet
from arcjet._errors import ArcjetMisconfiguration, ArcjetTransportError
from arcjet.proto.decide.v1alpha1 import decide_pb2
from arcjet.proto.decide.v1alpha1.decide_connect import DecideServiceClient
from arcjet.rules import token_bucket, validate_email


def make_allow_decision(ttl: int = 0):
    return decide_pb2.Decision(
        id="d-allow", conclusion=decide_pb2.CONCLUSION_ALLOW, ttl=ttl
    )


def test_fail_open_false_raises(monkeypatch):
    def raise_decide(req):
        raise RuntimeError("network down")

    DecideServiceClient.decide_behavior = raise_decide  # type: ignore[attr-defined]
    aj = arcjet(
        key="ajkey_x",
        rules=[token_bucket(refill_rate=1, interval=1, capacity=1)],
        fail_open=False,
    )
    with pytest.raises(ArcjetTransportError):
        import asyncio

        asyncio.run(aj.protect({"headers": [], "type": "http"}))


def test_email_required_for_validate_email_rule():
    aj = arcjet(key="ajkey_x", rules=[validate_email()])
    import asyncio

    with pytest.raises(ArcjetMisconfiguration):
        asyncio.run(aj.protect({"headers": [], "type": "http"}))


def test_fail_open_true_allows(monkeypatch):
    def raise_decide(req):
        raise RuntimeError("boom")

    DecideServiceClient.decide_behavior = raise_decide  # type: ignore[attr-defined]
    aj = arcjet(
        key="ajkey_x",
        rules=[token_bucket(refill_rate=1, interval=1, capacity=1)],
        fail_open=True,
    )
    import asyncio

    d = asyncio.run(aj.protect({"headers": [], "type": "http"}))
    assert d.is_allowed()
    assert d.reason.is_error()


def test_requested_default_and_characteristics_in_extra(monkeypatch):
    captured = {}

    def capture_decide(req):
        captured["extra"] = dict(req.details.extra)
        return types.SimpleNamespace(
            HasField=lambda f: True, decision=make_allow_decision()
        )

    DecideServiceClient.decide_behavior = capture_decide  # type: ignore[attr-defined]
    rules = [token_bucket(refill_rate=1, interval=1, capacity=1)]
    aj = arcjet(key="ajkey_x", rules=rules)
    import asyncio

    d = asyncio.run(
        aj.protect({"headers": [], "type": "http"}, characteristics={"uid": "123"})
    )
    assert captured["extra"]["requested"] == "1"
    assert captured["extra"]["uid"] == "123"


def test_ip_override_with_ip_src(monkeypatch):
    captured = {}

    def capture_decide(req):
        captured["ip"] = req.details.ip
        return types.SimpleNamespace(
            HasField=lambda f: True, decision=make_allow_decision()
        )

    DecideServiceClient.decide_behavior = capture_decide  # type: ignore[attr-defined]
    rules = [token_bucket(refill_rate=1, interval=1, capacity=1)]
    aj = arcjet(key="ajkey_x", rules=rules, disable_automatic_ip_detection=True)
    import asyncio

    ctx = {
        "type": "http",
        "headers": [("x-forwarded-for", "1.1.1.1")],
        "client": ("1.1.1.1", 12345),
    }
    d = asyncio.run(aj.protect(ctx, ip_src="8.8.8.8"))
    assert captured["ip"] == "8.8.8.8"
    assert d.is_allowed()


def test_disable_automatic_ip_detection_requires_ip_src():
    rules = [token_bucket(refill_rate=1, interval=1, capacity=1)]
    aj = arcjet(key="ajkey_x", rules=rules, disable_automatic_ip_detection=True)
    import asyncio

    with pytest.raises(ArcjetMisconfiguration, match="ip_src is required"):
        asyncio.run(aj.protect({"headers": [], "type": "http"}))


def test_disable_automatic_ip_detection_with_proxies():
    rules = [token_bucket(refill_rate=1, interval=1, capacity=1)]
    aj = arcjet(
        key="ajkey_x",
        rules=rules,
        disable_automatic_ip_detection=True,
        proxies=["3.3.3.3"],
    )
    import asyncio

    with pytest.raises(ArcjetMisconfiguration, match="proxies cannot be used"):
        asyncio.run(aj.protect({"headers": [], "type": "http"}, ip_src="8.8.8.8"))


def test_ip_src_disallowed_when_automatic_ip_detection_enabled():
    rules = [token_bucket(refill_rate=1, interval=1, capacity=1)]
    aj = arcjet(
        key="ajkey_x",
        rules=rules,
    )
    import asyncio

    with pytest.raises(ArcjetMisconfiguration, match="ip_src cannot be set"):
        asyncio.run(aj.protect({"headers": [], "type": "http"}, ip_src="8.8.8.8"))
