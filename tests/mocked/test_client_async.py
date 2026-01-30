from __future__ import annotations

import types
import pytest

from arcjet import arcjet
from arcjet._errors import ArcjetMisconfiguration
from arcjet.rules import token_bucket
from arcjet.proto.decide.v1alpha1 import decide_pb2
from arcjet.proto.decide.v1alpha1.decide_connect import DecideServiceClient


def make_allow_decision(ttl: int = 0):
    return decide_pb2.Decision(
        id="d-allow", conclusion=decide_pb2.CONCLUSION_ALLOW, ttl=ttl
    )


@pytest.mark.asyncio
async def test_ip_override_with_request_ip(monkeypatch):
    """Test that request_ip parameter overrides automatic IP detection."""
    captured = {}

    async def capture_decide(req):
        # Capture the IP from the request details
        captured["ip"] = req.details.ip
        return types.SimpleNamespace(
            HasField=lambda f: True, decision=make_allow_decision()
        )

    # type: ignore[attr-defined]
    DecideServiceClient.decide_behavior = capture_decide

    rules = [token_bucket(refill_rate=1, interval=1, capacity=1)]
    aj = arcjet(key="ajkey_x", rules=rules)

    # Provide request_ip to override automatic detection
    ctx = {"type": "http", "headers": [], "client": ("192.168.1.1", 1)}
    d = await aj.protect(ctx, request_ip="203.0.113.42")
    
    # Verify the overridden IP was used
    assert captured["ip"] == "203.0.113.42"
    assert d.is_allowed()


@pytest.mark.asyncio
async def test_disable_automatic_ip_detection_requires_request_ip():
    """Test that when disable_automatic_ip_detection=True, request_ip is required."""
    rules = [token_bucket(refill_rate=1, interval=1, capacity=1)]
    aj = arcjet(
        key="ajkey_x", 
        rules=rules, 
        disable_automatic_ip_detection=True
    )

    # Should raise error when request_ip is not provided
    with pytest.raises(ArcjetMisconfiguration, match="request_ip is required"):
        await aj.protect({"headers": [], "type": "http"})


@pytest.mark.asyncio
async def test_disable_automatic_ip_detection_with_request_ip(monkeypatch):
    """Test that disable_automatic_ip_detection works with request_ip."""
    captured = {}

    async def capture_decide(req):
        # Capture the IP from the request details
        captured["ip"] = req.details.ip
        return types.SimpleNamespace(
            HasField=lambda f: True, decision=make_allow_decision()
        )

    # type: ignore[attr-defined]
    DecideServiceClient.decide_behavior = capture_decide

    rules = [token_bucket(refill_rate=1, interval=1, capacity=1)]
    aj = arcjet(
        key="ajkey_x", 
        rules=rules, 
        disable_automatic_ip_detection=True
    )

    # Provide request_ip as required when automatic detection is disabled
    d = await aj.protect({"headers": [], "type": "http"}, request_ip="198.51.100.5")
    
    # Verify the provided IP was used
    assert captured["ip"] == "198.51.100.5"
    assert d.is_allowed()
