from __future__ import annotations

import pytest

from arcjet import arcjet
from arcjet._errors import ArcjetMisconfiguration, ArcjetTransportError
from arcjet.proto.decide.v1alpha1.decide_connect import DecideServiceClient
from arcjet.rules import token_bucket, validate_email

from .conftest import (
    capture_request_field,
    make_allow_decision,
    make_basic_http_context,
    make_decide_response,
)


@pytest.mark.asyncio
async def test_fail_open_false_raises():
    """Test that fail_open=False raises ArcjetTransportError on network failures."""

    def raise_decide(req):
        raise RuntimeError("network down")

    DecideServiceClient.decide_behavior = raise_decide  # type: ignore[attr-defined]
    aj = arcjet(
        key="ajkey_x",
        rules=[token_bucket(refill_rate=1, interval=1, capacity=1)],
        fail_open=False,
    )
    with pytest.raises(ArcjetTransportError):
        await aj.protect({"headers": [], "type": "http"})


@pytest.mark.asyncio
async def test_email_required_for_validate_email_rule():
    """Test that validate_email rule requires email in context."""
    aj = arcjet(key="ajkey_x", rules=[validate_email()])

    with pytest.raises(ArcjetMisconfiguration):
        await aj.protect({"headers": [], "type": "http"})


@pytest.mark.asyncio
async def test_fail_open_true_allows():
    """Test that fail_open=True returns allowed decision on network failures."""

    def raise_decide(req):
        raise RuntimeError("boom")

    DecideServiceClient.decide_behavior = raise_decide  # type: ignore[attr-defined]
    aj = arcjet(
        key="ajkey_x",
        rules=[token_bucket(refill_rate=1, interval=1, capacity=1)],
        fail_open=True,
    )

    d = await aj.protect({"headers": [], "type": "http"})
    assert d.is_allowed()
    assert d.reason.is_error()


@pytest.mark.asyncio
async def test_requested_default_and_characteristics_in_extra():
    """Test that characteristics are passed in the extra field of the request."""
    capture_decide, captured = capture_request_field("details")
    DecideServiceClient.decide_behavior = capture_decide  # type: ignore[attr-defined]

    rules = [token_bucket(refill_rate=1, interval=1, capacity=1)]
    aj = arcjet(key="ajkey_x", rules=rules)

    d = await aj.protect(
        {"headers": [], "type": "http"}, characteristics={"uid": "123"}
    )
    assert captured["extra"]["requested"] == "1"
    assert captured["extra"]["uid"] == "123"


@pytest.mark.asyncio
async def test_ip_override_with_ip_src():
    """Test that ip_src parameter overrides automatic IP detection."""
    capture_decide, captured = capture_request_field("details")
    DecideServiceClient.decide_behavior = capture_decide  # type: ignore[attr-defined]

    rules = [token_bucket(refill_rate=1, interval=1, capacity=1)]
    aj = arcjet(key="ajkey_x", rules=rules, disable_automatic_ip_detection=True)

    ctx = make_basic_http_context(
        headers=[("x-forwarded-for", "1.1.1.1")], client=("1.1.1.1", 12345)
    )
    d = await aj.protect(ctx, ip_src="8.8.8.8")
    assert captured["ip"] == "8.8.8.8"
    assert d.is_allowed()


@pytest.mark.asyncio
async def test_disable_automatic_ip_detection_requires_ip_src():
    """Test that disable_automatic_ip_detection requires ip_src to be provided."""
    rules = [token_bucket(refill_rate=1, interval=1, capacity=1)]
    aj = arcjet(key="ajkey_x", rules=rules, disable_automatic_ip_detection=True)

    with pytest.raises(ArcjetMisconfiguration, match="ip_src is required"):
        await aj.protect({"headers": [], "type": "http"})


@pytest.mark.asyncio
async def test_disable_automatic_ip_detection_with_proxies():
    """Test that disable_automatic_ip_detection conflicts with proxies."""
    rules = [token_bucket(refill_rate=1, interval=1, capacity=1)]
    aj = arcjet(
        key="ajkey_x",
        rules=rules,
        disable_automatic_ip_detection=True,
        proxies=["3.3.3.3"],
    )

    with pytest.raises(ArcjetMisconfiguration, match="proxies cannot be used"):
        await aj.protect({"headers": [], "type": "http"}, ip_src="8.8.8.8")


@pytest.mark.asyncio
async def test_ip_src_disallowed_when_automatic_ip_detection_enabled():
    """Test that ip_src cannot be set when automatic IP detection is enabled."""
    rules = [token_bucket(refill_rate=1, interval=1, capacity=1)]
    aj = arcjet(
        key="ajkey_x",
        rules=rules,
    )

    with pytest.raises(ArcjetMisconfiguration, match="ip_src cannot be set"):
        await aj.protect({"headers": [], "type": "http"}, ip_src="8.8.8.8")
