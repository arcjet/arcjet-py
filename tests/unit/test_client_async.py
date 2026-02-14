"""Unit tests for async client functionality.

Tests the async protect() behavior without requiring real protobuf dependencies.
"""

from __future__ import annotations

import pytest


def test_fail_open_false_raises(mock_protobuf_modules, monkeypatch: pytest.MonkeyPatch):
    """Test that fail_open=False raises ArcjetTransportError on network error."""
    from arcjet import arcjet
    from arcjet._errors import ArcjetTransportError
    from arcjet.proto.decide.v1alpha1.decide_connect import DecideServiceClient
    from arcjet.rules import token_bucket

    def raise_decide(req):
        raise RuntimeError("network down")

    monkeypatch.setattr(
        DecideServiceClient, "decide_behavior", raise_decide, raising=False
    )
    aj = arcjet(
        key="ajkey_x",
        rules=[token_bucket(refill_rate=1, interval=1, capacity=1)],
        fail_open=False,
    )
    with pytest.raises(ArcjetTransportError):
        import asyncio

        asyncio.run(aj.protect({"headers": [], "type": "http"}))


def test_email_required_for_validate_email_rule(mock_protobuf_modules):
    """Test that validate_email rule raises error when email is missing."""
    from arcjet import arcjet
    from arcjet._errors import ArcjetMisconfiguration
    from arcjet.rules import validate_email

    aj = arcjet(key="ajkey_x", rules=[validate_email()])
    import asyncio

    with pytest.raises(ArcjetMisconfiguration):
        asyncio.run(aj.protect({"headers": [], "type": "http"}))


def test_fail_open_true_allows(mock_protobuf_modules, monkeypatch: pytest.MonkeyPatch):
    """Test that fail_open=True allows request on network error."""
    from arcjet import arcjet
    from arcjet.proto.decide.v1alpha1.decide_connect import DecideServiceClient
    from arcjet.rules import token_bucket

    def raise_decide(req):
        raise RuntimeError("boom")

    monkeypatch.setattr(
        DecideServiceClient, "decide_behavior", raise_decide, raising=False
    )
    aj = arcjet(
        key="ajkey_x",
        rules=[token_bucket(refill_rate=1, interval=1, capacity=1)],
        fail_open=True,
    )
    import asyncio

    d = asyncio.run(aj.protect({"headers": [], "type": "http"}))
    assert d.is_allowed()
    with pytest.warns(DeprecationWarning, match="Use `reason_v2` property instead"):
        assert d.reason.is_error()


def test_requested_default_and_characteristics_in_extra(
    mock_protobuf_modules,
    make_allow_decision,
    dev_environment,
    monkeypatch: pytest.MonkeyPatch,
):
    """Test that requested default and characteristics are passed in extra metadata."""
    from arcjet import arcjet
    from arcjet.proto.decide.v1alpha1.decide_connect import DecideServiceClient
    from arcjet.rules import token_bucket

    captured = {}

    def capture_decide(req):
        captured["extra"] = dict(req.details.extra)
        decision = make_allow_decision()
        return mock_protobuf_modules["DecideResponse"](decision)

    monkeypatch.setattr(
        DecideServiceClient, "decide_behavior", capture_decide, raising=False
    )
    rules = [token_bucket(refill_rate=1, interval=1, capacity=1)]
    aj = arcjet(key="ajkey_x", rules=rules)
    import asyncio

    asyncio.run(
        aj.protect({"headers": [], "type": "http"}, characteristics={"uid": "123"})
    )
    assert captured["extra"]["requested"] == "1"
    assert captured["extra"]["uid"] == "123"


def test_ip_override_with_ip_src(
    mock_protobuf_modules,
    make_allow_decision,
    dev_environment,
    monkeypatch: pytest.MonkeyPatch,
):
    """Test that ip_src overrides automatic IP detection when configured."""
    from arcjet import arcjet
    from arcjet.proto.decide.v1alpha1.decide_connect import DecideServiceClient
    from arcjet.rules import token_bucket

    captured = {}

    def capture_decide(req):
        captured["ip"] = req.details.ip
        decision = make_allow_decision()
        return mock_protobuf_modules["DecideResponse"](decision)

    monkeypatch.setattr(
        DecideServiceClient, "decide_behavior", capture_decide, raising=False
    )
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


def test_disable_automatic_ip_detection_requires_ip_src(mock_protobuf_modules):
    """Test that ip_src is required when automatic IP detection is disabled."""
    from arcjet import arcjet
    from arcjet._errors import ArcjetMisconfiguration
    from arcjet.rules import token_bucket

    rules = [token_bucket(refill_rate=1, interval=1, capacity=1)]
    aj = arcjet(key="ajkey_x", rules=rules, disable_automatic_ip_detection=True)
    import asyncio

    with pytest.raises(ArcjetMisconfiguration, match="ip_src is required"):
        asyncio.run(aj.protect({"headers": [], "type": "http"}))


def test_disable_automatic_ip_detection_with_proxies(mock_protobuf_modules):
    """Test that proxies cannot be used with manual IP detection."""
    from arcjet import arcjet
    from arcjet._errors import ArcjetMisconfiguration
    from arcjet.rules import token_bucket

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


def test_ip_src_disallowed_when_automatic_ip_detection_enabled(mock_protobuf_modules):
    """Test that ip_src cannot be used when automatic IP detection is enabled."""
    from arcjet import arcjet
    from arcjet._errors import ArcjetMisconfiguration
    from arcjet.rules import token_bucket

    rules = [token_bucket(refill_rate=1, interval=1, capacity=1)]
    aj = arcjet(
        key="ajkey_x",
        rules=rules,
    )
    import asyncio

    with pytest.raises(ArcjetMisconfiguration, match="ip_src cannot be set"):
        asyncio.run(aj.protect({"headers": [], "type": "http"}, ip_src="8.8.8.8"))


def test_base_url_trailing_slash_is_stripped(mock_protobuf_modules):
    """Test that base_url parameter strips trailing slashes."""
    from arcjet import arcjet
    from arcjet.rules import token_bucket

    # Create client with trailing slash in base_url
    aj = arcjet(
        key="ajkey_x",
        rules=[token_bucket(refill_rate=1, interval=1, capacity=1)],
        base_url="https://example.com/",
    )
    # Access the internal client to verify the base_url
    assert getattr(aj._client, "base_url") == "https://example.com"


def test_base_url_multiple_trailing_slashes_are_stripped(mock_protobuf_modules):
    """Test that base_url parameter strips multiple trailing slashes."""
    from arcjet import arcjet
    from arcjet.rules import token_bucket

    # Create client with multiple trailing slashes
    aj = arcjet(
        key="ajkey_x",
        rules=[token_bucket(refill_rate=1, interval=1, capacity=1)],
        base_url="https://example.com///",
    )
    # Access the internal client to verify the base_url
    assert getattr(aj._client, "base_url") == "https://example.com"


def test_base_url_without_trailing_slash_unchanged(mock_protobuf_modules):
    """Test that base_url without trailing slash is unchanged."""
    from arcjet import arcjet
    from arcjet.rules import token_bucket

    # Create client without trailing slash
    aj = arcjet(
        key="ajkey_x",
        rules=[token_bucket(refill_rate=1, interval=1, capacity=1)],
        base_url="https://example.com",
    )
    # Access the internal client to verify the base_url
    assert getattr(aj._client, "base_url") == "https://example.com"


def test_default_base_url_from_env_trailing_slash_is_stripped(
    mock_protobuf_modules, monkeypatch: pytest.MonkeyPatch
):
    """Test DEFAULT_BASE_URL strips trailing slash from ARCJET_BASE_URL env var."""
    import importlib

    import arcjet.client as client_module
    from arcjet.rules import token_bucket

    with monkeypatch.context() as m:
        m.setenv("ARCJET_BASE_URL", "https://example.com/")
        reloaded_module = importlib.reload(client_module)
        aj = reloaded_module.arcjet(
            key="ajkey_x",
            rules=[token_bucket(refill_rate=1, interval=1, capacity=1)],
        )
        assert getattr(aj._client, "base_url") == "https://example.com"

    importlib.reload(client_module)
