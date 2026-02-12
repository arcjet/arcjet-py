"""Tests for request context handling and IP extraction."""

from __future__ import annotations

import pytest

from arcjet.context import (
    RequestContext,
    coerce_request_context,
    extract_ip_from_headers,
    request_details_from_context,
)


def test_extract_ip_xff_skips_trusted_proxy_literal():
    """Test that IP extraction skips literal trusted proxy addresses."""
    headers = {"x-forwarded-for": "1.1.1.1, 2.2.2.2, 3.3.3.3"}
    assert extract_ip_from_headers(headers, proxies=["3.3.3.3"]) == "2.2.2.2"


def test_extract_ip_xff_skips_trusted_proxy_cidr():
    """Test that IP extraction skips CIDR-matched trusted proxy addresses."""
    headers = {"x-forwarded-for": "1.1.1.1, 2.2.2.2, 3.3.3.3"}
    assert extract_ip_from_headers(headers, proxies=["3.3.3.3/32"]) == "2.2.2.2"


def test_extract_ip_xff_skips_multiple_trusted_proxies():
    """Test that IP extraction skips multiple trusted proxy addresses."""
    headers = {"x-forwarded-for": "1.1.1.1, 2.2.2.2, 3.3.3.3"}
    assert extract_ip_from_headers(headers, proxies=["3.3.3.3", "2.2.2.2"]) == "1.1.1.1"


def test_extract_ip_xff_ignores_invalid_proxy_entries():
    """Test that invalid proxy entries don't break IP extraction."""
    headers = {"x-forwarded-for": "1.1.1.1, 2.2.2.2, 3.3.3.3"}
    assert extract_ip_from_headers(headers, proxies=[1234]) == "3.3.3.3"  # type: ignore


def test_extract_ip_dev_override_wins():
    """Test that X-Arcjet-Ip header provides override for development."""
    headers = {"X-Arcjet-Ip": "10.0.0.1"}
    assert extract_ip_from_headers(headers) == "10.0.0.1"


def test_extract_ip_xff_picks_rightmost_global_ip():
    """Test that rightmost global IP is selected from X-Forwarded-For."""
    headers = {"x-forwarded-for": "9.9.9.9, 8.8.8.8"}
    assert extract_ip_from_headers(headers) == "8.8.8.8"


def test_extract_ip_xff_picks_rightmost_global_minus_trusted_proxies():
    """Test IP selection with private IPs in X-Forwarded-For."""
    headers = {"x-forwarded-for": "8.8.8.8, 192.168.0.1, 10.0.0.2"}
    # No trusted proxies => rightmost global is 8.8.8.8 (since others are private)
    assert extract_ip_from_headers(headers) == "8.8.8.8"


def test_extract_ip_xff_skips_trailing_private_then_uses_previous_global():
    """Test that trailing private IPs are skipped in favor of previous global IP."""
    headers = {"x-forwarded-for": "1.1.1.1, 2.2.2.2, 127.0.0.1"}
    assert extract_ip_from_headers(headers) == "2.2.2.2"


def test_extract_ip_xff_all_trusted_returns_none():
    """Test that all-trusted-proxy chain returns None."""
    headers = {"x-forwarded-for": "192.168.0.1, 10.0.0.2"}
    ip = extract_ip_from_headers(
        headers,
        proxies=["10.0.0.0/8", "192.168.0.0/16"],
    )
    assert ip is None


def test_extract_ip_multiple_xff_headers_are_combined_in_order():
    """Test that multiple X-Forwarded-For headers are combined correctly."""
    # MDN: multiple X-Forwarded-For headers must be treated as a single list
    headers = {
        "x-forwarded-for": [
            "10.0.0.1, 192.168.0.1",  # first header value
            "8.8.8.8, 1.1.1.1",  # second header value
        ]
    }

    # With no trusted proxies, should pick the last global IP: 1.1.1.1
    assert extract_ip_from_headers(headers) == "1.1.1.1"


def test_extract_ip_xff_ipv4_with_port_is_returned_without_port():
    """Test that port numbers are stripped from IPv4 addresses."""
    headers = {"x-forwarded-for": "1.1.1.1:443"}
    assert extract_ip_from_headers(headers) == "1.1.1.1"


def test_extract_ip_xff_ported_ipv4_is_matched_by_cidr_proxy():
    """Test that ported IPs are matched by CIDR proxy configuration."""
    headers = {"x-forwarded-for": "9.9.9.9, 1.1.1.1:443"}
    assert extract_ip_from_headers(headers, proxies=["1.1.1.1/32"]) == "9.9.9.9"


def test_extract_ip_xff_ignores_junk_and_whitespace():
    """Test that junk values and whitespace are handled gracefully."""
    headers = {"x-forwarded-for": "  , 8.8.8.8 , garbage , 192.168.0.1 "}
    assert (
        extract_ip_from_headers(
            headers,
            proxies=["192.168.0.0/16"],
        )
        == "8.8.8.8"
    )


def test_extract_ip_rejects_shared_address_space_100_64_0_0_10():
    """Test that shared address space (100.64.0.0/10) is rejected."""
    headers = {"x-forwarded-for": "1.1.1.1, 100.64.0.1"}
    assert extract_ip_from_headers(headers) == "1.1.1.1"


def test_extract_ip_rejects_benchmarking_198_18_0_0_15():
    """Test that benchmarking address range (198.18.0.0/15) is rejected."""
    headers = {"x-forwarded-for": "1.1.1.1, 198.18.0.1"}
    assert extract_ip_from_headers(headers) == "1.1.1.1"


def test_coerce_asgi_scope_and_plain_mapping():
    """Test that both ASGI scopes and plain mappings can be coerced to context."""
    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "https",
        "path": "/a",
        "headers": [(b"Host", b"example.com"), (b"Cookie", b"k=v")],
        "client": ("8.8.8.8", 12345),
        "query_string": b"q=1",
    }
    ctx = coerce_request_context(scope)
    assert ctx.ip == "8.8.8.8"
    assert ctx.method == "GET"
    assert ctx.host == "example.com"
    assert ctx.cookies == "k=v"

    mapping = {
        "ip": "203.0.113.7",
        "method": "POST",
        "headers": {"X": "Y"},
    }
    ctx2 = coerce_request_context(mapping)
    assert ctx2.ip == "203.0.113.7"
    assert ctx2.method == "POST"
    assert ctx2.headers["X"] == "Y"


def test_request_details_from_context_normalizes_headers_and_extra():
    """Test that request details normalize headers and extra fields."""
    ctx = RequestContext(
        ip="203.0.113.6",
        method="GET",
        protocol="https",
        host="ex",
        path="/p",
        headers={"X-FOO": "Bar"},
        extra={"k": "v"},
    )
    d = request_details_from_context(ctx)
    assert d.ip == "203.0.113.6"
    assert d.headers["x-foo"] == "Bar"
    assert d.extra["k"] == "v"


def test_request_details_from_context_normalizes_query_string():
    """Test that query strings are normalized with leading '?' for decide server.
    
    Decide server expects query string to include the leading '?' while
    RequestContext explicitly excludes it from the `query` field.
    """
    ctx = RequestContext(
        ip="203.0.113.6",
        method="GET",
        protocol="https",
        host="ex",
        path="/p",
        query="a=1&b=2",
    )
    d = request_details_from_context(ctx)
    assert d.ip == "203.0.113.6"
    assert d.query == "?a=1&b=2"
