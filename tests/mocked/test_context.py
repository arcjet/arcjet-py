from __future__ import annotations

from arcjet.context import (
    extract_ip_from_headers,
    coerce_request_context,
    request_details_from_context,
    RequestContext,
)


import pytest


def test_extract_ip_xff_skips_trusted_proxy_literal():
    headers = {"x-forwarded-for": "1.1.1.1, 2.2.2.2, 3.3.3.3"}
    assert extract_ip_from_headers(headers, proxies=["3.3.3.3"]) == "2.2.2.2"


def test_extract_ip_xff_skips_trusted_proxy_cidr():
    headers = {"x-forwarded-for": "1.1.1.1, 2.2.2.2, 3.3.3.3"}
    assert extract_ip_from_headers(headers, proxies=["3.3.3.3/32"]) == "2.2.2.2"


def test_extract_ip_xff_skips_multiple_trusted_proxies():
    headers = {"x-forwarded-for": "1.1.1.1, 2.2.2.2, 3.3.3.3"}
    assert extract_ip_from_headers(headers, proxies=["3.3.3.3", "2.2.2.2"]) == "1.1.1.1"


def test_extract_ip_xff_ignores_invalid_proxy_entries():
    headers = {"x-forwarded-for": "1.1.1.1, 2.2.2.2, 3.3.3.3"}
    assert extract_ip_from_headers(headers, proxies=[1234]) == "3.3.3.3"  # type: ignore


def test_extract_ip_dev_override_wins(monkeypatch):
    headers = {"X-Arcjet-Ip": "10.0.0.1"}
    assert extract_ip_from_headers(headers) == "10.0.0.1"


def test_extract_ip_xff_picks_rightmost_global_ip():
    headers = {"x-forwarded-for": "9.9.9.9, 8.8.8.8"}
    assert extract_ip_from_headers(headers) == "8.8.8.8"


def test_extract_ip_xff_picks_rightmost_global_minus_trusted_proxies():
    headers = {"x-forwarded-for": "8.8.8.8, 192.168.0.1, 10.0.0.2"}
    # No trusted proxies => rightmost global is 8.8.8.8 (since others are private anyway)
    assert extract_ip_from_headers(headers) == "8.8.8.8"


def test_extract_ip_xff_skips_trailing_private_then_uses_previous_global():
    headers = {"x-forwarded-for": "1.1.1.1, 2.2.2.2, 127.0.0.1"}
    assert extract_ip_from_headers(headers) == "2.2.2.2"


def test_extract_ip_xff_all_trusted_returns_none():
    headers = {"x-forwarded-for": "192.168.0.1, 10.0.0.2"}
    ip = extract_ip_from_headers(
        headers,
        proxies=["10.0.0.0/8", "192.168.0.0/16"],
    )
    assert ip is None


def test_extract_ip_multiple_xff_headers_are_combined_in_order():
    # MDN: multiple X-Forwarded-For headers must be treated as a single list.
    # Simulate multiple header instances via a list value (common
    # representation).
    headers = {
        "x-forwarded-for": [
            "10.0.0.1, 192.168.0.1",  # first header value
            "8.8.8.8, 1.1.1.1",  # second header value
        ]
    }

    # With no trusted proxies configured, Arcjet-style selection walks from the
    # end of the combined list, so it should pick the last global IP: 1.1.1.1
    assert extract_ip_from_headers(headers) == "1.1.1.1"


def test_extract_ip_xff_ipv4_with_port_is_returned_without_port():
    headers = {"x-forwarded-for": "1.1.1.1:443"}
    assert extract_ip_from_headers(headers) == "1.1.1.1"


def test_extract_ip_xff_ported_ipv4_is_matched_by_cidr_proxy():
    headers = {"x-forwarded-for": "9.9.9.9, 1.1.1.1:443"}
    assert extract_ip_from_headers(headers, proxies=["1.1.1.1/32"]) == "9.9.9.9"


def test_extract_ip_xff_ignores_junk_and_whitespace():
    headers = {"x-forwarded-for": "  , 8.8.8.8 , garbage , 192.168.0.1 "}
    assert (
        extract_ip_from_headers(
            headers,
            proxies=["192.168.0.0/16"],
        )
        == "8.8.8.8"
    )


def test_extract_ip_rejects_shared_address_space_100_64_0_0_10():
    headers = {"x-forwarded-for": "1.1.1.1, 100.64.0.1"}
    assert extract_ip_from_headers(headers) == "1.1.1.1"


def test_extract_ip_rejects_benchmarking_198_18_0_0_15():
    headers = {"x-forwarded-for": "1.1.1.1, 198.18.0.1"}
    assert extract_ip_from_headers(headers) == "1.1.1.1"


def test_coerce_asgi_scope_and_plain_mapping(monkeypatch):
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
    """
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
