from __future__ import annotations

from arcjet.context import (
    extract_ip_from_headers,
    coerce_request_context,
    request_details_from_context,
    RequestContext,
)


def test_extract_ip_various_headers_and_dev_override(monkeypatch):
    # In development, X-Arcjet-Ip override wins
    headers = {"X-Arcjet-Ip": "10.0.0.1"}
    ip = extract_ip_from_headers(headers)
    assert ip == "10.0.0.1"

    # Global/public IP selection from x-forwarded-for (last trusted non-proxy)
    headers = {
        "x-forwarded-for": "10.0.0.2, 192.168.0.1, 8.8.8.8",
    }
    ip = extract_ip_from_headers(headers, proxies=["10.0.0.0/8", "192.168.0.0/16"])
    assert ip == "8.8.8.8"


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
