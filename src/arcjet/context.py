"""Arcjet request context utilities.

This module provides a lightweight, framework-agnostic way to describe an HTTP
request (`RequestContext`) and helpers to extract/normalize request details from
common Python web frameworks (ASGI/Starlette/FastAPI, Flask/Werkzeug, Django).

Key pieces:
- `RequestContext`: The minimal, serializable shape Arcjet needs to make
    decisions.
- `coerce_request_context(...)`: Best-effort conversion from various request
    objects to `RequestContext` with sensible defaults during development.
- `request_details_from_context(...)`: Converts a `RequestContext` to the
    protobuf type expected by the Decide API.
- `extract_ip_from_headers(...)`: Derives a client IP using standard proxy
    headers; honors a development override for testing.

Environment behavior:
- If `ARCJET_ENV=development`, a missing IP is defaulted to `127.0.0.1` and the
    header `X-Arcjet-Ip` may be used to force an IP for local testing.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Any, Iterable, Mapping, Protocol, Sequence
import ipaddress

from proto.decide.v1alpha1 import decide_pb2


def _is_development() -> bool:
    """Return True when running in development mode.

    We consider the environment to be development when `ARCJET_ENV` is set to
    "development" (case-insensitive). Defaults to production otherwise.
    """
    env = (os.getenv("ARCJET_ENV") or "production").lower()
    return env == "development"


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Minimal request context Arcjet needs.

    Build this directly or let `coerce_request_context` derive it from common
    framework request objects. Only fields you have matter; everything is
    optional, but more context generally improves decision quality.

    Fields:
    - ip: Client IP address (string). If omitted during development, a
        default of `127.0.0.1` will be used.
    - method: HTTP method (e.g., "GET").
    - protocol: URL scheme (e.g., "http" or "https").
    - host: Value of the `Host` header.
    - path: Request path component (e.g., "/login").
    - headers: Mapping of request headers.
    - cookies: Raw `Cookie` header value.
    - query: Raw query string without leading `?`.
    - body: Raw request body bytes if available.
    - email: User email for email validation rule.
    - extra: Additional key/value metadata to be forwarded to the Decide API.
    """

    ip: str | None = None
    method: str | None = None
    protocol: str | None = None
    host: str | None = None
    path: str | None = None
    headers: Mapping[str, str] | None = None
    cookies: str | None = None
    query: str | None = None
    body: bytes | None = None
    email: str | None = None
    extra: Mapping[str, str] | None = None


class SupportsRequestContext(Protocol):
    """Protocol for request-like objects that Arcjet can coerce.

    This captures a minimal set of attributes commonly present across popular
    frameworks. It's used to aid type checkers and IDEs; runtime coercion still
    uses duck-typing with careful defensive access.
    """

    headers: Mapping[str, str]
    method: str
    # Optional/duck-typed fields; Protocol does not enforce at runtime.
    # Present in ASGI scope: `type`, `path`, `scheme`, `client`, `query_string`.


def _first_header(headers: Mapping[str, str], *names: str) -> str | None:
    """Return the first matching header value from `headers`.

    Matching is case-insensitive and respects the order of `names`.
    """
    for n in names:
        for k, v in headers.items():
            if k.lower() == n.lower():
                return v
    return None


def _normalize_ip_string(value: str | None) -> str | None:
    """Normalize an IP string possibly containing ports/brackets.

    Examples accepted:
    - "203.0.113.5"
    - "203.0.113.5:8080" -> "203.0.113.5"
    - "[2001:db8::1]" -> "2001:db8::1"
    - "[2001:db8::1]:8080" -> "2001:db8::1"
    """
    if not value:
        return None
    s = value.strip()
    if not s:
        return None
    # Bracketed IPv6 with optional port
    if s.startswith("["):
        rb = s.find("]")
        if rb != -1:
            return s[1:rb]
    # IPv4 with port
    if s.count(":") == 1 and s.count(".") == 3:
        host, port = s.split(":", 1)
        if port.isdigit():
            return host
    return s


def _parse_proxies(
    proxies: Iterable[str] | None,
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    out: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    if not proxies:
        return out
    for p in proxies:
        try:
            # Support CIDR or single IP; strict=False allows single IPs.
            net = ipaddress.ip_network(p, strict=False)
            out.append(net)
        except Exception:
            continue
    return out


def _is_trusted_proxy(
    ip_str: str | None, proxies: list[ipaddress.IPv4Network | ipaddress.IPv6Network]
) -> bool:
    ip_norm = _normalize_ip_string(ip_str or "")
    if not ip_norm:
        return False
    try:
        ip = ipaddress.ip_address(ip_norm)
    except Exception:
        return False
    for net in proxies:
        if ip.version != net.version:
            continue
        if ip in net:
            return True
    return False


def _is_global_public_ip(
    ip_str: str | None,
    proxies: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    """True if `ip_str` is a valid, globally routable IP and not a trusted proxy."""
    ip_norm = _normalize_ip_string(ip_str or "")
    if not ip_norm:
        return False
    try:
        ip = ipaddress.ip_address(ip_norm)
    except Exception:
        return False
    if not ip.is_global:
        return False
    if _is_trusted_proxy(ip_norm, proxies):
        return False
    return True


def _parse_x_forwarded_for(v: str | None) -> list[str]:
    if not isinstance(v, str):
        return []
    return [item.strip() for item in v.split(",") if item.strip()]


def extract_ip_from_headers(
    headers: Mapping[str, str],
    *,
    proxies: Sequence[str] | None = None,
) -> str | None:
    """Extract a likely client IP from headers with validation and trusted proxies.

    Strategy (best-effort):
    - In development, honor `X-Arcjet-Ip` override.
    - Prefer platform-style headers when present (Cloudflare, Fly.io, Vercel, etc.).
    - Fall back to generic headers (`X-Client-Ip`, `X-Forwarded-For`, `X-Real-Ip`, ...).
    - Validate that chosen IP is global/public and not in `proxies` ranges.
    """
    proxy_nets = _parse_proxies(proxies)

    # In development only, allow override for testing.
    if _is_development():
        xaj = _first_header(headers, "x-arcjet-ip")
        if xaj:
            # In development, accept any override to ease local testing.
            return _normalize_ip_string(xaj)

    # Platform-specific style headers (only used if present; still validated)
    cf_ipv6 = _first_header(headers, "cf-connecting-ipv6")
    if _is_global_public_ip(cf_ipv6, proxy_nets):
        return _normalize_ip_string(cf_ipv6)
    cf_ip = _first_header(headers, "cf-connecting-ip")
    if _is_global_public_ip(cf_ip, proxy_nets):
        return _normalize_ip_string(cf_ip)
    fly = _first_header(headers, "fly-client-ip")
    if _is_global_public_ip(fly, proxy_nets):
        return _normalize_ip_string(fly)
    vercel_xvff = _first_header(headers, "x-vercel-forwarded-for")
    for item in reversed(_parse_x_forwarded_for(vercel_xvff)):
        if _is_global_public_ip(item, proxy_nets):
            return _normalize_ip_string(item)
    firebase = _first_header(headers, "x-fah-client-ip")
    if _is_global_public_ip(firebase, proxy_nets):
        return _normalize_ip_string(firebase)
    render_true = _first_header(headers, "true-client-ip")
    if _is_global_public_ip(render_true, proxy_nets):
        return _normalize_ip_string(render_true)

    # Generic headers
    xclient = _first_header(headers, "x-client-ip")
    if _is_global_public_ip(xclient, proxy_nets):
        return _normalize_ip_string(xclient)

    xff = _first_header(headers, "x-forwarded-for")
    for item in reversed(_parse_x_forwarded_for(xff)):
        if _is_global_public_ip(item, proxy_nets):
            return _normalize_ip_string(item)

    do_conn = _first_header(headers, "do-connecting-ip")
    if _is_global_public_ip(do_conn, proxy_nets):
        return _normalize_ip_string(do_conn)
    fastly = _first_header(headers, "fastly-client-ip")
    if _is_global_public_ip(fastly, proxy_nets):
        return _normalize_ip_string(fastly)
    true_client = _first_header(headers, "true-client-ip")
    if _is_global_public_ip(true_client, proxy_nets):
        return _normalize_ip_string(true_client)
    xri = _first_header(headers, "x-real-ip")
    if _is_global_public_ip(xri, proxy_nets):
        return _normalize_ip_string(xri)
    xcluster = _first_header(headers, "x-cluster-client-ip")
    if _is_global_public_ip(xcluster, proxy_nets):
        return _normalize_ip_string(xcluster)
    xfwd = _first_header(headers, "x-forwarded")
    if _is_global_public_ip(xfwd, proxy_nets):
        return _normalize_ip_string(xfwd)
    fwd_for = _first_header(headers, "forwarded-for")
    if _is_global_public_ip(fwd_for, proxy_nets):
        return _normalize_ip_string(fwd_for)
    forwarded = _first_header(headers, "forwarded")
    if _is_global_public_ip(forwarded, proxy_nets):
        return _normalize_ip_string(forwarded)
    appengine = _first_header(headers, "x-appengine-user-ip")
    if _is_global_public_ip(appengine, proxy_nets):
        return _normalize_ip_string(appengine)
    return None


def request_details_from_context(ctx: RequestContext) -> decide_pb2.RequestDetails:
    """Convert a `RequestContext` to `decide_pb2.RequestDetails`.

    Performs light normalization for headers and extra metadata, ensuring the
    Decide API receives lowercase keys for headers and string values for maps.
    """
    d = decide_pb2.RequestDetails()
    if ctx.ip:
        d.ip = ctx.ip
    if ctx.method:
        d.method = ctx.method
    if ctx.protocol:
        d.protocol = ctx.protocol
    if ctx.host:
        d.host = ctx.host
    if ctx.path:
        d.path = ctx.path
    if ctx.cookies:
        d.cookies = ctx.cookies
    if ctx.query:
        d.query = ctx.query
    if ctx.body is not None:
        d.body = ctx.body
    if ctx.email:
        d.email = ctx.email

    if ctx.headers:
        for k, v in ctx.headers.items():
            # Decide API expects a simple string map; normalize keys to lowercase.
            d.headers[str(k).lower()] = str(v)

    if ctx.extra:
        for k, v in ctx.extra.items():
            d.extra[k] = str(v)

    return d


def coerce_request_context(
    req: SupportsRequestContext | Any,
    *,
    proxies: Sequence[str] | None = None,
) -> RequestContext:
    """Best-effort coercion from common request objects.

    Supported inputs:
    - `RequestContext`: returned as-is.
    - ASGI scope `dict`: decodes headers, extracts client IP/host/path/scheme,
        and normalizes the query string.
    - Plain `Mapping`: treated as already-normalized; fields are copied by key.
    - Flask/Werkzeug `Request`: extracts headers, method, scheme, host, path,
        query string, remote address, and body via `get_data()`.
    - Django `HttpRequest`: extracts headers (if available), META info, path,
        cookies, query string, and body.

    In development, if no IP can be determined, defaults to `127.0.0.1`.
    Raises `TypeError` for unsupported shapes.
    """
    if isinstance(req, RequestContext):
        return req

    if isinstance(req, Mapping):
        # ASGI scope (has "type" and "headers") vs our own dict.
        if "headers" in req and "type" in req:
            headers = {}
            raw = req.get("headers") or []
            # ASGI headers are list[tuple[bytes, bytes]]
            for k, v in raw:
                try:
                    headers[k.decode("latin-1")] = v.decode("latin-1")
                except Exception:
                    continue
            ip = None
            client = req.get("client")
            if isinstance(client, (tuple, list)) and client:
                # Prefer the direct remote address when it's global and not a trusted proxy.
                if _is_global_public_ip(client[0], _parse_proxies(proxies)):
                    ip = client[0]
            ip = ip or extract_ip_from_headers(headers, proxies=proxies)
            if not ip and _is_development():
                ip = "127.0.0.1"
            return RequestContext(
                ip=ip,
                method=req.get("method"),
                protocol=req.get("scheme"),
                host=_first_header(headers, "host"),
                path=req.get("path"),
                headers=headers,
                query=(
                    req.get("query_string", b"").decode("latin-1")
                    if isinstance(req.get("query_string"), (bytes, bytearray))
                    else req.get("query_string")
                ),
                cookies=_first_header(headers, "cookie"),
            )

        # Plain mapping: treat as already-normalized
        return RequestContext(
            **{
                k: req.get(k)
                for k in RequestContext.__dataclass_fields__.keys()
                if k in req
            }
        )

    # Flask/Werkzeug Request (duck typing)
    if (
        hasattr(req, "headers")
        and hasattr(req, "method")
        and hasattr(req, "path")
        and hasattr(req, "host")
    ):
        try:
            headers = dict(getattr(req, "headers", {}) or {})
        except Exception:
            headers = {}
        ip = None
        remote = getattr(req, "remote_addr", None)
        if _is_global_public_ip(remote, _parse_proxies(proxies)):
            ip = remote
        ip = ip or extract_ip_from_headers(headers, proxies=proxies)
        if not ip and _is_development():
            ip = "127.0.0.1"
        try:
            query_raw = getattr(req, "query_string", None)
            query = (
                query_raw.decode("latin-1")
                if isinstance(query_raw, (bytes, bytearray))
                else query_raw
            )
        except Exception:
            query = None
        try:
            body = getattr(req, "get_data", None)()
        except Exception:
            body = None
        scheme = "https" if getattr(req, "is_secure", False) else "http"
        return RequestContext(
            ip=ip,
            method=getattr(req, "method", None),
            protocol=scheme,
            host=getattr(req, "host", None),
            path=getattr(req, "path", None),
            headers=headers,
            cookies=headers.get("Cookie"),
            query=query,
            body=body,
        )

    # Django HttpRequest (duck typing)
    if hasattr(req, "META") and hasattr(req, "method"):
        meta = getattr(req, "META", {}) or {}
        # Django 2.2+ has request.headers (case-insensitive)
        hdrs_obj = getattr(req, "headers", None)
        headers = dict(hdrs_obj) if hdrs_obj is not None else {}
        ip = None
        remote = meta.get("REMOTE_ADDR")
        if _is_global_public_ip(remote, _parse_proxies(proxies)):
            ip = remote
        ip = ip or extract_ip_from_headers(headers, proxies=proxies)
        if not ip and _is_development():
            ip = "127.0.0.1"
        scheme = (
            "https"
            if meta.get("wsgi.url_scheme") == "https"
            else meta.get("wsgi.url_scheme", None)
        )
        host = meta.get("HTTP_HOST") or meta.get("SERVER_NAME")
        path = getattr(req, "path", None) or meta.get("PATH_INFO")
        query = getattr(req, "META", {}).get("QUERY_STRING")
        cookies = meta.get("HTTP_COOKIE")
        body = None
        try:
            body = getattr(req, "body", None)
        except Exception:
            body = None
        return RequestContext(
            ip=ip,
            method=getattr(req, "method", None),
            protocol=scheme,
            host=host,
            path=path,
            headers=headers,
            cookies=cookies,
            query=query,
            body=body,
        )

    raise TypeError(
        "Unsupported request type for Arcjet protect(). "
        "Pass a RequestContext, an ASGI scope dict, a Django HttpRequest, or a plain mapping."
    )
