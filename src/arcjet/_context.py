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
- For frameworks whose config library does not propagate `.env` values into
    `os.environ` (e.g. `pydantic-settings`), pass `environment=` explicitly to
    `coerce_request_context` / `extract_ip_from_headers` to override the
    env-var read. End users typically set this once via the
    `arcjet(environment=...)` / `arcjet_sync(environment=...)` factory kwarg,
    which threads the value through to these helpers automatically.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Iterable, Mapping, Protocol, Sequence, cast

from arcjet.proto.decide.v1alpha1 import decide_pb2

HeaderValue = str | Sequence[str]
ProxyNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ClientIpProvenance(str, Enum):
    """Where Arcjet obtained a client IP address.

    ``DIRECT`` and ``PLATFORM`` identify framework or hosting-platform data.
    ``TRUSTED_PROXY`` means the direct peer matched configured ``proxies``.
    ``UNVERIFIED_HEADER`` means Arcjet used a forwarding header without that
    trust signal. ``MANUAL`` is an explicit ``ip_src`` value, ``REQUEST`` is an
    application-supplied request context, ``DEVELOPMENT`` is a development
    override or loopback fallback, and ``NONE`` means no usable address exists.
    """

    DIRECT = "direct"
    TRUSTED_PROXY = "trusted-proxy"
    UNVERIFIED_HEADER = "unverified-header"
    MANUAL = "manual"
    DEVELOPMENT = "development"
    REQUEST = "request"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class ClientIpDetails:
    """Explain the client IP Arcjet selected for a request.

    Attributes:
        ip: Normalized IPv4 or IPv6 address, or ``None`` when no usable address
            was found.
        provenance: Where Arcjet obtained the address.
        verified: Whether the SDK tied the source to a direct request or a
            configured platform/proxy. This does not certify the surrounding
            network configuration.
        header: Lowercase header name when a header supplied the address.

    Example::

        details = aj.client_ip_details(request)
        print(details.ip, details.provenance, details.verified, details.header)
    """

    ip: str | None
    provenance: ClientIpProvenance
    verified: bool
    header: str | None = None


def _is_development(environment: str | None = None) -> bool:
    """Return True when running in development mode.

    Args:
        environment: Explicit environment string, e.g. from a framework
            Settings object. When ``None`` (default), falls back to the
            ``ARCJET_ENV`` environment variable. Matching is case-insensitive;
            anything other than "development" (or unset/empty) is treated as
            production.
    """
    if environment is None:
        environment = os.getenv("ARCJET_ENV")
    return (environment or "production").lower() == "development"


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
    - sensitive_info_value: Content string to scan for sensitive
        information detection rule.
    - detect_prompt_injection_message: User message for prompt injection
        detection rule.
    - extra: Additional key/value metadata to be forwarded to the Decide API.
    - correlation_id: Optional, caller-supplied opaque identifier used to
        correlate this request with other `protect()` and `guard()` calls that
        belong to the same workflow, agent run, or multi-step task. It does not
        affect the decision and is excluded from fingerprinting; it is stored
        alongside the recorded decision so a chain of actions can be
        reconstructed. Bounded server-side to 256 bytes of printable ASCII;
        invalid values are dropped, not truncated.
    """

    ip: str | None = None
    method: str | None = None
    protocol: str | None = None
    host: str | None = None
    path: str | None = None
    headers: Mapping[str, HeaderValue] | None = None
    cookies: str | None = None
    query: str | None = None
    body: bytes | None = None
    email: str | None = None
    sensitive_info_value: str | None = None
    detect_prompt_injection_message: str | None = None
    filter_local: Mapping[str, str] | None = None
    extra: Mapping[str, str] | None = None
    correlation_id: str | None = None


class SupportsRequestContext(Protocol):
    """Protocol for request-like objects that Arcjet can coerce.

    This captures a minimal set of attributes commonly present across popular
    frameworks. It's used to aid type checkers and IDEs; runtime coercion still
    uses duck-typing with careful defensive access.
    """

    headers: Mapping[str, HeaderValue]
    method: str
    # Optional/duck-typed fields; Protocol does not enforce at runtime.
    # Present in ASGI scope: `type`, `path`, `scheme`, `client`, `query_string`.


def _first_header(headers: Mapping[str, HeaderValue], *names: str) -> str | None:
    """Return the first matching header value from `headers`.

    Matching is case-insensitive and respects the order of `names`.

    If a header is represented with multiple instances (value is a list/tuple),
    returns the first string item.
    """
    for n in names:
        for k, v in headers.items():
            if k.lower() != n.lower():
                continue
            if isinstance(v, str):
                return v
            # Multiple header instances represented as a list/tuple
            if isinstance(v, Sequence):
                if len(v) > 0 and isinstance(v[0], str):
                    return v[0]
            return None
    return None


def _all_headers(headers: Mapping[str, HeaderValue], name: str) -> list[str]:
    """Return all values for a header name (case-insensitive).

    Supports both a single string value and a list/tuple of strings representing
    multiple header instances.
    """
    out: list[str] = []
    for k, v in headers.items():
        if k.lower() != name.lower():
            continue
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, Sequence):
            out.extend([x for x in v if isinstance(x, str)])
    return out


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
) -> list[ProxyNetwork]:
    out: list[ProxyNetwork] = []
    if not proxies:
        return out
    for p in proxies:
        if not isinstance(p, str) or not p.strip():
            raise ValueError(f"invalid proxy IP or CIDR: {p!r}")
        try:
            # Support CIDR or single IP; strict=False allows single IPs.
            net = ipaddress.ip_network(p.strip(), strict=False)
            out.append(net)
        except ValueError as exc:
            raise ValueError(f"invalid proxy IP or CIDR: {p!r}") from exc
    return out


def validate_ip(value: str, *, name: str = "IP address") -> str:
    """Validate and normalize a caller-supplied IPv4 or IPv6 address."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a valid IPv4 or IPv6 address")
    candidate = value.strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError as exc:
        raise ValueError(
            f"{name} must be a valid IPv4 or IPv6 address: {value!r}"
        ) from exc


def _validate_proxy_config(
    proxies: Sequence[str],
) -> tuple[tuple[str, ...], tuple[ProxyNetwork, ...]]:
    """Normalize proxy strings and parse them once for configuration checks."""
    normalized: list[str] = []
    for proxy in proxies:
        if not isinstance(proxy, str) or not proxy.strip():
            raise ValueError(f"invalid proxy IP or CIDR: {proxy!r}")
        normalized.append(proxy.strip())
    values = tuple(normalized)
    return values, tuple(_parse_proxies(values))


def validate_proxies(proxies: Sequence[str]) -> tuple[str, ...]:
    """Validate proxy IP/CIDR configuration and return stripped values."""
    return _validate_proxy_config(proxies)[0]


def has_trust_all_proxy(proxies: Sequence[str]) -> bool:
    """Return whether configuration trusts an entire IP address family."""
    return any(network.prefixlen == 0 for network in _validate_proxy_config(proxies)[1])


def _is_trusted_proxy(ip_str: str | None, proxies: Sequence[ProxyNetwork]) -> bool:
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
    proxies: Sequence[ProxyNetwork],
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


def _parse_x_forwarded_for_values(values: Sequence[str]) -> list[str]:
    """Parse one or more XFF header values into a single ordered list.

    MDN: multiple X-Forwarded-For headers must be treated as a single list,
    starting with the first IP of the first header and continuing to the last IP
    of the last header.
    """
    out: list[str] = []
    for v in values:
        if not isinstance(v, str):
            continue
        for item in v.split(","):
            item = item.strip()
            if item:
                out.append(item)
    return out


def _extract_ip_details_from_headers(
    headers: Mapping[str, HeaderValue],
    *,
    proxy_nets: Sequence[ProxyNetwork],
    environment: str | None = None,
) -> ClientIpDetails:
    # In development only, allow override for testing.
    if _is_development(environment=environment):
        xaj = _first_header(headers, "x-arcjet-ip")
        if xaj:
            # In development, accept any override to ease local testing.
            return ClientIpDetails(
                ip=_normalize_ip_string(xaj),
                provenance=ClientIpProvenance.DEVELOPMENT,
                verified=False,
                header="x-arcjet-ip",
            )

    # X-Forwarded-For may appear multiple times; combine as a single list per MDN.
    xff_values = _all_headers(headers, "x-forwarded-for")
    for item in reversed(_parse_x_forwarded_for_values(xff_values)):
        if _is_global_public_ip(item, proxy_nets):
            return ClientIpDetails(
                ip=_normalize_ip_string(item),
                provenance=ClientIpProvenance.UNVERIFIED_HEADER,
                verified=False,
                header="x-forwarded-for",
            )

    return ClientIpDetails(None, ClientIpProvenance.NONE, False)


def extract_ip_details_from_headers(
    headers: Mapping[str, HeaderValue],
    *,
    proxies: Sequence[str] | None = None,
    environment: str | None = None,
) -> ClientIpDetails:
    """Extract a client IP and provenance from forwarding headers.

    Without a trusted direct peer this is an ``UNVERIFIED_HEADER`` result. Pass
    every trusted proxy IP/CIDR in ``proxies`` and restrict direct access to the
    application before treating the header as authoritative.
    """
    return _extract_ip_details_from_headers(
        headers,
        proxy_nets=_parse_proxies(proxies),
        environment=environment,
    )


def extract_ip_from_headers(
    headers: Mapping[str, HeaderValue],
    *,
    proxies: Sequence[str] | None = None,
    environment: str | None = None,
) -> str | None:
    """Extract a likely client IP while preserving the legacy string API."""
    return extract_ip_details_from_headers(
        headers, proxies=proxies, environment=environment
    ).ip


def client_ip_details(
    req: SupportsRequestContext | Any,
    *,
    proxies: Sequence[str] | None = None,
    ip_src: str | None = None,
    environment: str | None = None,
) -> ClientIpDetails:
    """Explain how Arcjet would select the client IP for ``req``.

    This low-level helper performs no logging or network request. Prefer
    ``Arcjet.client_ip_details()`` or ``ArcjetSync.client_ip_details()`` so the
    client's proxy, environment, and manual-IP configuration is applied.
    """
    proxy_nets = _parse_proxies(proxies)

    if ip_src is not None:
        return ClientIpDetails(
            validate_ip(ip_src, name="ip_src"), ClientIpProvenance.MANUAL, True
        )

    if isinstance(req, RequestContext):
        if req.ip:
            try:
                ip = validate_ip(req.ip, name="request IP")
            except ValueError:
                ip = None
            if ip is not None:
                return ClientIpDetails(ip, ClientIpProvenance.REQUEST, True)
        if _is_development(environment=environment):
            return ClientIpDetails("127.0.0.1", ClientIpProvenance.DEVELOPMENT, False)
        return ClientIpDetails(None, ClientIpProvenance.NONE, False)

    headers: dict[str, HeaderValue] = {}
    remote: str | None = None

    if isinstance(req, Mapping):
        cast_req = cast(Mapping[str, Any], req)
        if "headers" in req and "type" in req:
            for k, v in cast_req.get("headers") or []:
                try:
                    headers[k.decode("latin-1")] = v.decode("latin-1")
                except Exception:
                    continue
            client = cast_req.get("client")
            if isinstance(client, (tuple, list)) and client:
                remote = client[0]
        else:
            value = cast_req.get("ip")
            if isinstance(value, str) and value:
                try:
                    ip = validate_ip(value, name="request IP")
                except ValueError:
                    ip = None
                if ip is not None:
                    return ClientIpDetails(ip, ClientIpProvenance.REQUEST, True)
            if _is_development(environment=environment):
                return ClientIpDetails(
                    "127.0.0.1", ClientIpProvenance.DEVELOPMENT, False
                )
            return ClientIpDetails(None, ClientIpProvenance.NONE, False)
    elif hasattr(req, "META") and hasattr(req, "method"):
        meta = getattr(req, "META", {}) or {}
        hdrs_obj = getattr(req, "headers", None)
        headers = dict(hdrs_obj) if hdrs_obj is not None else {}
        remote = meta.get("REMOTE_ADDR")
    elif hasattr(req, "headers") and hasattr(req, "method"):
        try:
            headers = dict(getattr(req, "headers", {}) or {})
        except Exception:
            headers = {}
        remote = getattr(req, "remote_addr", None)
    else:
        raise TypeError(
            "Unsupported request type for Arcjet client_ip_details(). "
            "Pass a RequestContext, an ASGI scope dict, a Django HttpRequest, or a plain mapping."
        )

    if _is_global_public_ip(remote, proxy_nets):
        return ClientIpDetails(
            _normalize_ip_string(remote), ClientIpProvenance.DIRECT, True
        )

    header_details = _extract_ip_details_from_headers(
        headers, proxy_nets=proxy_nets, environment=environment
    )
    if header_details.ip is not None:
        if (
            header_details.provenance is ClientIpProvenance.UNVERIFIED_HEADER
            and _is_trusted_proxy(remote, proxy_nets)
        ):
            return ClientIpDetails(
                header_details.ip,
                ClientIpProvenance.TRUSTED_PROXY,
                True,
                header_details.header,
            )
        return header_details

    if _is_development(environment=environment):
        return ClientIpDetails("127.0.0.1", ClientIpProvenance.DEVELOPMENT, False)
    return ClientIpDetails(None, ClientIpProvenance.NONE, False)


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
        # Decide API expects leading "?" on query string while RequestContext
        # explicitly excludes it. We add it here if missing in an abundance of
        # caution.
        d.query = f"?{ctx.query}" if not ctx.query.startswith("?") else ctx.query
    if ctx.body is not None:
        d.body = ctx.body
    if ctx.email:
        d.email = ctx.email
    if ctx.correlation_id:
        # Dedicated top-level field (not `extra`). Excluded from the cache key;
        # see `make_cache_key`, which only hashes rule characteristics.
        d.correlation_id = ctx.correlation_id

    if ctx.headers:
        for k, v in ctx.headers.items():
            # Decide API expects a simple string map; normalize keys to lowercase.
            d.headers[str(k).lower()] = str(v)

    if ctx.extra:
        for k, v in ctx.extra.items():
            d.extra[k] = str(v)

    # Pass message through extra if present
    if ctx.detect_prompt_injection_message:
        d.extra["detectPromptInjectionMessage"] = ctx.detect_prompt_injection_message

    # Redact sensitive fields that are only used for local WASM evaluation.
    # The server needs to know these fields exist (for dashboard/logging) but
    # must not receive the raw values.  Matches the JS SDK's redaction pattern.
    if ctx.filter_local:
        d.extra["filterLocal"] = "<redacted>"
    if ctx.sensitive_info_value:
        d.extra["sensitiveInfoValue"] = "<redacted>"

    return d


def coerce_request_context(
    req: SupportsRequestContext | Any,
    *,
    proxies: Sequence[str] | None = None,
    ip_src: str | None = None,
    environment: str | None = None,
    resolved_ip_details: ClientIpDetails | None = None,
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
    When ``environment`` is supplied, it overrides ``ARCJET_ENV`` for the
    development-mode check; pass this when using a config library that does
    not propagate ``.env`` values into ``os.environ`` (e.g. ``pydantic-settings``).
    ``resolved_ip_details`` lets callers reuse a previously resolved address so
    proxy headers are not parsed twice. Raises `TypeError` for unsupported
    shapes.
    """

    def resolved_ip() -> str | None:
        if resolved_ip_details is not None:
            return resolved_ip_details.ip
        return client_ip_details(
            req,
            proxies=proxies,
            ip_src=ip_src,
            environment=environment,
        ).ip

    if isinstance(req, RequestContext):
        if resolved_ip_details is None and ip_src is None:
            return req
        return replace(req, ip=resolved_ip())

    if isinstance(req, Mapping):
        # Here we cast to Mapping[str, Any] to help type checkers understand
        # that we can access keys by string. At runtime, we still do duck-typing
        # but ty doesn't yet understand the narrowing. This has no runtime effect.
        cast_req = cast(Mapping[str, Any], req)

        # ASGI scope (has "type" and "headers") vs our own dict.
        if "headers" in req and "type" in req:
            headers: dict[str, str] = {}
            raw = cast_req.get("headers") or []
            # ASGI headers are list[tuple[bytes, bytes]]
            for k, v in raw:
                try:
                    headers[k.decode("latin-1")] = v.decode("latin-1")
                except Exception:
                    continue
            ip = resolved_ip()

            return RequestContext(
                ip=ip,
                method=cast_req.get("method"),
                protocol=cast_req.get("scheme"),
                host=_first_header(headers, "host"),
                path=cast_req.get("path"),
                headers=headers,
                query=(
                    cast_req.get("query_string", b"").decode("latin-1")
                    if isinstance(cast_req.get("query_string"), (bytes, bytearray))
                    else cast_req.get("query_string")
                ),
                cookies=_first_header(headers, "cookie"),
            )

        # Plain mapping: treat as already-normalized
        context = RequestContext(
            **{
                k: cast_req.get(k)
                for k in RequestContext.__dataclass_fields__.keys()
                if k in cast_req
            }
        )
        if resolved_ip_details is not None or ip_src is not None:
            return replace(context, ip=resolved_ip())
        return context

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
        ip = resolved_ip()
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
            body = getattr(req, "get_data", None)()  # type: ignore - caught by except
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
        ip = resolved_ip()
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
