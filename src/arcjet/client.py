"""Arcjet SDK for Python.

This module exposes both async (`Arcjet`) and sync (`ArcjetSync`) clients:

- `arcjet(...)` / `arcjet_sync(...)`: Factory functions that construct clients
    with sensible defaults for base URL, timeout, and metadata.
- `.protect(request, ...)`: Evaluates configured rules against a request and
  returns a `Decision` wrapper.


The request object you pass can be raw framework requests (ASGI scope dict,
Flask/Werkzeug `Request`, Django `HttpRequest`) or a pre-built
    `RequestContext`; see `coerce_request_context` for details.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import os
import time
import uuid
from dataclasses import dataclass, field, replace
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from typing import Any, Mapping, Sequence, TypedDict

import pyqwest

from arcjet.proto.decide.v1alpha1 import decide_pb2
from arcjet.proto.decide.v1alpha1.decide_connect import (
    DecideServiceClient,
    DecideServiceClientSync,
)

from ._errors import ArcjetMisconfiguration, ArcjetTransportError
from ._logging import logger
from .cache import DecisionCache, make_cache_key
from .context import (
    RequestContext,
    coerce_request_context,
    request_details_from_context,
)
from .decision import Decision
from .rules import EmailValidation, RuleSpec, TokenBucket


def _new_local_request_id() -> str:
    """Generate a local request ID with `lreq` prefix using typeid-python.

    Falls back to a UUID4-based ID if `typeid-python` is unavailable.
    """
    try:
        from typeid import TypeID

        return str(TypeID(prefix="lreq"))
    except Exception:
        return f"lreq_{uuid.uuid4().hex}"


class ProtectOptions(TypedDict, total=False):
    """Optional per-request keyword arguments for ``protect()``.

    All fields are optional. Pass them as keyword arguments directly to
    ``Arcjet.protect()`` or ``ArcjetSync.protect()``.
    """

    requested: int
    """Number of tokens to consume from the token bucket for this request.
    Defaults to 1 when a token bucket rule is configured."""

    characteristics: Mapping[str, Any]
    """Custom key/value pairs for client fingerprinting. Defaults to the client IP address. Keys must match
    characteristic names configured on your rules.
    Example: ``{"user_id": "123"}``. See https://docs.arcjet.com/fingerprints."""

    email: str
    """Email address to validate when a ``validate_email()`` rule is configured."""

    extra: Mapping[str, str]
    """Arbitrary key/value pairs forwarded verbatim to the Arcjet Decide API."""


def _default_timeout_ms() -> int:
    # 1000ms in development, 500ms otherwise.
    env = (os.getenv("ARCJET_ENV") or "production").lower()
    return 1000 if env == "development" else 500


DEFAULT_BASE_URL = (
    os.getenv("ARCJET_BASE_URL")
    or (
        "https://fly.decide.arcjet.com"
        if os.getenv("FLY_APP_NAME")
        else "https://decide.arcjet.com"
    )
).rstrip("/")


def _auth_headers(
    key: str | None, headers: Mapping[str, str] | None = None
) -> dict[str, str]:
    """Build authorization and custom headers for Decide API calls.

    - Copies any provided `headers` (stringifies keys/values).
    - Adds `Authorization: Bearer <key>` if a key is provided and the caller
        hasn't already set it.
    """
    out: dict[str, str] = {}
    if headers:
        out.update({str(k): str(v) for k, v in headers.items()})
    if key:
        out.setdefault("Authorization", f"Bearer {key}")
    return out


def _sdk_stack(stack: str | None) -> str | decide_pb2.SDKStack:
    """Resolve the SDK stack for client metadata.

    Uses the provided `stack` string if given; otherwise defaults to
    `decide_pb2.SDK_STACK_PYTHON`.
    """
    if stack is None:
        return decide_pb2.SDK_STACK_PYTHON
    return stack


def _sdk_version(default: str = "0.0.0") -> str:
    """Resolve the installed SDK version for client metadata.

    Uses the distribution name from `pyproject.toml` ("arcjet"). When running
    from source without installed metadata, falls back to `default`.
    """
    try:
        return pkg_version("arcjet")
    except PackageNotFoundError:
        # Happens when running from source without installed metadata.
        return default


@dataclass(slots=True)
class Arcjet:
    """Async Arcjet client.

    Evaluates HTTP requests against a configured set of security rules by.
    Results are returned as a ``Decision`` object you can inspect to allow or
    deny the request.

    Do not instantiate this class directly - use the ``arcjet()`` factory
    function instead, which sets sensible defaults for the API endpoint,
    timeout, and transport.

    Example::

        import os
        from arcjet import (
            arcjet,
            shield,
            detect_bot,
            token_bucket,
            Mode,
            BotCategory,
        )

        arcjet_key = os.getenv("ARCJET_KEY")
        if not arcjet_key:
            raise RuntimeError(
                "ARCJET_KEY is required. Get one at https://app.arcjet.com")

        aj = arcjet(
            key=arcjet_key,  # Get your key from https://app.arcjet.com
            rules=[
                # Shield protects your app from common attacks e.g. SQL injection
                shield(mode=Mode.LIVE),
                # Create a bot detection rule
                detect_bot(
                    mode=Mode.LIVE, allow=[
                        BotCategory.SEARCH_ENGINE,  # Google, Bing, etc
                        # Uncomment to allow these other common bot categories
                        # See the full list at https://docs.arcjet.com/bot-protection/identifying-bots
                        # BotCategory.MONITOR, # Uptime monitoring services
                        # BotCategory.PREVIEW, # Link previews e.g. Slack, Discord
                    ]
                ),
                # Create a token bucket rate limit. Other algorithms are supported
                token_bucket(
                    # Tracked by IP address by default, but this can be customized
                    # See https://docs.arcjet.com/fingerprints
                    # characteristics: ["ip.src"],
                    mode=Mode.LIVE,
                    refill_rate=5,  # Refill 5 tokens per interval
                    interval=10,  # Refill every 10 seconds
                    capacity=10,  # Bucket capacity of 10 tokens
                ),
            ],
        )

        # Inside an async route handler:
        decision = await aj.protect(request, requested=1)
        if decision.is_denied():
            return JSONResponse({"error": "Forbidden"}, status_code=403)
    """

    _key: str
    _rules: tuple[RuleSpec, ...]
    _client: DecideServiceClient
    _sdk_stack: str | None
    _sdk_version: str
    _timeout_ms: int | None
    _fail_open: bool
    _needs_email: bool = False
    _has_token_bucket: bool = False
    _proxies: tuple[str, ...] = ()
    _disable_automatic_ip_detection: bool = False
    _cache: DecisionCache = field(default_factory=DecisionCache)

    async def protect(
        self,
        request: Any,
        *,
        requested: int | None = None,
        characteristics: Mapping[str, Any] | None = None,
        email: str | None = None,
        extra: Mapping[str, str] | None = None,
        ip_src: str | None = None,
    ) -> Decision:
        """Evaluate the configured security rules against an incoming request.

        Call this once per request, typically at the start of your route
        handler before running any application logic. The returned ``Decision``
        tells you whether to allow or deny the request.

        Args:
            ``request``: The incoming HTTP request. Accepts ASGI scope dicts,
                Flask/Werkzeug ``Request`` objects, Django ``HttpRequest``
                objects, or a ``RequestContext`` built manually.
            ``requested``: Number of tokens to consume for this request when a
                ``token_bucket()`` rule is configured. Defaults to 1.
            ``characteristics``: Custom key/value pairs for client fingerprinting. Defaults to the client IP address.
                Keys must match characteristic names configured on your rules.
                Example: ``{"user_id": current_user.id}``.
            ``email``: Email address to validate when a ``validate_email()`` rule
                is configured. Required if email validation is active.
            ``extra``: Additional key/value pairs forwarded verbatim to the Arcjet
                Decide API. Useful for custom metadata or debugging.
            ``ip_src``: Override the detected client IP. Only valid when
                ``disable_automatic_ip_detection=True`` was set on the client.
                **Caution:** only pass IPs from sources you trust. See
                https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For.

        Returns:
            A ``Decision`` containing the overall conclusion and per-rule
            results. Use ``decision.is_denied()`` for a quick allow/block
            check, or inspect ``decision.reason_v2`` and ``decision.results``
            for per-rule detail.

        Raises:
            ArcjetMisconfiguration: When required context (e.g. ``email``) is
                missing for the configured rules, or when ``ip_src`` is used
                inconsistently with ``disable_automatic_ip_detection``.
            ArcjetTransportError: On network errors when ``fail_open=False``.

        Example::

            decision = await aj.protect(request, requested=1)
            if decision.is_denied():
                status = 429 if decision.reason_v2.type == "RATE_LIMIT" else 403
                return JSONResponse({"error": "Forbidden"}, status_code=status)

            if decision.ip.is_hosting():
                return JSONResponse({"error": "Blocked"}, status_code=403)
        """
        t0 = time.perf_counter()
        if self._disable_automatic_ip_detection and not ip_src:
            raise ArcjetMisconfiguration(
                "ip_src is required when disable_automatic_ip_detection=True. "
                "Pass ip_src=... to aj.protect(...)."
            )
        if self._disable_automatic_ip_detection and self._proxies:
            raise ArcjetMisconfiguration(
                "proxies cannot be used when disable_automatic_ip_detection=True. proxies are ignored with manual IP detection so they have no effect."
            )
        if not self._disable_automatic_ip_detection and ip_src:
            raise ArcjetMisconfiguration(
                "ip_src cannot be set when disable_automatic_ip_detection=False."
            )
        ctx = coerce_request_context(request, proxies=self._proxies, ip_src=ip_src)

        if email:
            ctx = replace(ctx, email=email)
        # Enforce required per-request context based on configured rules.
        if self._needs_email and not (email or ctx.email):
            raise ArcjetMisconfiguration(
                "email is required when validate_email(...) is configured. "
                "Pass email=... to aj.protect(...)."
            )
        # Token bucket uses a per-request cost. Default to 1 token if not provided.
        if self._has_token_bucket and requested is None:
            requested = 1

        merged_extra: dict[str, str] = {}
        if ctx.extra:
            merged_extra.update({str(k): str(v) for k, v in ctx.extra.items()})
        if extra:
            merged_extra.update({str(k): str(v) for k, v in extra.items()})
        if requested is not None:
            merged_extra["requested"] = str(int(requested))
        # If disable_automatic_ip_detection is True, add an Arcjet field to extra to report this
        if self._disable_automatic_ip_detection and ip_src:
            merged_extra["arcjet_disable_automatic_ip_detection"] = "true"

        # Include per-request characteristic values as extra fields so
        # server-side fingerprinting can read them by name.
        if characteristics:
            for k, v in characteristics.items():
                if isinstance(v, (list, tuple)):
                    # Flatten list/tuple values into multiple extras sharing the key
                    # by joining with commas for simplicity.
                    merged_extra[str(k)] = ",".join(str(x) for x in v)
                else:
                    merged_extra[str(k)] = str(v)

        ctx = RequestContext(
            ip=ctx.ip,
            method=ctx.method,
            protocol=ctx.protocol,
            host=ctx.host,
            path=ctx.path,
            headers=ctx.headers,
            cookies=ctx.cookies,
            query=ctx.query,
            body=ctx.body,
            email=ctx.email,
            extra=merged_extra or None,
        )

        # Cache lookup before hitting Decide API
        cache_key = make_cache_key(ctx, self._rules)
        cached = self._cache.get(cache_key) if cache_key is not None else None
        if cached is not None:
            # Fire-and-forget async report; do not await
            try:
                # Use cached decision but override ID with locally generated request ID
                dec = cached.to_proto()
                dec.id = _new_local_request_id()
                rep = decide_pb2.ReportRequest(
                    sdk_stack=_sdk_stack(self._sdk_stack),
                    sdk_version=self._sdk_version,
                    details=request_details_from_context(ctx),
                    decision=dec,
                )
                rep.rules.extend([r.to_proto() for r in self._rules])

                async def _send_report():
                    try:
                        await self._client.report(
                            rep,
                            headers=_auth_headers(self._key),
                            timeout_ms=self._timeout_ms,
                        )
                    except Exception as e:
                        # Background error: log at debug; do not raise
                        logger.debug(
                            "report error on cache hit: error=%s",
                            str(e),
                            extra={
                                "event": "arcjet_report_error",
                                "error": str(e),
                            },
                        )

                asyncio.create_task(_send_report())
                # Log cache-hit report scheduling with latency figures similar to decide
                if logger.isEnabledFor(logging.DEBUG):
                    t_prepare_end = time.perf_counter()
                    total_ms = (time.perf_counter() - t0) * 1000.0
                    prepare_ms = (t_prepare_end - t0) * 1000.0
                    api_ms = 0.0  # fire-and-forget; API latency not measured here
                    logger.debug(
                        "report: id=%s conclusion=%s reason=%s ttl=%s api_ms=%.3f prepare_ms=%.3f total_ms=%.3f rules=%d",
                        dec.id,
                        decide_pb2.Conclusion.Name(cached.conclusion),
                        cached.reason.which(),
                        str(cached.ttl),
                        round(api_ms, 3),
                        round(prepare_ms, 3),
                        round(total_ms, 3),
                        len(self._rules),
                        extra={
                            "event": "arcjet_report_cache_hit",
                            "decision_id": dec.id,
                            "conclusion": decide_pb2.Conclusion.Name(cached.conclusion),
                            "reason": cached.reason.which(),
                            "ttl": cached.ttl,
                            "rule_count": len(self._rules),
                            "api_ms": round(api_ms, 3),
                            "prepare_ms": round(prepare_ms, 3),
                            "total_ms": round(total_ms, 3),
                        },
                    )
            except Exception as e:
                logger.debug(
                    "cache-hit report scheduling error: error=%s",
                    str(e),
                    extra={
                        "event": "arcjet_report_schedule_error",
                        "error": str(e),
                    },
                )
            return cached

        req = decide_pb2.DecideRequest(
            sdk_stack=_sdk_stack(self._sdk_stack),
            sdk_version=self._sdk_version,
            details=request_details_from_context(ctx),
        )
        req.rules.extend([r.to_proto() for r in self._rules])
        # Do not set `req.characteristics` here; rule-level configuration controls
        # which characteristics are used. When none provided, server defaults to IP.
        t_prepare_end = time.perf_counter()

        t_api_start = time.perf_counter()
        try:
            resp = await self._client.decide(
                req,
                headers=_auth_headers(self._key),
                timeout_ms=self._timeout_ms,
            )
            t_api_end = time.perf_counter()
        except Exception as e:
            total_ms = (time.perf_counter() - t0) * 1000.0
            prepare_ms = (
                (t_api_start - t0) * 1000.0
                if "t_api_start" in locals()
                else (time.perf_counter() - t0) * 1000.0
            )
            api_ms = (
                (time.perf_counter() - t_api_start) * 1000.0
                if "t_api_start" in locals()
                else 0.0
            )
            if self._fail_open:
                # Fail open: return an error decision instead of raising an exception.
                logger.warning(
                    "arcjet fail_open error due to transport error: error=%s api_ms=%.3f prepare_ms=%.3f total_ms=%.3f rules=%d",
                    str(e),
                    round(api_ms, 3),
                    round(prepare_ms, 3),
                    round(total_ms, 3),
                    len(self._rules),
                    extra={
                        "event": "arcjet_transport_error",
                        "error": str(e),
                        "api_ms": round(api_ms, 3),
                        "prepare_ms": round(prepare_ms, 3),
                        "total_ms": round(total_ms, 3),
                        "rule_count": len(self._rules),
                    },
                )
                d = decide_pb2.Decision(
                    id="",
                    conclusion=decide_pb2.CONCLUSION_ERROR,
                    reason=decide_pb2.Reason(
                        error=decide_pb2.ErrorReason(message=str(e))
                    ),
                )
                return Decision(d)
            logger.error(
                "arcjet transport error: error=%s api_ms=%.3f prepare_ms=%.3f total_ms=%.3f rules=%d",
                str(e),
                round(api_ms, 3),
                round(prepare_ms, 3),
                round(total_ms, 3),
                len(self._rules),
                extra={
                    "event": "arcjet_transport_error",
                    "error": str(e),
                    "api_ms": round(api_ms, 3),
                    "prepare_ms": round(prepare_ms, 3),
                    "total_ms": round(total_ms, 3),
                    "rule_count": len(self._rules),
                },
            )
            raise ArcjetTransportError(str(e)) from e

        if not resp or not resp.HasField("decision"):
            total_ms = (time.perf_counter() - t0) * 1000.0
            api_ms = (
                (t_api_end - t_api_start) * 1000.0 if "t_api_end" in locals() else 0.0
            )
            prepare_ms = (
                (t_api_start - t0) * 1000.0 if "t_api_start" in locals() else total_ms
            )
            if self._fail_open:
                logger.warning(
                    "arcjet fail_open error due to invalid response: error=%s api_ms=%.3f prepare_ms=%.3f total_ms=%.3f rules=%d",
                    "missing decision in response",
                    round(api_ms, 3),
                    round(prepare_ms, 3),
                    round(total_ms, 3),
                    len(self._rules),
                    extra={
                        "event": "arcjet_invalid_response",
                        "error": "missing decision in response",
                        "api_ms": round(api_ms, 3),
                        "prepare_ms": round(prepare_ms, 3),
                        "total_ms": round(total_ms, 3),
                        "rule_count": len(self._rules),
                    },
                )
                d = decide_pb2.Decision(
                    id="",
                    conclusion=decide_pb2.CONCLUSION_ERROR,
                    reason=decide_pb2.Reason(
                        error=decide_pb2.ErrorReason(
                            message="missing decision in response"
                        )
                    ),
                )
                return Decision(d)
            logger.error(
                "arcjet invalid response: error=%s api_ms=%.3f prepare_ms=%.3f total_ms=%.3f rules=%d",
                "missing decision in response",
                round(api_ms, 3),
                round(prepare_ms, 3),
                round(total_ms, 3),
                len(self._rules),
                extra={
                    "event": "arcjet_invalid_response",
                    "error": "missing decision in response",
                    "api_ms": round(api_ms, 3),
                    "prepare_ms": round(prepare_ms, 3),
                    "total_ms": round(total_ms, 3),
                    "rule_count": len(self._rules),
                },
            )
            raise ArcjetTransportError(
                "Arcjet API returned an invalid response (missing decision)."
            )

        decision = Decision(resp.decision)
        # Cache the decision when TTL is present (>0)
        try:
            ttl = int(getattr(decision, "ttl", 0) or 0)
            if ttl > 0 and cache_key is not None:
                self._cache.set(cache_key, decision, ttl)
        except Exception:
            pass
        if logger.isEnabledFor(logging.DEBUG):
            # Timings
            total_ms = (time.perf_counter() - t0) * 1000.0
            api_ms = (
                (t_api_end - t_api_start) * 1000.0 if "t_api_end" in locals() else 0.0
            )
            prepare_ms = (t_prepare_end - t0) * 1000.0
            logger.debug(
                "decision: id=%s conclusion=%s reason=%s ttl=%s api_ms=%.3f prepare_ms=%.3f total_ms=%.3f rules=%d",
                decision.id,
                decide_pb2.Conclusion.Name(decision.conclusion),
                decision.reason.which(),
                str(decision.ttl),
                round(api_ms, 3),
                round(prepare_ms, 3),
                round(total_ms, 3),
                len(self._rules),
                extra={
                    "event": "arcjet_decision",
                    "decision_id": decision.id,
                    "conclusion": decide_pb2.Conclusion.Name(decision.conclusion),
                    "reason": decision.reason.which(),
                    "ttl": decision.ttl,
                    "rule_count": len(self._rules),
                    "api_ms": round(api_ms, 3),
                    "prepare_ms": round(prepare_ms, 3),
                    "total_ms": round(total_ms, 3),
                },
            )
        return decision

    async def aclose(self) -> None:
        """Close the underlying transport when supported (async)."""
        close = getattr(self._client, "aclose", None)
        if callable(close):
            result = close()
            if inspect.isawaitable(result):
                await result
            return
        close_sync = getattr(self._client, "close", None)
        if callable(close_sync):
            close_sync()

    async def __aenter__(self) -> "Arcjet":
        """Async context manager entry; returns `self`."""
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        """Async context manager exit; ensures the client is closed."""
        await self.aclose()


@dataclass(slots=True)
class ArcjetSync:
    """Sync Arcjet client.

    Synchronous counterpart to ``Arcjet``. Use this with synchronous
    frameworks such as Flask or Django when you cannot use ``await``. The
    ``.protect()`` method signature is identical to the async version.

    Do not instantiate this class directly - use the ``arcjet_sync()`` factory
    function instead, which sets sensible defaults for the API endpoint,
    timeout, and transport.

    Example::

        import os
        from arcjet import (
            arcjet_sync,
            shield,
            detect_bot,
            token_bucket,
            Mode,
            BotCategory,
        )

        arcjet_key = os.getenv("ARCJET_KEY")
        if not arcjet_key:
            raise RuntimeError(
                "ARCJET_KEY is required. Get one at https://app.arcjet.com")

        aj = arcjet_sync(
            key=arcjet_key,  # Get your key from https://app.arcjet.com
            rules=[
                # Shield protects your app from common attacks e.g. SQL injection
                shield(mode=Mode.LIVE),
                # Create a bot detection rule
                detect_bot(
                    mode=Mode.LIVE, allow=[
                        BotCategory.SEARCH_ENGINE,  # Google, Bing, etc
                        # Uncomment to allow these other common bot categories
                        # See the full list at https://docs.arcjet.com/bot-protection/identifying-bots
                        # BotCategory.MONITOR, # Uptime monitoring services
                        # BotCategory.PREVIEW, # Link previews e.g. Slack, Discord
                    ]
                ),
                # Create a token bucket rate limit. Other algorithms are supported
                token_bucket(
                    # Tracked by IP address by default, but this can be customized
                    # See https://docs.arcjet.com/fingerprints
                    # characteristics: ["ip.src"],
                    mode=Mode.LIVE,
                    refill_rate=5,  # Refill 5 tokens per interval
                    interval=10,  # Refill every 10 seconds
                    capacity=10,  # Bucket capacity of 10 tokens
                ),
            ],
        )

        # Inside a route handler:
        decision = aj.protect(request)
        if decision.is_denied():
            return jsonify(error="Forbidden"), 403
    """

    _key: str
    _rules: tuple[RuleSpec, ...]
    _client: DecideServiceClientSync
    _sdk_stack: str | None
    _sdk_version: str
    _timeout_ms: int | None
    _fail_open: bool
    _needs_email: bool = False
    _has_token_bucket: bool = False
    _proxies: tuple[str, ...] = ()
    _disable_automatic_ip_detection: bool = False
    _cache: DecisionCache = field(default_factory=DecisionCache)

    def protect(
        self,
        request: Any,
        *,
        requested: int | None = None,
        characteristics: Mapping[str, Any] | None = None,
        email: str | None = None,
        extra: Mapping[str, str] | None = None,
        ip_src: str | None = None,
    ) -> Decision:
        """Evaluate the configured security rules against an incoming request (sync).

        Synchronous counterpart to ``Arcjet.protect()``. See that method's
        documentation for full parameter, return value, and error details.

        Example::

            decision = aj.protect(request, requested=1, email="user@example.com")
            if decision.is_denied():
                return jsonify(error="Forbidden"), 403
        """
        t0 = time.perf_counter()
        if self._disable_automatic_ip_detection and not ip_src:
            raise ArcjetMisconfiguration(
                "ip_src is required when disable_automatic_ip_detection=True. "
                "Pass ip_src=... to aj.protect(...)."
            )
        if self._disable_automatic_ip_detection and self._proxies:
            raise ArcjetMisconfiguration(
                "proxies cannot be used when disable_automatic_ip_detection=True. proxies are ignored with manual IP detection so they have no effect."
            )
        if not self._disable_automatic_ip_detection and ip_src:
            raise ArcjetMisconfiguration(
                "ip_src cannot be set when disable_automatic_ip_detection=False."
            )
        ctx = coerce_request_context(request, proxies=self._proxies, ip_src=ip_src)

        if email:
            ctx = replace(ctx, email=email)
        # Enforce required per-request context based on configured rules.
        if self._needs_email and not (email or ctx.email):
            raise ArcjetMisconfiguration(
                "email is required when validate_email(...) is configured. "
                "Pass email=... to aj.protect(...)."
            )
        # Token bucket uses a per-request cost. Default to 1 token if not provided.
        if self._has_token_bucket and requested is None:
            requested = 1

        merged_extra: dict[str, str] = {}
        if ctx.extra:
            merged_extra.update({str(k): str(v) for k, v in ctx.extra.items()})
        if extra:
            merged_extra.update({str(k): str(v) for k, v in extra.items()})
        # If disable_automatic_ip_detection is True, add an Arcjet field to extra to report this
        if self._disable_automatic_ip_detection and ip_src:
            merged_extra["arcjet_disable_automatic_ip_detection"] = "true"
        if requested is not None:
            merged_extra["requested"] = str(int(requested))
        if characteristics:
            for k, v in characteristics.items():
                if isinstance(v, (list, tuple)):
                    merged_extra[str(k)] = ",".join(str(x) for x in v)
                else:
                    merged_extra[str(k)] = str(v)

        ctx = RequestContext(
            ip=ctx.ip,
            method=ctx.method,
            protocol=ctx.protocol,
            host=ctx.host,
            path=ctx.path,
            headers=ctx.headers,
            cookies=ctx.cookies,
            query=ctx.query,
            body=ctx.body,
            email=ctx.email,
            extra=merged_extra or None,
        )

        # Cache lookup before hitting Decide API
        cache_key = make_cache_key(ctx, self._rules)
        cached = self._cache.get(cache_key) if cache_key is not None else None
        if cached is not None:
            # Fire-and-forget background report using sync client
            try:
                dec = cached.to_proto()
                dec.id = _new_local_request_id()
                rep = decide_pb2.ReportRequest(
                    sdk_stack=_sdk_stack(self._sdk_stack),
                    sdk_version=self._sdk_version,
                    details=request_details_from_context(ctx),
                    decision=dec,
                )
                rep.rules.extend([r.to_proto() for r in self._rules])

                def _send_report_sync():
                    try:
                        self._client.report(
                            rep,
                            headers=_auth_headers(self._key),
                            timeout_ms=self._timeout_ms,
                        )
                    except Exception as e:
                        logger.debug(
                            "report error on cache hit (sync): error=%s",
                            str(e),
                            extra={
                                "event": "arcjet_report_error",
                                "error": str(e),
                            },
                        )

                import threading

                threading.Thread(target=_send_report_sync, daemon=True).start()

                if logger.isEnabledFor(logging.DEBUG):
                    t_prepare_end = time.perf_counter()
                    total_ms = (time.perf_counter() - t0) * 1000.0
                    prepare_ms = (t_prepare_end - t0) * 1000.0
                    api_ms = 0.0  # fire-and-forget; API latency not measured here
                    logger.debug(
                        "report (cache-hit sync): id=%s conclusion=%s reason=%s ttl=%s api_ms=%.3f prepare_ms=%.3f total_ms=%.3f rules=%d",
                        dec.id,
                        decide_pb2.Conclusion.Name(cached.conclusion),
                        cached.reason.which(),
                        str(cached.ttl),
                        round(api_ms, 3),
                        round(prepare_ms, 3),
                        round(total_ms, 3),
                        len(self._rules),
                        extra={
                            "event": "arcjet_report_cache_hit",
                            "decision_id": dec.id,
                            "conclusion": decide_pb2.Conclusion.Name(cached.conclusion),
                            "reason": cached.reason.which(),
                            "ttl": cached.ttl,
                            "rule_count": len(self._rules),
                            "api_ms": round(api_ms, 3),
                            "prepare_ms": round(prepare_ms, 3),
                            "total_ms": round(total_ms, 3),
                        },
                    )
            except Exception as e:
                logger.debug(
                    "cache-hit report scheduling error (sync): error=%s",
                    str(e),
                    extra={
                        "event": "arcjet_report_schedule_error",
                        "error": str(e),
                    },
                )
            return cached

        req = decide_pb2.DecideRequest(
            sdk_stack=_sdk_stack(self._sdk_stack),
            sdk_version=self._sdk_version,
            details=request_details_from_context(ctx),
        )
        req.rules.extend([r.to_proto() for r in self._rules])
        t_prepare_end = time.perf_counter()

        t_api_start = time.perf_counter()
        try:
            resp = self._client.decide(
                req,
                headers=_auth_headers(self._key),
                timeout_ms=self._timeout_ms,
            )
            t_api_end = time.perf_counter()
        except Exception as e:
            total_ms = (time.perf_counter() - t0) * 1000.0
            prepare_ms = (
                (t_api_start - t0) * 1000.0
                if "t_api_start" in locals()
                else (time.perf_counter() - t0) * 1000.0
            )
            api_ms = (
                (time.perf_counter() - t_api_start) * 1000.0
                if "t_api_start" in locals()
                else 0.0
            )
            if self._fail_open:
                logger.warning(
                    "arcjet fail_open error due to transport error: error=%s api_ms=%.3f prepare_ms=%.3f total_ms=%.3f rules=%d",
                    str(e),
                    round(api_ms, 3),
                    round(prepare_ms, 3),
                    round(total_ms, 3),
                    len(self._rules),
                    extra={
                        "event": "arcjet_transport_error",
                        "error": str(e),
                        "api_ms": round(api_ms, 3),
                        "prepare_ms": round(prepare_ms, 3),
                        "total_ms": round(total_ms, 3),
                        "rule_count": len(self._rules),
                    },
                )
                d = decide_pb2.Decision(
                    id="",
                    conclusion=decide_pb2.CONCLUSION_ERROR,
                    reason=decide_pb2.Reason(
                        error=decide_pb2.ErrorReason(message=str(e))
                    ),
                )
                return Decision(d)
            logger.error(
                "arcjet transport error: error=%s api_ms=%.3f prepare_ms=%.3f total_ms=%.3f rules=%d",
                str(e),
                round(api_ms, 3),
                round(prepare_ms, 3),
                round(total_ms, 3),
                len(self._rules),
                extra={
                    "event": "arcjet_transport_error",
                    "error": str(e),
                    "api_ms": round(api_ms, 3),
                    "prepare_ms": round(prepare_ms, 3),
                    "total_ms": round(total_ms, 3),
                    "rule_count": len(self._rules),
                },
            )
            raise ArcjetTransportError(str(e)) from e

        if not resp or not resp.HasField("decision"):
            total_ms = (time.perf_counter() - t0) * 1000.0
            api_ms = (
                (t_api_end - t_api_start) * 1000.0 if "t_api_end" in locals() else 0.0
            )
            prepare_ms = (
                (t_api_start - t0) * 1000.0 if "t_api_start" in locals() else total_ms
            )
            if self._fail_open:
                logger.warning(
                    "arcjet fail_open error due to invalid response: error=%s api_ms=%.3f prepare_ms=%.3f total_ms=%.3f rules=%d",
                    "missing decision in response",
                    round(api_ms, 3),
                    round(prepare_ms, 3),
                    round(total_ms, 3),
                    len(self._rules),
                    extra={
                        "event": "arcjet_invalid_response",
                        "error": "missing decision in response",
                        "api_ms": round(api_ms, 3),
                        "prepare_ms": round(prepare_ms, 3),
                        "total_ms": round(total_ms, 3),
                        "rule_count": len(self._rules),
                    },
                )
                d = decide_pb2.Decision(
                    id="",
                    conclusion=decide_pb2.CONCLUSION_ERROR,
                    reason=decide_pb2.Reason(
                        error=decide_pb2.ErrorReason(
                            message="missing decision in response"
                        )
                    ),
                )
                return Decision(d)
            logger.error(
                "arcjet invalid response: error=%s api_ms=%.3f prepare_ms=%.3f total_ms=%.3f rules=%d",
                "missing decision in response",
                round(api_ms, 3),
                round(prepare_ms, 3),
                round(total_ms, 3),
                len(self._rules),
                extra={
                    "event": "arcjet_invalid_response",
                    "error": "missing decision in response",
                    "api_ms": round(api_ms, 3),
                    "prepare_ms": round(prepare_ms, 3),
                    "total_ms": round(total_ms, 3),
                    "rule_count": len(self._rules),
                },
            )
            raise ArcjetTransportError(
                "Arcjet API returned an invalid response (missing decision)."
            )

        decision = Decision(resp.decision)
        # Cache the decision when TTL is present (>0)
        try:
            ttl = int(getattr(decision, "ttl", 0) or 0)
            if ttl > 0 and cache_key is not None:
                self._cache.set(cache_key, decision, ttl)
        except Exception:
            pass
        if logger.isEnabledFor(logging.DEBUG):
            total_ms = (time.perf_counter() - t0) * 1000.0
            api_ms = (
                (t_api_end - t_api_start) * 1000.0 if "t_api_end" in locals() else 0.0
            )
            prepare_ms = (t_prepare_end - t0) * 1000.0
            logger.debug(
                "decision: id=%s conclusion=%s reason=%s ttl=%s api_ms=%.3f prepare_ms=%.3f total_ms=%.3f rules=%d",
                decision.id,
                decide_pb2.Conclusion.Name(decision.conclusion),
                decision.reason.which(),
                str(decision.ttl),
                round(api_ms, 3),
                round(prepare_ms, 3),
                round(total_ms, 3),
                len(self._rules),
                extra={
                    "event": "arcjet_decision",
                    "decision_id": decision.id,
                    "conclusion": decide_pb2.Conclusion.Name(decision.conclusion),
                    "reason": decision.reason.which(),
                    "ttl": decision.ttl,
                    "rule_count": len(self._rules),
                    "api_ms": round(api_ms, 3),
                    "prepare_ms": round(prepare_ms, 3),
                    "total_ms": round(total_ms, 3),
                },
            )
        return decision

    def close(self) -> None:
        """Close the underlying transport when supported (sync)."""
        close = getattr(self._client, "close", None)
        if callable(close):
            close()

    def __enter__(self) -> "ArcjetSync":
        """Context manager entry; returns `self`."""
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        """Context manager exit; ensures the client is closed."""
        self.close()


def arcjet(
    *,
    key: str,
    rules: Sequence[RuleSpec],
    base_url: str = DEFAULT_BASE_URL,
    timeout_ms: int | None = None,
    stack: str | None = None,
    sdk_version: str | None = None,
    fail_open: bool = True,
    proxies: Sequence[str] = (),
    disable_automatic_ip_detection: bool = False,
) -> Arcjet:
    """Create an async Arcjet client.

    Args:
        ``key``: Your Arcjet site key from https://app.arcjet.com. Keep this
            secret — store it in an environment variable, never in source code.
        ``rules``: One or more rule specs created by ``shield()``, ``detect_bot()``,
            ``token_bucket()``, ``fixed_window()``, ``sliding_window()``, or
            ``validate_email()``.
        ``base_url``: Override the Arcjet Decide API endpoint. Only set this if directed by Arcjet support.
        ``timeout_ms``: Request timeout in milliseconds. Defaults to 1000 ms in
            development and 500 ms in production.
        ``fail_open``: When ``True`` (default), transport errors produce an ERROR
            decision instead of raising an exception, so your app stays
            available if Arcjet is temporarily unreachable. Set to ``False``
            to raise ``ArcjetTransportError`` on network failures instead.
        ``proxies``: IP addresses or CIDR ranges of trusted reverse proxies or
            load balancers sitting in front of your app. Arcjet skips these
            when resolving the real client IP from ``X-Forwarded-For``.
            Example: ``["10.0.0.0/8", "192.168.1.1"]``.
        ``disable_automatic_ip_detection``: Set to ``True`` to disable automatic
            IP extraction from request headers and supply the client IP
            yourself via ``ip_src`` on each ``protect()`` call. Only use this
            when you have your own validated IP-extraction logic. See
            https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For.

    Returns:
        An ``Arcjet`` async client instance.

    Raises:
        ArcjetMisconfiguration: If ``key`` is empty.

    Example::

        import os
        from arcjet import (
            arcjet,
            shield,
            detect_bot,
            token_bucket,
            Mode,
            BotCategory,
        )

        arcjet_key = os.getenv("ARCJET_KEY")
        if not arcjet_key:
            raise RuntimeError(
                "ARCJET_KEY is required. Get one at https://app.arcjet.com")

        aj = arcjet(
            key=arcjet_key,  # Get your key from https://app.arcjet.com
            rules=[
                # Shield protects your app from common attacks e.g. SQL injection
                shield(mode=Mode.LIVE),
                # Create a bot detection rule
                detect_bot(
                    mode=Mode.LIVE, allow=[
                        BotCategory.SEARCH_ENGINE,  # Google, Bing, etc
                        # Uncomment to allow these other common bot categories
                        # See the full list at https://docs.arcjet.com/bot-protection/identifying-bots
                        # BotCategory.MONITOR, # Uptime monitoring services
                        # BotCategory.PREVIEW, # Link previews e.g. Slack, Discord
                    ]
                ),
                # Create a token bucket rate limit. Other algorithms are supported
                token_bucket(
                    # Tracked by IP address by default, but this can be customized
                    # See https://docs.arcjet.com/fingerprints
                    # characteristics: ["ip.src"],
                    mode=Mode.LIVE,
                    refill_rate=5,  # Refill 5 tokens per interval
                    interval=10,  # Refill every 10 seconds
                    capacity=10,  # Bucket capacity of 10 tokens
                ),
            ],
        )
    """
    if not key:
        raise ArcjetMisconfiguration("Arcjet key is required.")
    # Always enable HTTP/2 by default.
    transport = pyqwest.HTTPTransport(http_version=pyqwest.HTTPVersion.HTTP2)
    client = DecideServiceClient(
        base_url.rstrip("/"), http_client=pyqwest.Client(transport)
    )
    return Arcjet(
        _key=key,
        _rules=tuple(rules),
        _client=client,
        _sdk_stack=stack,
        _sdk_version=_sdk_version() if sdk_version is None else sdk_version,
        _timeout_ms=_default_timeout_ms() if timeout_ms is None else timeout_ms,
        _fail_open=fail_open,
        _needs_email=any(isinstance(r, EmailValidation) for r in rules),
        _has_token_bucket=any(isinstance(r, TokenBucket) for r in rules),
        _proxies=tuple(proxies),
        _disable_automatic_ip_detection=disable_automatic_ip_detection,
    )


def arcjet_sync(
    *,
    key: str,
    rules: Sequence[RuleSpec],
    base_url: str = DEFAULT_BASE_URL,
    timeout_ms: int | None = None,
    stack: str | None = None,
    sdk_version: str | None = None,
    fail_open: bool = True,
    proxies: Sequence[str] = (),
    disable_automatic_ip_detection: bool = False,
) -> ArcjetSync:
    """Create a sync Arcjet client.

    Synchronous counterpart to ``arcjet()``. Use this with frameworks that do
    not support ``async/await`` such as Flask or Django.

    Args:
        ``key``: Your Arcjet site key from https://app.arcjet.com. Keep this
            secret — store it in an environment variable, never in source code.
        ``rules``: One or more rule specs created by ``shield()``, ``detect_bot()``,
            ``token_bucket()``, ``fixed_window()``, ``sliding_window()``, or
            ``validate_email()``.
        ``base_url``: Override the Arcjet Decide API endpoint. Only set this if directed by Arcjet support.
        ``timeout_ms``: Request timeout in milliseconds. Defaults to 1000 ms in
            development and 500 ms in production.
        ``fail_open``: When ``True`` (default), transport errors produce an ERROR
            decision instead of raising an exception, so your app stays
            available if Arcjet is temporarily unreachable. Set to ``False``
            to raise ``ArcjetTransportError`` on network failures instead.
        ``proxies``: IP addresses or CIDR ranges of trusted reverse proxies or
            load balancers sitting in front of your app. Arcjet skips these
            when resolving the real client IP from ``X-Forwarded-For``.
            Example: ``["10.0.0.0/8", "192.168.1.1"]``.
        ``disable_automatic_ip_detection``: Set to ``True`` to disable automatic
            IP extraction from request headers and supply the client IP
            yourself via ``ip_src`` on each ``protect()`` call. Only use this
            when you have your own validated IP-extraction logic. See
            https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For.

    Returns:
        An ``ArcjetSync`` sync client instance.

    Raises:
        ArcjetMisconfiguration: If ``key`` is empty.

    Example::

        import os
        from arcjet import (
            arcjet_sync,
            shield,
            detect_bot,
            token_bucket,
            Mode,
            BotCategory,
        )

        arcjet_key = os.getenv("ARCJET_KEY")
        if not arcjet_key:
            raise RuntimeError(
                "ARCJET_KEY is required. Get one at https://app.arcjet.com")

        aj = arcjet_sync(
            key=arcjet_key,  # Get your key from https://app.arcjet.com
            rules=[
                # Shield protects your app from common attacks e.g. SQL injection
                shield(mode=Mode.LIVE),
                # Create a bot detection rule
                detect_bot(
                    mode=Mode.LIVE, allow=[
                        BotCategory.SEARCH_ENGINE,  # Google, Bing, etc
                        # Uncomment to allow these other common bot categories
                        # See the full list at https://docs.arcjet.com/bot-protection/identifying-bots
                        # BotCategory.MONITOR, # Uptime monitoring services
                        # BotCategory.PREVIEW, # Link previews e.g. Slack, Discord
                    ]
                ),
                # Create a token bucket rate limit. Other algorithms are supported
                token_bucket(
                    # Tracked by IP address by default, but this can be customized
                    # See https://docs.arcjet.com/fingerprints
                    # characteristics: ["ip.src"],
                    mode=Mode.LIVE,
                    refill_rate=5,  # Refill 5 tokens per interval
                    interval=10,  # Refill every 10 seconds
                    capacity=10,  # Bucket capacity of 10 tokens
                ),
            ],
        )
    """
    if not key:
        raise ArcjetMisconfiguration("Arcjet key is required.")
    # Always enable HTTP/2 by default.
    transport = pyqwest.SyncHTTPTransport(http_version=pyqwest.HTTPVersion.HTTP2)
    client = DecideServiceClientSync(
        base_url.rstrip("/"), http_client=pyqwest.SyncClient(transport)
    )

    return ArcjetSync(
        _key=key,
        _rules=tuple(rules),
        _client=client,
        _sdk_stack=stack,
        _sdk_version=_sdk_version() if sdk_version is None else sdk_version,
        _timeout_ms=_default_timeout_ms() if timeout_ms is None else timeout_ms,
        _fail_open=fail_open,
        _needs_email=any(isinstance(r, EmailValidation) for r in rules),
        _has_token_bucket=any(isinstance(r, TokenBucket) for r in rules),
        _proxies=tuple(proxies),
        _disable_automatic_ip_detection=disable_automatic_ip_detection,
    )
