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

import os
from dataclasses import dataclass, replace, field
import logging
import time
from importlib.metadata import PackageNotFoundError, version as pkg_version
from typing import Mapping, Sequence, Any, TypedDict
import asyncio
import uuid

from proto.decide.v1alpha1 import decide_pb2
from proto.decide.v1alpha1.decide_connect import (
    DecideServiceClient,
    DecideServiceClientSync,
)
import httpx

from ._errors import ArcjetMisconfiguration, ArcjetTransportError
from ._logging import logger
from .context import (
    RequestContext,
    coerce_request_context,
    request_details_from_context,
)
from .decision import Decision
from .rules import RuleSpec, TokenBucket, EmailValidation
from .cache import DecisionCache, make_cache_key


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
    """Optional per-request options for `protect`.

    These are typically passed as keyword arguments to `Arcjet.protect` or
    `ArcjetSync.protect`.
    """

    requested: int
    characteristics: Mapping[str, Any]
    email: str
    extra: Mapping[str, str]


def _default_timeout_ms() -> int:
    # 1000ms in development, 500ms otherwise.
    env = (os.getenv("ARCJET_ENV") or "production").lower()
    return 1000 if env == "development" else 500


DEFAULT_BASE_URL = os.getenv("ARCJET_BASE_URL") or (
    "https://fly.decide.arcjet.com"
    if os.getenv("FLY_APP_NAME")
    else "https://decide.arcjet.com"
)


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
    """Arcjet client (async).

    Typical usage:
    ```python
    aj = arcjet(key="ajkey_...", rules=[...])
    decision = await aj.protect(request, requested=5)
    if decision.is_denied():
        ...
    ```

    Attributes are considered internal; prefer using the `arcjet(...)` factory
    to construct an instance with the right defaults.
    """

    _key: str
    _rules: tuple[RuleSpec, ...]
    _client: DecideServiceClient
    _session: Any | None
    _sdk_stack: int
    _sdk_version: str
    _timeout_ms: int | None
    _fail_open: bool
    _needs_email: bool = False
    _has_token_bucket: bool = False
    _proxies: tuple[str, ...] = ()
    _cache: DecisionCache = field(default_factory=DecisionCache)

    async def protect(
        self,
        request: Any,
        *,
        requested: int | None = None,
        characteristics: Mapping[str, Any] | None = None,
        email: str | None = None,
        extra: Mapping[str, str] | None = None,
    ) -> Decision:
        """Evaluate configured rules for a given request.

        Parameters: - request: A framework request (ASGI scope dict,
        Flask `Request`,
            Django `HttpRequest`) or a pre-built `RequestContext`.
        - requested: For token bucket rate limits, the request's cost
            (defaults to 1 when a token bucket rule is present).
        - characteristics: Configuration for how to track the client
            across requests.
        - email: Email address to validate when an email rule is
            configured.
        - extra: Arbitrary key/value pairs forwarded to the Decide API.

        Returns: - `Decision`: a convenience wrapper around the
        protobuf response with
            helpers like `.is_allowed()` and `.reason`.

        Raises: - `ArcjetMisconfiguration` when required context (e.g.
        `email`) is
            missing for the configured rules.
        - `ArcjetTransportError` for transport issues when
            `fail_open=False`.
        """
        t0 = time.perf_counter()
        ctx = coerce_request_context(request, proxies=self._proxies)
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
                    sdk_stack=self._sdk_stack,
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
            sdk_stack=self._sdk_stack,
            sdk_version=self._sdk_version,
            details=request_details_from_context(ctx),
        )
        req.rules.extend([r.to_proto() for r in self._rules])
        # Do not set `req.characteristics` here; rule-level configuration controls
        # which characteristics are used. When none provided, server defaults to IP.
        t_prepare_end = time.perf_counter()

        try:
            t_api_start = time.perf_counter()
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
                # Fail open: allow the request and record the error in the decision reason.
                logger.warning(
                    "arcjet fail_open allow due to transport error: error=%s api_ms=%.3f prepare_ms=%.3f total_ms=%.3f rules=%d",
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
                    conclusion=decide_pb2.CONCLUSION_ALLOW,
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
                    "arcjet fail_open allow due to invalid response: error=%s api_ms=%.3f prepare_ms=%.3f total_ms=%.3f rules=%d",
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
                    conclusion=decide_pb2.CONCLUSION_ALLOW,
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
            await close()
            return
        close_sync = getattr(self._client, "close", None)
        if callable(close_sync):
            close_sync()
        if self._session is not None:
            # We own the session; ensure it's closed to free sockets
            aclose = getattr(self._session, "aclose", None)
            if callable(aclose):
                await aclose()

    async def __aenter__(self) -> "Arcjet":
        """Async context manager entry; returns `self`."""
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        """Async context manager exit; ensures the client is closed."""
        await self.aclose()


@dataclass(slots=True)
class ArcjetSync:
    """Arcjet client (sync).

    Synchronous variant exposing the same `.protect(...)` shape as `Arcjet`.
    Prefer this when your application stack is synchronous.
    """

    _key: str
    _rules: tuple[RuleSpec, ...]
    _client: DecideServiceClientSync
    _session: Any | None
    _sdk_stack: int
    _sdk_version: str
    _timeout_ms: int | None
    _fail_open: bool
    _needs_email: bool = False
    _has_token_bucket: bool = False
    _proxies: tuple[str, ...] = ()
    _cache: DecisionCache = field(default_factory=DecisionCache)

    def protect(
        self,
        request: Any,
        *,
        requested: int | None = None,
        characteristics: Mapping[str, Any] | None = None,
        email: str | None = None,
        extra: Mapping[str, str] | None = None,
    ) -> Decision:
        """Evaluate configured rules for a given request (sync).

        See `Arcjet.protect` for parameter and behavior details.
        """
        t0 = time.perf_counter()
        ctx = coerce_request_context(request, proxies=self._proxies)
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
                    sdk_stack=self._sdk_stack,
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
            sdk_stack=self._sdk_stack,
            sdk_version=self._sdk_version,
            details=request_details_from_context(ctx),
        )
        req.rules.extend([r.to_proto() for r in self._rules])
        t_prepare_end = time.perf_counter()

        try:
            t_api_start = time.perf_counter()
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
                    "arcjet fail_open allow due to transport error: error=%s api_ms=%.3f prepare_ms=%.3f total_ms=%.3f rules=%d",
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
                    conclusion=decide_pb2.CONCLUSION_ALLOW,
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
                    "arcjet fail_open allow due to invalid response: error=%s api_ms=%.3f prepare_ms=%.3f total_ms=%.3f rules=%d",
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
                    conclusion=decide_pb2.CONCLUSION_ALLOW,
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
        if self._session is not None:
            # We own the session; ensure it's closed to free sockets
            sess_close = getattr(self._session, "close", None)
            if callable(sess_close):
                sess_close()

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
    stack: int = decide_pb2.SDK_STACK_PYTHON,
    sdk_version: str | None = None,
    fail_open: bool = True,
    proxies: Sequence[str] = (),
) -> Arcjet:
    """Create an async Arcjet client.

    Parameters:
    - `base_url`: Defaults to `ARCJET_BASE_URL` env var, then Fly.io internal
        URL when `FLY_APP_NAME` is set, otherwise the public Decide endpoint.
    - `timeout_ms`: Defaults to 1000ms in development and 500ms otherwise.
    - `fail_open`: When True (default), transport errors yield ALLOW decisions
        with an error reason instead of raising.
    """
    if not key:
        raise ArcjetMisconfiguration("Arcjet key is required.")
    # Always enable HTTP/2 by default.
    session = httpx.AsyncClient(http2=True)
    client = DecideServiceClient(base_url, session=session)
    return Arcjet(
        _key=key,
        _rules=tuple(rules),
        _client=client,
        _session=session,
        _sdk_stack=stack,
        _sdk_version=_sdk_version() if sdk_version is None else sdk_version,
        _timeout_ms=_default_timeout_ms() if timeout_ms is None else timeout_ms,
        _fail_open=fail_open,
        _needs_email=any(isinstance(r, EmailValidation) for r in rules),
        _has_token_bucket=any(isinstance(r, TokenBucket) for r in rules),
        _proxies=tuple(proxies),
    )


def arcjet_sync(
    *,
    key: str,
    rules: Sequence[RuleSpec],
    base_url: str = DEFAULT_BASE_URL,
    timeout_ms: int | None = None,
    stack: int = decide_pb2.SDK_STACK_PYTHON,
    sdk_version: str | None = None,
    fail_open: bool = True,
    proxies: Sequence[str] = (),
) -> ArcjetSync:
    """Create a sync Arcjet client.

    See `arcjet(...)` for parameter details and default behavior.
    """
    if not key:
        raise ArcjetMisconfiguration("Arcjet key is required.")
    # Always enable HTTP/2 by default.
    session = httpx.Client(http2=True)
    client = DecideServiceClientSync(base_url, session=session)
    return ArcjetSync(
        _key=key,
        _rules=tuple(rules),
        _client=client,
        _session=session,
        _sdk_stack=stack,
        _sdk_version=_sdk_version() if sdk_version is None else sdk_version,
        _timeout_ms=_default_timeout_ms() if timeout_ms is None else timeout_ms,
        _fail_open=fail_open,
        _needs_email=any(isinstance(r, EmailValidation) for r in rules),
        _has_token_bucket=any(isinstance(r, TokenBucket) for r in rules),
        _proxies=tuple(proxies),
    )
