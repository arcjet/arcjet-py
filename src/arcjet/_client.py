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
import atexit
import inspect
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
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

from ._cache import DecisionCache, make_cache_key
from ._context import (
    RequestContext,
    coerce_request_context,
    request_details_from_context,
)
from ._decision import Decision, materialize_cached_decision
from ._errors import ArcjetMisconfiguration, ArcjetTransportError
from ._ids import crockford32, uuidv7_bytes
from ._local import (
    evaluate_bot_locally,
    evaluate_email_locally,
    evaluate_filter_locally,
    evaluate_sensitive_info_locally,
)
from ._logging import logger
from ._metadata import (
    LocalWarning,
    Metadata,
    encode_metadata,
    enforce_metadata_budget,
)
from ._rules import (
    BotDetection,
    EmailValidation,
    Filter,
    FixedWindow,
    PromptInjectionDetection,
    RuleSpec,
    SensitiveInfoDetection,
    SlidingWindow,
    TokenBucket,
)
from ._transport import build_async_transport, build_sync_transport


def _fire_and_forget(coro: Any) -> None:
    """Schedule a coroutine as a fire-and-forget task.

    Suppresses 'Task exception was never retrieved' warnings by attaching
    a done callback that consumes the exception (the coroutine itself should
    already log any errors it catches).
    """
    task = asyncio.create_task(coro)
    task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)


# Lazy thread pool for fire-and-forget report requests (sync client).
# Initialized on first use so async-only callers don't pay for thread creation.
_report_pool: ThreadPoolExecutor | None = None
_report_pool_lock = threading.Lock()


def _get_report_pool() -> ThreadPoolExecutor:
    global _report_pool
    if _report_pool is not None:
        return _report_pool
    with _report_pool_lock:
        if _report_pool is None:
            _report_pool = ThreadPoolExecutor(
                max_workers=4, thread_name_prefix="arcjet-report"
            )
            atexit.register(_report_pool.shutdown, wait=True, cancel_futures=False)
        return _report_pool


def _new_local_request_id() -> str:
    """Generate a TypeID-compatible local request ID with ``lreq`` prefix.

    The suffix is a Crockford base32 encoding of a UUIDv7 (26 chars).
    See https://github.com/jetify-com/typeid for the specification.
    """
    return f"lreq_{crockford32(uuidv7_bytes())}"


class ProtectOptions(TypedDict, total=False):
    """Optional per-request keyword arguments for ``protect()``.

    All fields are optional. Pass them as keyword arguments directly to
    ``Arcjet.protect()`` or ``ArcjetSync.protect()``.
    """

    requested: int
    """Number of tokens to consume from the token bucket for this request.
    Defaults to 1 when a token bucket rule is configured."""

    characteristics: Mapping[str, Any]
    """Custom key/value pairs for client fingerprinting.

    Defaults to the client IP address. Keys must match characteristic names
    configured on your rules. Example: ``{"user_id": "123"}``.
    See https://docs.arcjet.com/fingerprints."""

    email: str
    """Email address to validate when a ``validate_email()`` rule is configured."""

    extra: Mapping[str, str]
    """Arbitrary key/value pairs forwarded verbatim to the Arcjet Decide API."""

    correlation_id: str
    """Optional, caller-supplied opaque identifier used to correlate this
    request with other ``protect()`` and ``guard()`` calls that belong to the
    same workflow, agent run, or multi-step task.

    It does not affect the decision and is excluded from fingerprinting (and the
    decision cache key), so two requests that differ only by correlation ID
    still share rate-limit state. Bounded server-side to 256 bytes of printable
    ASCII; invalid values are dropped, not truncated."""


# Deadline for a protect() call when timeout_ms is not set.
#
# Sized for the slowest rules: a cold prompt-injection or content-moderation
# start can exceed the old 500ms production default, and a tight deadline
# fail-opens instead of evaluating the rule. Matches Guard's default.
_DEFAULT_TIMEOUT_MS = 2000


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


def _run_local_rules(
    ctx: RequestContext,
    rules: tuple[RuleSpec, ...],
) -> Decision | None:
    """Run local WASM evaluation for rules that support it.

    Returns a DENY Decision if any rule denies in LIVE mode (short-circuit),
    or None if all locally-evaluated rules allow (proceed to remote API).
    """
    local_results: list[decide_pb2.RuleResult] = []

    for rule in rules:
        result: decide_pb2.RuleResult | None = None
        if isinstance(rule, BotDetection):
            result = evaluate_bot_locally(ctx, rule)
        elif isinstance(rule, EmailValidation):
            result = evaluate_email_locally(ctx, rule)
        elif isinstance(rule, SensitiveInfoDetection):
            result = evaluate_sensitive_info_locally(ctx, rule)
        elif isinstance(rule, Filter):
            result = evaluate_filter_locally(ctx, rule)

        if result is None:
            continue

        local_results.append(result)

        # Short-circuit: if a local rule denies in RUN mode, return immediately
        if result.conclusion == decide_pb2.CONCLUSION_DENY:
            if result.state == decide_pb2.RULE_STATE_RUN:
                # Propagate TTL from the denying rule result to the decision.
                ttl = result.ttl
                decision = decide_pb2.Decision(
                    id=_new_local_request_id(),
                    conclusion=decide_pb2.CONCLUSION_DENY,
                    reason=result.reason,
                    rule_results=local_results,
                    ttl=ttl,
                )
                return Decision(decision)
            else:
                # DRY_RUN deny — log but don't short-circuit
                logger.debug(
                    "local rule would deny (dry-run): rule=%s",
                    type(rule).__name__,
                )

    return None


def _redact_report_details(
    ctx: RequestContext,
) -> decide_pb2.RequestDetails:
    """Build RequestDetails for a Report call with sensitive fields redacted.

    Reports are sent when the decision is already known locally (cache hit or
    local WASM deny). The server receives the context for dashboard/logging
    purposes only — it never re-runs detection — so fields that contain raw
    user content must not be sent in plain text.

    ``detectPromptInjectionMessage`` is redacted here for the same reason that
    ``sensitiveInfoValue`` is always redacted in ``request_details_from_context``:
    both fields may contain PII or otherwise sensitive user input.
    """
    details = request_details_from_context(ctx)
    if "detectPromptInjectionMessage" in details.extra:
        details.extra["detectPromptInjectionMessage"] = "<redacted>"
    return details


def _apply_metadata(
    request: decide_pb2.DecideRequest | decide_pb2.ReportRequest,
    metadata_json: Mapping[str, str],
    local_warnings: Sequence[LocalWarning],
) -> None:
    """Attach encoded ``metadata_json`` and client-side ``local_warnings`` to a
    Decide or Report request.

    Both RPCs carry the same fields so a decision and its report describe the
    same metadata. The map is already JSON-encoded per top-level key by
    :func:`~arcjet._metadata.encode_metadata` and is stored verbatim; the server
    enforces the count/size/depth/key limits and warns on anything it drops.
    """
    warnings = list(local_warnings)
    for key, value in metadata_json.items():
        request.metadata_json[key] = value
    # Trim to the SDK ceiling after the map is on the request, so an oversized
    # blob cannot push the request past the 1 MiB protocol limit and get it
    # rejected — a rejected request is a fail open.
    warnings.extend(enforce_metadata_budget([request.metadata_json]))
    request.local_warnings.extend(
        decide_pb2.Warning(code=w.code, message=w.message) for w in warnings
    )


def _build_local_deny_report(
    sdk_stack_val: str | None,
    sdk_version: str,
    ctx: RequestContext,
    local_decision: Decision,
    rules: tuple[RuleSpec, ...],
    metadata_json: Mapping[str, str] | None = None,
    local_warnings: Sequence[LocalWarning] | None = None,
) -> decide_pb2.ReportRequest:
    """Build a ReportRequest for a local DENY decision.

    This mirrors the cache-hit report pattern: the server receives the
    decision so it appears in the Arcjet dashboard even though no remote
    Decide call was made.
    """
    dec = local_decision.to_proto()
    rep = decide_pb2.ReportRequest(
        sdk_stack=_sdk_stack(sdk_stack_val),
        sdk_version=sdk_version,
        details=_redact_report_details(ctx),
        decision=dec,
    )
    rep.rules.extend([r.to_proto() for r in rules])
    _apply_metadata(rep, metadata_json or {}, local_warnings or ())
    return rep


def _try_cache_decision(
    cache: DecisionCache,
    key: str | None,
    decision: Decision,
) -> None:
    """Cache *decision* if it is a DENY with TTL > 0.

    Only DENY decisions are cached, matching JS SDK semantics.
    ALLOW/ERROR/CHALLENGE decisions are never cached.
    """
    try:
        if decision.is_denied() and decision.ttl > 0 and key is not None:
            cache.set(key, decision, decision.ttl)
    except Exception:
        pass


# Rate-limit rule types that inherit global characteristics when they have none.
_RATE_LIMIT_TYPES = (TokenBucket, FixedWindow, SlidingWindow)


def _apply_global_characteristics(
    rules: tuple[RuleSpec, ...],
    characteristics: tuple[str, ...],
) -> tuple[RuleSpec, ...]:
    """Apply global characteristics to rate-limit rules that lack their own.

    Returns a new tuple with the same rules, except rate-limit rules whose
    ``characteristics`` field is empty get a copy with the global value filled in.
    Non-rate-limit rules and rules that already define characteristics are
    returned unchanged.
    """
    if not characteristics:
        return rules
    out: list[RuleSpec] = []
    for r in rules:
        if isinstance(r, _RATE_LIMIT_TYPES) and not r.characteristics:
            r = replace(r, characteristics=characteristics)
        out.append(r)
    return tuple(out)


@dataclass(slots=True)
class Arcjet:
    """Async Arcjet client.

    Evaluates HTTP requests against a configured set of security rules.
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
                "ARCJET_KEY is required. Get one with: arcjet sites get-key"
                " or from https://app.arcjet.com")

        aj = arcjet(
            key=arcjet_key,  # Get your key with: arcjet sites get-key
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
        # FastAPI: from fastapi.responses import JSONResponse
        decision = await aj.protect(request, requested=1)
        if decision.is_denied():
            return JSONResponse({"error": "Forbidden"}, status_code=403)
    """

    # Kept out of the generated repr. The key authenticates as this site, and a
    # client reaches a great many places that render objects: a traceback
    # captured with frame locals, a log line, an error reporter, a debugger.
    _key: str = field(repr=False)
    _rules: tuple[RuleSpec, ...]
    _client: DecideServiceClient
    _sdk_stack: str | None
    _sdk_version: str
    _timeout_ms: int | None
    _fail_open: bool
    _needs_email: bool = False
    _needs_message: bool = False
    _has_token_bucket: bool = False
    _proxies: tuple[str, ...] = ()
    _disable_automatic_ip_detection: bool = False
    _cache: DecisionCache = field(default_factory=DecisionCache)
    _environment: str | None = None

    async def protect(
        self,
        request: Any,
        *,
        requested: int | None = None,
        characteristics: Mapping[str, Any] | None = None,
        email: str | None = None,
        sensitive_info_value: str | None = None,
        detect_prompt_injection_message: str | None = None,
        extra: Mapping[str, str] | None = None,
        metadata: Metadata | None = None,
        filter_local: Mapping[str, str] | None = None,
        correlation_id: str | None = None,
        ip_src: str | None = None,
    ) -> Decision:
        """Evaluate the configured security rules against an incoming request.

        Call this once per request, typically at the start of your route
        handler before running any application logic. The returned ``Decision``
        tells you whether to allow or deny the request.

        Args:
            request: The incoming HTTP request. Accepts ASGI scope dicts,
                Flask/Werkzeug ``Request`` objects, Django ``HttpRequest``
                objects, or a ``RequestContext`` built manually.
            requested: Number of tokens to consume for this request when a
                ``token_bucket()`` rule is configured. Defaults to 1.
            characteristics: Custom key/value pairs for client fingerprinting.
                Defaults to the client IP address. Keys must match
                characteristic names configured on your rules.
                Example: ``{"user_id": current_user.id}``.
            email: Email address to validate when a ``validate_email()`` rule
                is configured. Required if email validation is active.
            detect_prompt_injection_message: The user-supplied text to analyze
                for prompt injection attacks. Required when a
                ``detect_prompt_injection()`` rule is configured.
            extra: Additional key/value pairs forwarded verbatim to the Arcjet
                Decide API. SDK-derived request context; prefer ``metadata`` for
                your own application data.
            metadata: Structured metadata for correlation and analytics — string
                keys mapped to any JSON-serializable value, including nested
                objects and arrays. Each top-level value is JSON-encoded by the
                SDK and stored verbatim, so exact integers survive. Server-
                enforced limits: 128 top-level keys, 4 KiB per serialized value,
                10 levels of nesting, and key names limited to letters, digits,
                dash, dot, and underscore. Anything over a limit drops that one
                key with a warning — never a failed call, and never a changed
                decision (metadata is excluded from fingerprinting and from the
                decision cache key). Metadata is untrusted: do not put secrets
                or PII in it.
            filter_local: Additional key/value pairs available as ``local.<key>``
                in ``filter_request()`` expressions. Only used when a
                ``filter_request()`` rule is configured.
            correlation_id: Optional opaque identifier used to correlate this
                request with other ``protect()``/``guard()`` calls in the same
                workflow or agent run. Does not affect the decision and is
                excluded from fingerprinting (and the decision cache key).
            ip_src: Override the detected client IP. Only valid when
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

            # FastAPI: from fastapi.responses import JSONResponse
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
        ctx = coerce_request_context(
            request,
            proxies=self._proxies,
            ip_src=ip_src,
            environment=self._environment,
        )

        if email:
            ctx = replace(ctx, email=email)
        if sensitive_info_value:
            ctx = replace(ctx, sensitive_info_value=sensitive_info_value)
        if detect_prompt_injection_message:
            ctx = replace(
                ctx, detect_prompt_injection_message=detect_prompt_injection_message
            )
        if filter_local:
            ctx = replace(ctx, filter_local=filter_local)
        if correlation_id:
            ctx = replace(ctx, correlation_id=correlation_id)
        # Enforce required per-request context based on configured rules.
        if self._needs_email and not (email or ctx.email):
            raise ArcjetMisconfiguration(
                "email is required when validate_email(...) is configured. "
                "Pass email=... to aj.protect(...)."
            )
        if self._needs_message and not (
            detect_prompt_injection_message or ctx.detect_prompt_injection_message
        ):
            raise ArcjetMisconfiguration(
                "detect_prompt_injection_message is required when detect_prompt_injection(...) is configured. "
                "Pass detect_prompt_injection_message=... to aj.protect(...)."
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

        ctx = replace(ctx, extra=merged_extra or None)

        # metadata is JSON-encoded once and attached to every request this call
        # may send (Decide, or a Report on a cache hit or local deny). It is
        # deliberately not part of the cache key: metadata never affects a
        # decision.
        metadata_json, metadata_warnings = encode_metadata(metadata)
        for warning in metadata_warnings:
            # The message names only the offending keys, escaped and
            # length-bounded by `encode_metadata`, so a key containing control
            # characters cannot forge a log entry.
            logger.warning(
                "arcjet %s",
                warning.message,
                extra={
                    "event": "arcjet_metadata_dropped",
                    "code": warning.code,
                },
            )

        # Cache lookup before hitting Decide API
        cache_key = make_cache_key(ctx, self._rules)
        cached_hit = self._cache.get(cache_key) if cache_key is not None else None
        if cached_hit is not None:
            cached, remaining_ttl = cached_hit
            # Isolate the caller from the cached proto: new id, live TTL, and
            # a rewritten rate-limit reset. The object in the cache is unchanged.
            served = materialize_cached_decision(
                cached, remaining_ttl, _new_local_request_id()
            )
            # Fire-and-forget async report; do not await
            try:
                dec = served.to_proto()
                rep = decide_pb2.ReportRequest(
                    sdk_stack=_sdk_stack(self._sdk_stack),
                    sdk_version=self._sdk_version,
                    details=_redact_report_details(ctx),
                    decision=dec,
                )
                rep.rules.extend([r.to_proto() for r in self._rules])
                _apply_metadata(rep, metadata_json, metadata_warnings)

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

                _fire_and_forget(_send_report())
                # Log cache-hit report scheduling with latency figures similar to decide
                if logger.isEnabledFor(logging.DEBUG):
                    t_prepare_end = time.perf_counter()
                    total_ms = (time.perf_counter() - t0) * 1000.0
                    prepare_ms = (t_prepare_end - t0) * 1000.0
                    api_ms = 0.0  # fire-and-forget; API latency not measured here
                    logger.debug(
                        "report: id=%s conclusion=%s reason=%s ttl=%s api_ms=%.3f prepare_ms=%.3f total_ms=%.3f rules=%d",
                        dec.id,
                        decide_pb2.Conclusion.Name(served.conclusion),
                        served.reason.which(),
                        str(served.ttl),
                        round(api_ms, 3),
                        round(prepare_ms, 3),
                        round(total_ms, 3),
                        len(self._rules),
                        extra={
                            "event": "arcjet_report_cache_hit",
                            "decision_id": dec.id,
                            "conclusion": decide_pb2.Conclusion.Name(served.conclusion),
                            "reason": served.reason.which(),
                            "ttl": served.ttl,
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
            return served

        # Local WASM evaluation: run bot/email rules locally before remote API
        local_decision = _run_local_rules(ctx, self._rules)
        if local_decision is not None:
            # Fire-and-forget report so local denies appear in the dashboard
            try:
                rep = _build_local_deny_report(
                    self._sdk_stack,
                    self._sdk_version,
                    ctx,
                    local_decision,
                    self._rules,
                    metadata_json,
                    metadata_warnings,
                )

                async def _send_local_report():
                    try:
                        await self._client.report(
                            rep,
                            headers=_auth_headers(self._key),
                            timeout_ms=self._timeout_ms,
                        )
                    except Exception as e:
                        logger.debug(
                            "report error on local decision: error=%s",
                            str(e),
                            extra={
                                "event": "arcjet_report_error",
                                "error": str(e),
                            },
                        )

                _fire_and_forget(_send_local_report())
            except Exception as e:
                logger.debug(
                    "local decision report scheduling error: error=%s",
                    str(e),
                    extra={
                        "event": "arcjet_report_schedule_error",
                        "error": str(e),
                    },
                )
            _try_cache_decision(self._cache, cache_key, local_decision)
            logger.debug(
                "local decision: id=%s conclusion=%s",
                local_decision.id,
                decide_pb2.Conclusion.Name(local_decision.conclusion),
            )
            return local_decision

        req = decide_pb2.DecideRequest(
            sdk_stack=_sdk_stack(self._sdk_stack),
            sdk_version=self._sdk_version,
            details=request_details_from_context(ctx),
        )
        req.rules.extend([r.to_proto() for r in self._rules])
        _apply_metadata(req, metadata_json, metadata_warnings)
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
        _try_cache_decision(self._cache, cache_key, decision)
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
                "ARCJET_KEY is required. Get one with: arcjet sites get-key"
                " or from https://app.arcjet.com")

        aj = arcjet_sync(
            key=arcjet_key,  # Get your key with: arcjet sites get-key
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
        # Flask: from flask import jsonify
        decision = aj.protect(request)
        if decision.is_denied():
            return jsonify(error="Forbidden"), 403
    """

    # Kept out of the generated repr. The key authenticates as this site, and a
    # client reaches a great many places that render objects: a traceback
    # captured with frame locals, a log line, an error reporter, a debugger.
    _key: str = field(repr=False)
    _rules: tuple[RuleSpec, ...]
    _client: DecideServiceClientSync
    _sdk_stack: str | None
    _sdk_version: str
    _timeout_ms: int | None
    _fail_open: bool
    _needs_email: bool = False
    _needs_message: bool = False
    _has_token_bucket: bool = False
    _proxies: tuple[str, ...] = ()
    _disable_automatic_ip_detection: bool = False
    _cache: DecisionCache = field(default_factory=DecisionCache)
    _environment: str | None = None

    def protect(
        self,
        request: Any,
        *,
        requested: int | None = None,
        characteristics: Mapping[str, Any] | None = None,
        email: str | None = None,
        sensitive_info_value: str | None = None,
        detect_prompt_injection_message: str | None = None,
        extra: Mapping[str, str] | None = None,
        metadata: Metadata | None = None,
        filter_local: Mapping[str, str] | None = None,
        correlation_id: str | None = None,
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
        ctx = coerce_request_context(
            request,
            proxies=self._proxies,
            ip_src=ip_src,
            environment=self._environment,
        )

        if email:
            ctx = replace(ctx, email=email)
        if sensitive_info_value:
            ctx = replace(ctx, sensitive_info_value=sensitive_info_value)
        if detect_prompt_injection_message:
            ctx = replace(
                ctx, detect_prompt_injection_message=detect_prompt_injection_message
            )
        if filter_local:
            ctx = replace(ctx, filter_local=filter_local)
        if correlation_id:
            ctx = replace(ctx, correlation_id=correlation_id)
        # Enforce required per-request context based on configured rules.
        if self._needs_email and not (email or ctx.email):
            raise ArcjetMisconfiguration(
                "email is required when validate_email(...) is configured. "
                "Pass email=... to aj.protect(...)."
            )
        if self._needs_message and not (
            detect_prompt_injection_message or ctx.detect_prompt_injection_message
        ):
            raise ArcjetMisconfiguration(
                "detect_prompt_injection_message is required when detect_prompt_injection(...) is configured. "
                "Pass detect_prompt_injection_message=... to aj.protect(...)."
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

        ctx = replace(ctx, extra=merged_extra or None)

        # metadata is JSON-encoded once and attached to every request this call
        # may send (Decide, or a Report on a cache hit or local deny). It is
        # deliberately not part of the cache key: metadata never affects a
        # decision.
        metadata_json, metadata_warnings = encode_metadata(metadata)
        for warning in metadata_warnings:
            # The message names only the offending keys, escaped and
            # length-bounded by `encode_metadata`, so a key containing control
            # characters cannot forge a log entry.
            logger.warning(
                "arcjet %s",
                warning.message,
                extra={
                    "event": "arcjet_metadata_dropped",
                    "code": warning.code,
                },
            )

        # Cache lookup before hitting Decide API
        cache_key = make_cache_key(ctx, self._rules)
        cached_hit = self._cache.get(cache_key) if cache_key is not None else None
        if cached_hit is not None:
            cached, remaining_ttl = cached_hit
            served = materialize_cached_decision(
                cached, remaining_ttl, _new_local_request_id()
            )
            # Fire-and-forget background report using sync client
            try:
                dec = served.to_proto()
                rep = decide_pb2.ReportRequest(
                    sdk_stack=_sdk_stack(self._sdk_stack),
                    sdk_version=self._sdk_version,
                    details=_redact_report_details(ctx),
                    decision=dec,
                )
                rep.rules.extend([r.to_proto() for r in self._rules])
                _apply_metadata(rep, metadata_json, metadata_warnings)

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

                _get_report_pool().submit(_send_report_sync)

                if logger.isEnabledFor(logging.DEBUG):
                    t_prepare_end = time.perf_counter()
                    total_ms = (time.perf_counter() - t0) * 1000.0
                    prepare_ms = (t_prepare_end - t0) * 1000.0
                    api_ms = 0.0  # fire-and-forget; API latency not measured here
                    logger.debug(
                        "report (cache-hit sync): id=%s conclusion=%s reason=%s ttl=%s api_ms=%.3f prepare_ms=%.3f total_ms=%.3f rules=%d",
                        dec.id,
                        decide_pb2.Conclusion.Name(served.conclusion),
                        served.reason.which(),
                        str(served.ttl),
                        round(api_ms, 3),
                        round(prepare_ms, 3),
                        round(total_ms, 3),
                        len(self._rules),
                        extra={
                            "event": "arcjet_report_cache_hit",
                            "decision_id": dec.id,
                            "conclusion": decide_pb2.Conclusion.Name(served.conclusion),
                            "reason": served.reason.which(),
                            "ttl": served.ttl,
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
            return served

        # Local WASM evaluation: run bot/email rules locally before remote API
        local_decision = _run_local_rules(ctx, self._rules)
        if local_decision is not None:
            # Fire-and-forget report so local denies appear in the dashboard
            try:
                rep = _build_local_deny_report(
                    self._sdk_stack,
                    self._sdk_version,
                    ctx,
                    local_decision,
                    self._rules,
                    metadata_json,
                    metadata_warnings,
                )

                def _send_local_report_sync():
                    try:
                        self._client.report(
                            rep,
                            headers=_auth_headers(self._key),
                            timeout_ms=self._timeout_ms,
                        )
                    except Exception as e:
                        logger.debug(
                            "report error on local decision (sync): error=%s",
                            str(e),
                            extra={
                                "event": "arcjet_report_error",
                                "error": str(e),
                            },
                        )

                _get_report_pool().submit(_send_local_report_sync)
            except Exception as e:
                logger.debug(
                    "local decision report scheduling error (sync): error=%s",
                    str(e),
                    extra={
                        "event": "arcjet_report_schedule_error",
                        "error": str(e),
                    },
                )
            _try_cache_decision(self._cache, cache_key, local_decision)
            logger.debug(
                "local decision: id=%s conclusion=%s",
                local_decision.id,
                decide_pb2.Conclusion.Name(local_decision.conclusion),
            )
            return local_decision

        req = decide_pb2.DecideRequest(
            sdk_stack=_sdk_stack(self._sdk_stack),
            sdk_version=self._sdk_version,
            details=request_details_from_context(ctx),
        )
        req.rules.extend([r.to_proto() for r in self._rules])
        _apply_metadata(req, metadata_json, metadata_warnings)
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
        _try_cache_decision(self._cache, cache_key, decision)
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
    characteristics: Sequence[str] = (),
    base_url: str = DEFAULT_BASE_URL,
    timeout_ms: int | None = None,
    stack: str | None = None,
    sdk_version: str | None = None,
    fail_open: bool = True,
    proxies: Sequence[str] = (),
    disable_automatic_ip_detection: bool = False,
    environment: str | None = None,
) -> Arcjet:
    """Create an async Arcjet client.

    Args:
        key: Your Arcjet site key. Get one with ``arcjet sites get-key``
            or at https://app.arcjet.com. Keep this secret — store it in an
            environment variable, never in source code.
        rules: One or more rule specs created by ``shield()``, ``detect_bot()``,
            ``token_bucket()``, ``fixed_window()``, ``sliding_window()``, or
            ``validate_email()``.
        characteristics: Global fingerprint characteristics applied to all
            rate-limit rules that don't define their own. Defaults to empty
            (server uses IP address). See https://docs.arcjet.com/fingerprints.
        base_url: Override the Arcjet Decide API endpoint. Only set this if
            directed by Arcjet support.
        timeout_ms: Request timeout in milliseconds. Defaults to 2000 ms.
        fail_open: When ``True`` (default), transport errors produce an ERROR
            decision instead of raising an exception, so your app stays
            available if Arcjet is temporarily unreachable. Set to ``False``
            to raise ``ArcjetTransportError`` on network failures instead.
        proxies: IP addresses or CIDR ranges of trusted reverse proxies or
            load balancers sitting in front of your app. Arcjet skips these
            when resolving the real client IP from ``X-Forwarded-For``.
            Example: ``["10.0.0.0/8", "192.168.1.1"]``.
        disable_automatic_ip_detection: Set to ``True`` to disable automatic
            IP extraction from request headers and supply the client IP
            yourself via ``ip_src`` on each ``protect()`` call. Only use this
            when you have your own validated IP-extraction logic. See
            https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For.
        environment: Environment mode (``"development"`` or ``"production"``).
            When ``None`` (default), falls back to the ``ARCJET_ENV``
            environment variable. Set this explicitly when using a config
            library such as ``pydantic-settings`` that loads ``.env`` files
            into a typed settings object without propagating values to
            ``os.environ``::

                aj = arcjet(key=..., rules=[...], environment=settings.ARCJET_ENV)

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
                "ARCJET_KEY is required. Get one with: arcjet sites get-key"
                " or from https://app.arcjet.com")

        aj = arcjet(
            key=arcjet_key,  # Get your key with: arcjet sites get-key
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
    resolved_rules = _apply_global_characteristics(tuple(rules), tuple(characteristics))
    transport = build_async_transport()
    client = DecideServiceClient(
        base_url.rstrip("/"), http_client=pyqwest.Client(transport)
    )
    return Arcjet(
        _key=key,
        _rules=resolved_rules,
        _client=client,
        _sdk_stack=stack,
        _sdk_version=_sdk_version() if sdk_version is None else sdk_version,
        _timeout_ms=_DEFAULT_TIMEOUT_MS if timeout_ms is None else timeout_ms,
        _fail_open=fail_open,
        _needs_email=any(isinstance(r, EmailValidation) for r in rules),
        _needs_message=any(isinstance(r, PromptInjectionDetection) for r in rules),
        _has_token_bucket=any(isinstance(r, TokenBucket) for r in rules),
        _proxies=tuple(proxies),
        _disable_automatic_ip_detection=disable_automatic_ip_detection,
        _environment=environment,
    )


def arcjet_sync(
    *,
    key: str,
    rules: Sequence[RuleSpec],
    characteristics: Sequence[str] = (),
    base_url: str = DEFAULT_BASE_URL,
    timeout_ms: int | None = None,
    stack: str | None = None,
    sdk_version: str | None = None,
    fail_open: bool = True,
    proxies: Sequence[str] = (),
    disable_automatic_ip_detection: bool = False,
    environment: str | None = None,
) -> ArcjetSync:
    """Create a sync Arcjet client.

    Synchronous counterpart to ``arcjet()``. Use this with frameworks that do
    not support ``async/await`` such as Flask or Django.

    Args:
        key: Your Arcjet site key. Get one with ``arcjet sites get-key``
            or at https://app.arcjet.com. Keep this secret — store it in an
            environment variable, never in source code.
        rules: One or more rule specs created by ``shield()``, ``detect_bot()``,
            ``token_bucket()``, ``fixed_window()``, ``sliding_window()``, or
            ``validate_email()``.
        characteristics: Global fingerprint characteristics applied to all
            rate-limit rules that don't define their own. Defaults to empty
            (server uses IP address). See https://docs.arcjet.com/fingerprints.
        base_url: Override the Arcjet Decide API endpoint. Only set this if
            directed by Arcjet support.
        timeout_ms: Request timeout in milliseconds. Defaults to 2000 ms.
        fail_open: When ``True`` (default), transport errors produce an ERROR
            decision instead of raising an exception, so your app stays
            available if Arcjet is temporarily unreachable. Set to ``False``
            to raise ``ArcjetTransportError`` on network failures instead.
        proxies: IP addresses or CIDR ranges of trusted reverse proxies or
            load balancers sitting in front of your app. Arcjet skips these
            when resolving the real client IP from ``X-Forwarded-For``.
            Example: ``["10.0.0.0/8", "192.168.1.1"]``.
        disable_automatic_ip_detection: Set to ``True`` to disable automatic
            IP extraction from request headers and supply the client IP
            yourself via ``ip_src`` on each ``protect()`` call. Only use this
            when you have your own validated IP-extraction logic. See
            https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For.
        environment: Environment mode (``"development"`` or ``"production"``).
            When ``None`` (default), falls back to the ``ARCJET_ENV``
            environment variable. Set this explicitly when using a config
            library such as ``pydantic-settings`` that loads ``.env`` files
            into a typed settings object without propagating values to
            ``os.environ``::

                aj = arcjet_sync(key=..., rules=[...], environment=settings.ARCJET_ENV)

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
                "ARCJET_KEY is required. Get one with: arcjet sites get-key"
                " or from https://app.arcjet.com")

        aj = arcjet_sync(
            key=arcjet_key,  # Get your key with: arcjet sites get-key
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
    resolved_rules = _apply_global_characteristics(tuple(rules), tuple(characteristics))
    transport = build_sync_transport()
    client = DecideServiceClientSync(
        base_url.rstrip("/"), http_client=pyqwest.SyncClient(transport)
    )

    return ArcjetSync(
        _key=key,
        _rules=resolved_rules,
        _client=client,
        _sdk_stack=stack,
        _sdk_version=_sdk_version() if sdk_version is None else sdk_version,
        _timeout_ms=_DEFAULT_TIMEOUT_MS if timeout_ms is None else timeout_ms,
        _fail_open=fail_open,
        _needs_email=any(isinstance(r, EmailValidation) for r in rules),
        _needs_message=any(isinstance(r, PromptInjectionDetection) for r in rules),
        _has_token_bucket=any(isinstance(r, TokenBucket) for r in rules),
        _proxies=tuple(proxies),
        _disable_automatic_ip_detection=disable_automatic_ip_detection,
        _environment=environment,
    )
