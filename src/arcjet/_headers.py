"""Helpers for applying Arcjet decisions to HTTP response headers.

Mirrors ``@arcjet/decorate`` ``setRateLimitHeaders`` in the JS SDK: emit
``RateLimit`` and ``RateLimit-Policy`` from the IETF Rate Limit Fields draft.
"""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import Any

from arcjet._dataclasses import RateLimitReason
from arcjet._decision import Decision
from arcjet._logging import logger


def _to_limit_string(reason: RateLimitReason) -> str:
    return (
        f"limit={reason.max}, remaining={reason.remaining}, "
        f"reset={int(reason.reset.total_seconds())}"
    )


def _to_policy_string(max_requests: int, window_seconds: int) -> str:
    return f"{max_requests};w={window_seconds}"


def _nearest_limit(current: RateLimitReason, nxt: RateLimitReason) -> RateLimitReason:
    if current.remaining < nxt.remaining:
        return current
    if current.remaining > nxt.remaining:
        return nxt
    if current.reset < nxt.reset:
        return current
    if current.reset > nxt.reset:
        return nxt
    if current.max < nxt.max:
        return current
    return nxt


def _rate_limit_reasons(decision: Decision) -> list[RateLimitReason]:
    reasons = [
        result.reason_v2
        for result in decision.results
        if isinstance(result.reason_v2, RateLimitReason)
    ]
    if reasons:
        return reasons
    if isinstance(decision.reason_v2, RateLimitReason):
        return [decision.reason_v2]
    return []


def _is_header_like(value: Any) -> bool:
    return (
        hasattr(value, "has")
        and callable(value.has)
        and hasattr(value, "get")
        and callable(value.get)
        and hasattr(value, "set")
        and callable(value.set)
    )


def _is_outgoing_message_like(value: Any) -> bool:
    return (
        isinstance(getattr(value, "headersSent", None), bool)
        and hasattr(value, "hasHeader")
        and callable(value.hasHeader)
        and hasattr(value, "getHeader")
        and callable(value.getHeader)
        and hasattr(value, "setHeader")
        and callable(value.setHeader)
    )


def _warn_existing(name: str, original: Any, new: str) -> None:
    logger.warning(
        "Response already contains `%s` header (original=%s new=%s)",
        name,
        original,
        new,
    )


def _apply_headers(target: Any, limit: str, policy: str) -> bool:
    """Write the two IETF headers onto *target*. Return ``False`` if unsupported."""
    if _is_header_like(target):
        if target.has("RateLimit"):
            _warn_existing("RateLimit", target.get("RateLimit"), limit)
        if target.has("RateLimit-Policy"):
            _warn_existing(
                "RateLimit-Policy", target.get("RateLimit-Policy"), policy
            )
        target.set("RateLimit", limit)
        target.set("RateLimit-Policy", policy)
        return True

    headers = getattr(target, "headers", None)
    if headers is not None and _is_header_like(headers):
        return _apply_headers(headers, limit, policy)

    if _is_outgoing_message_like(target):
        if target.headersSent:
            logger.error("Headers have already been sent—cannot set RateLimit header")
            return True
        if target.hasHeader("RateLimit"):
            _warn_existing("RateLimit", target.getHeader("RateLimit"), limit)
        if target.hasHeader("RateLimit-Policy"):
            _warn_existing(
                "RateLimit-Policy", target.getHeader("RateLimit-Policy"), policy
            )
        target.setHeader("RateLimit", limit)
        target.setHeader("RateLimit-Policy", policy)
        return True

    mapping: MutableMapping[str, str] | None
    if isinstance(target, MutableMapping):
        mapping = target
    elif isinstance(headers, MutableMapping):
        mapping = headers
    elif headers is not None and hasattr(headers, "__setitem__"):
        mapping = headers
    elif hasattr(target, "__setitem__") and hasattr(target, "__contains__"):
        mapping = target
    else:
        mapping = None

    if mapping is None:
        return False

    if "RateLimit" in mapping:
        _warn_existing("RateLimit", mapping["RateLimit"], limit)
    if "RateLimit-Policy" in mapping:
        _warn_existing("RateLimit-Policy", mapping["RateLimit-Policy"], policy)
    mapping["RateLimit"] = limit
    mapping["RateLimit-Policy"] = policy
    return True


def set_rate_limit_headers(target: Any, decision: Decision) -> None:
    """Set ``RateLimit`` and ``RateLimit-Policy`` on a response or header map.

    Accepts Fetch-style ``Headers`` (``.has`` / ``.get`` / ``.set``), an
    object with those methods on ``.headers`` (Starlette / FastAPI /
    Flask), a Node-style ``setHeader`` response, or a mutable mapping.

    When several rate-limit results are present, the tightest remaining
    budget is advertised, matching ``@arcjet/decorate``.

    Args:
        target: Response or header map to decorate.
        decision: Decision returned from ``protect()``.

    Example::

        from arcjet import set_rate_limit_headers

        decision = await aj.protect(request, requested=1)
        set_rate_limit_headers(response, decision)
        if decision.is_denied():
            return JSONResponse({"error": "Too many requests"}, status_code=429)
    """
    reasons = _rate_limit_reasons(decision)
    if not reasons:
        return

    policies: dict[int, int] = {}
    for reason in reasons:
        window_seconds = int(reason.window.total_seconds())
        # JS rejects two policies that share the same limit, even when the
        # windows match — the IETF field cannot disambiguate them.
        if reason.max in policies:
            logger.error(
                "Invalid rate limit policy—two policies should not share the same limit"
            )
            return
        policies[reason.max] = window_seconds

    nearest = reasons[0]
    for reason in reasons[1:]:
        nearest = _nearest_limit(nearest, reason)

    limit = _to_limit_string(nearest)
    policy = ", ".join(
        _to_policy_string(max_requests, window)
        for max_requests, window in sorted(policies.items())
    )

    if not _apply_headers(target, limit, policy):
        logger.debug(
            "Cannot determine how to set RateLimit headers on %r", type(target)
        )
