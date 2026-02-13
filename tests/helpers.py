"""Shared test helpers for arcjet-py tests.

This module provides reusable utilities for creating test fixtures,
decisions, and other common test data.
"""

from __future__ import annotations

from typing import Any


def make_test_request(
    ip: str = "127.0.0.1",
    method: str = "GET",
    host: str = "example.com",
    path: str = "/",
    headers: dict[str, str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Create a test request context.

    Args:
        ip: IP address for the request
        method: HTTP method
        host: Host header value
        path: Request path
        headers: Additional headers
        **extra: Additional fields to include in the request

    Returns:
        A dictionary suitable for passing to arcjet.protect()
    """
    req = {
        "type": "http",
        "ip": ip,
        "method": method,
        "host": host,
        "path": path,
        "headers": headers or {},
    }
    req.update(extra)
    return req


def make_test_decision(
    conclusion: str = "ALLOW",
    ttl: int = 0,
    decision_id: str = "test_decision",
    ip: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Create a test decision response.

    Args:
        conclusion: Decision conclusion (ALLOW, DENY, CHALLENGE, ERROR)
        ttl: Time-to-live for caching
        decision_id: Unique decision ID
        ip: IP address
        **extra: Additional fields

    Returns:
        A dictionary representing a decision
    """
    decision = {
        "id": decision_id,
        "conclusion": conclusion,
        "ttl": ttl,
    }
    if ip:
        decision["ip"] = ip
    decision.update(extra)
    return decision
