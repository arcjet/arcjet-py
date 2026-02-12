"""Shared test utilities and helper functions.

This module provides common utilities used across all test files to reduce
duplication and improve test readability.
"""

from __future__ import annotations

import types
from typing import Any, Callable, Dict, Optional

from arcjet.proto.decide.v1alpha1 import decide_pb2


def make_allow_decision(ttl: int = 0, id: str = "d-allow") -> decide_pb2.Decision:
    """Create a simple ALLOW decision for testing.
    
    Args:
        ttl: Time-to-live for the decision in seconds
        id: Decision ID string
        
    Returns:
        A Decision protobuf with CONCLUSION_ALLOW
    """
    return decide_pb2.Decision(
        id=id, conclusion=decide_pb2.CONCLUSION_ALLOW, ttl=ttl
    )


def make_deny_decision(ttl: int = 0, id: str = "d-deny") -> decide_pb2.Decision:
    """Create a simple DENY decision for testing.
    
    Args:
        ttl: Time-to-live for the decision in seconds
        id: Decision ID string
        
    Returns:
        A Decision protobuf with CONCLUSION_DENY
    """
    return decide_pb2.Decision(
        id=id, conclusion=decide_pb2.CONCLUSION_DENY, ttl=ttl
    )


def make_error_decision(
    message: str = "Test error", id: str = "d-error"
) -> decide_pb2.Decision:
    """Create an ERROR decision for testing.
    
    Args:
        message: Error message to include
        id: Decision ID string
        
    Returns:
        A Decision protobuf with CONCLUSION_ERROR
    """
    return decide_pb2.Decision(
        id=id,
        conclusion=decide_pb2.CONCLUSION_ERROR,
        reason=decide_pb2.Reason(error=decide_pb2.ErrorReason(message=message)),
    )


def make_decide_response(decision: Optional[decide_pb2.Decision] = None):
    """Create a mock decide response with the given decision.
    
    Args:
        decision: Decision to wrap, defaults to allow decision
        
    Returns:
        A SimpleNamespace mock of a decide response
    """
    if decision is None:
        decision = make_allow_decision()
    return types.SimpleNamespace(HasField=lambda f: True, decision=decision)


def capture_request_field(field_name: str) -> tuple[Callable, Dict[str, Any]]:
    """Create a decide behavior that captures a specific request field.
    
    This is useful for testing what values are being sent to the decide service.
    
    Args:
        field_name: Name of the request field to capture (e.g., "details")
        
    Returns:
        A tuple of (behavior_function, captured_dict) where the captured_dict
        will be populated with the captured values
        
    Example:
        >>> capture_decide, captured = capture_request_field("details")
        >>> DecideServiceClient.decide_behavior = capture_decide
        >>> # ... run test ...
        >>> assert captured["ip"] == "1.2.3.4"
    """
    captured: Dict[str, Any] = {}

    def capture_behavior(req):
        field_value = getattr(req, field_name, None)
        if field_value is not None:
            if hasattr(field_value, "__dict__"):
                # Capture all attributes
                for key, value in vars(field_value).items():
                    if not key.startswith("_"):
                        captured[key] = value
            else:
                captured[field_name] = field_value
        return make_decide_response()

    return capture_behavior, captured


def make_basic_http_context(
    headers: Optional[list[tuple[str, str]]] = None,
    client: Optional[tuple[str, int]] = None,
) -> dict:
    """Create a basic HTTP context for testing.
    
    Args:
        headers: List of (name, value) header tuples
        client: Optional (ip, port) tuple for client address
        
    Returns:
        A context dict suitable for passing to arcjet.protect()
    """
    ctx = {
        "type": "http",
        "headers": headers or [],
    }
    if client is not None:
        ctx["client"] = client
    return ctx
