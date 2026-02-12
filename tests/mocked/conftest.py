# Test bootstrap and stubs for proto and google protobuf utilities
from __future__ import annotations

import os
import pytest
import sys
import types
from typing import Any, Dict, List, Optional

# Ensure the package's src directory is importable
# tests/mocked/conftest.py -> tests/mocked/ -> tests/ -> repo root
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

# ---------------------------------------------------------------------------
# Stub google.protobuf.json_format.MessageToDict to avoid real protobuf dep
# ---------------------------------------------------------------------------
mod_google = types.ModuleType("google")
mod_protobuf = types.ModuleType("google.protobuf")
mod_json_format = types.ModuleType("google.protobuf.json_format")


def _message_to_dict(x: Any, preserving_proto_field_name: bool = True) -> dict:
    # Best-effort: try to convert known stub messages to dicts
    if hasattr(x, "_as_dict"):
        return x._as_dict()  # type: ignore[attr-defined]
    if hasattr(x, "__dict__"):
        # Shallow dict of attributes (excluding callables and private ones)
        return {
            k: v
            for k, v in vars(x).items()
            if not k.startswith("_") and not callable(v)
        }
    return {}


mod_json_format.MessageToDict = _message_to_dict  # type: ignore[attr-defined]

# Register stub modules if not already present
sys.modules.setdefault("google", mod_google)
sys.modules.setdefault("google.protobuf", mod_protobuf)
sys.modules.setdefault("google.protobuf.json_format", mod_json_format)

# ---------------------------------------------------------------------------
# Stub proto.decide.v1alpha1.decide_pb2 and decide_connect
# ---------------------------------------------------------------------------
mod_proto = types.ModuleType("arcjet.proto")
mod_decide = types.ModuleType("arcjet.proto.decide")
mod_v1 = types.ModuleType("arcjet.proto.decide.v1alpha1")
mod_pb2 = types.ModuleType("arcjet.proto.decide.v1alpha1.decide_pb2")
mod_connect = types.ModuleType("arcjet.proto.decide.v1alpha1.decide_connect")

# Constants and enums
MODE_DRY_RUN = 1
MODE_LIVE = 2
SDK_STACK_PYTHON = 1
CONCLUSION_ALLOW = 1
CONCLUSION_DENY = 2
CONCLUSION_CHALLENGE = 3
CONCLUSION_ERROR = 4

EMAIL_TYPE_DISPOSABLE = 1
EMAIL_TYPE_FREE = 2
EMAIL_TYPE_NO_MX_RECORDS = 3
EMAIL_TYPE_NO_GRAVATAR = 4
EMAIL_TYPE_INVALID = 5

RATE_LIMIT_ALGORITHM_TOKEN_BUCKET = 1
RATE_LIMIT_ALGORITHM_FIXED_WINDOW = 2
RATE_LIMIT_ALGORITHM_SLIDING_WINDOW = 3


class _Conclusion:
    _names = {
        CONCLUSION_ALLOW: "ALLOW",
        CONCLUSION_DENY: "DENY",
        CONCLUSION_CHALLENGE: "CHALLENGE",
        CONCLUSION_ERROR: "ERROR",
    }

    @staticmethod
    def Name(value: int) -> str:
        return _Conclusion._names.get(value, str(value))


# Message stubs --------------------------------------------------------------
class RequestDetails:
    def __init__(self) -> None:
        self.ip: Optional[str] = None
        self.method: Optional[str] = None
        self.protocol: Optional[str] = None
        self.host: Optional[str] = None
        self.path: Optional[str] = None
        self.cookies: Optional[str] = None
        self.query: Optional[str] = None
        self.body: Optional[bytes] = None
        self.email: Optional[str] = None
        self.headers: Dict[str, str] = {}
        self.extra: Dict[str, str] = {}

    def _as_dict(self) -> dict:
        return {
            "ip": self.ip,
            "method": self.method,
            "protocol": self.protocol,
            "host": self.host,
            "path": self.path,
            "cookies": self.cookies,
            "query": self.query,
            "email": self.email,
            "headers": dict(self.headers),
            "extra": dict(self.extra),
        }


class ShieldRule:
    def __init__(self, mode: int) -> None:
        self.mode = mode
        self.characteristics: List[str] = []


class BotV2Rule:
    def __init__(self, mode: int) -> None:
        self.mode = mode
        self.allow: List[str] = []
        self.deny: List[str] = []


class RateLimitRule:
    def __init__(self, mode: int, algorithm: int, **kwargs: Any) -> None:
        self.mode = mode
        self.algorithm = algorithm
        # Common numeric params
        for k, v in kwargs.items():
            setattr(self, k, v)
        self.characteristics: List[str] = []


class EmailRule:
    def __init__(
        self, mode: int, require_top_level_domain: bool, allow_domain_literal: bool
    ) -> None:
        self.mode = mode
        self.require_top_level_domain = require_top_level_domain
        self.allow_domain_literal = allow_domain_literal
        self.allow: List[int] = []
        self.deny: List[int] = []


class Rule:
    def __init__(self, **kwargs: Any) -> None:
        # oneof: shield | bot_v2 | rate_limit | email
        self.shield = kwargs.get("shield")
        self.bot_v2 = kwargs.get("bot_v2")
        self.rate_limit = kwargs.get("rate_limit")
        self.email = kwargs.get("email")


class ErrorReason:
    def __init__(self, message: str) -> None:
        self.message = message


class _Reason:
    def __init__(self, **kwargs: Any) -> None:
        # oneof variants used in SDK
        self.rate_limit = kwargs.get("rate_limit")
        self.bot = kwargs.get("bot")
        self.bot_v2 = kwargs.get("bot_v2")
        self.shield = kwargs.get("shield")
        self.email = kwargs.get("email")
        self.sensitive_info = kwargs.get("sensitive_info")
        self.filter = kwargs.get("filter")
        self.error = kwargs.get("error")

    def WhichOneof(self, name: str) -> Optional[str]:
        for field in (
            "rate_limit",
            "bot",
            "bot_v2",
            "shield",
            "email",
            "sensitive_info",
            "filter",
            "error",
        ):
            if getattr(self, field) is not None:
                return field
        return None


class IpDetails:
    def __init__(self) -> None:
        self.is_hosting = False
        self.is_vpn = False
        self.is_proxy = False
        self.is_tor = False


class RuleResult:
    def __init__(
        self,
        rule_id: str = "",
        state: int = 0,
        conclusion: int = CONCLUSION_ALLOW,
        reason: Optional[_Reason] = None,
        fingerprint: str | None = None,
    ) -> None:
        self.rule_id = rule_id
        self.state = state
        self.conclusion = conclusion
        self.reason = reason
        self.fingerprint = fingerprint or ""


class Decision:
    def __init__(
        self,
        id: str = "",
        conclusion: int = CONCLUSION_ALLOW,
        ttl: int = 0,
        reason: Optional[_Reason] = None,
        ip_details: Optional[IpDetails] = None,
        rule_results: Optional[List[RuleResult]] = None,
    ) -> None:
        self.id = id
        self.conclusion = conclusion
        self.ttl = ttl
        self.reason = reason
        self.ip_details = ip_details
        self.rule_results: List[RuleResult] = list(rule_results or [])

    def HasField(self, name: str) -> bool:
        return getattr(self, name, None) is not None


class DecideRequest:
    def __init__(
        self, sdk_stack: int, sdk_version: str, details: RequestDetails
    ) -> None:
        self.sdk_stack = sdk_stack
        self.sdk_version = sdk_version
        self.details = details
        self.rules: List[Rule] = []

    # protobuf-like list
    class _RulesList(list):
        def extend(self, items):
            super().extend(items)

    @property
    def rules(self):  # type: ignore[override]
        return self._rules

    @rules.setter
    def rules(self, v):
        self._rules = v


class ReportRequest:
    def __init__(
        self,
        sdk_stack: int,
        sdk_version: str,
        details: RequestDetails,
        decision: Decision,
    ) -> None:
        self.sdk_stack = sdk_stack
        self.sdk_version = sdk_version
        self.details = details
        self.decision = decision
        self.rules: List[Rule] = []


class _DecideResponse:
    def __init__(self, decision: Optional[Decision] = None) -> None:
        self.decision = decision

    def HasField(self, name: str) -> bool:
        return getattr(self, name, None) is not None


class EmailType(int):
    EMAIL_TYPE_DISPOSABLE = EMAIL_TYPE_DISPOSABLE
    EMAIL_TYPE_FREE = EMAIL_TYPE_FREE
    EMAIL_TYPE_NO_MX_RECORDS = EMAIL_TYPE_NO_MX_RECORDS
    EMAIL_TYPE_NO_GRAVATAR = EMAIL_TYPE_NO_GRAVATAR
    EMAIL_TYPE_INVALID = EMAIL_TYPE_INVALID


# Expose symbols like real module
mod_pb2.MODE_DRY_RUN = MODE_DRY_RUN
mod_pb2.MODE_LIVE = MODE_LIVE
mod_pb2.SDK_STACK_PYTHON = SDK_STACK_PYTHON
mod_pb2.CONCLUSION_ALLOW = CONCLUSION_ALLOW
mod_pb2.CONCLUSION_DENY = CONCLUSION_DENY
mod_pb2.CONCLUSION_CHALLENGE = CONCLUSION_CHALLENGE
mod_pb2.CONCLUSION_ERROR = CONCLUSION_ERROR
mod_pb2.EMAIL_TYPE_DISPOSABLE = EMAIL_TYPE_DISPOSABLE
mod_pb2.EMAIL_TYPE_FREE = EMAIL_TYPE_FREE
mod_pb2.EMAIL_TYPE_NO_MX_RECORDS = EMAIL_TYPE_NO_MX_RECORDS
mod_pb2.EMAIL_TYPE_NO_GRAVATAR = EMAIL_TYPE_NO_GRAVATAR
mod_pb2.EMAIL_TYPE_INVALID = EMAIL_TYPE_INVALID
mod_pb2.RATE_LIMIT_ALGORITHM_TOKEN_BUCKET = RATE_LIMIT_ALGORITHM_TOKEN_BUCKET
mod_pb2.RATE_LIMIT_ALGORITHM_FIXED_WINDOW = RATE_LIMIT_ALGORITHM_FIXED_WINDOW
mod_pb2.RATE_LIMIT_ALGORITHM_SLIDING_WINDOW = RATE_LIMIT_ALGORITHM_SLIDING_WINDOW
mod_pb2.Conclusion = _Conclusion
mod_pb2.RequestDetails = RequestDetails
mod_pb2.ShieldRule = ShieldRule
mod_pb2.BotV2Rule = BotV2Rule
mod_pb2.RateLimitRule = RateLimitRule
mod_pb2.EmailRule = EmailRule
mod_pb2.Rule = Rule
mod_pb2.ErrorReason = ErrorReason
mod_pb2.Reason = _Reason
mod_pb2.IpDetails = IpDetails
mod_pb2.RuleResult = RuleResult
mod_pb2.Decision = Decision
mod_pb2.DecideRequest = DecideRequest
mod_pb2.ReportRequest = ReportRequest
mod_pb2.EmailType = EmailType


# Decide client stubs with injectable behavior
class _BaseClient:
    # class-level hooks for behavior and counters
    decide_calls = 0
    report_calls = 0
    decide_behavior = None  # type: Optional[Any]

    def __init__(self, base_url: str, http_client: Any = None) -> None:
        self.base_url = base_url
        self.http_client = http_client  # placeholder for real HTTP client

    def _decide_impl(self, req: DecideRequest):
        type(self).decide_calls += 1
        if callable(type(self).decide_behavior):
            return type(self).decide_behavior(req)
        # default ALLOW decision with zero TTL
        return _DecideResponse(Decision(id="d1", conclusion=CONCLUSION_ALLOW, ttl=0))

    def _report_impl(self, rep: ReportRequest):
        type(self).report_calls += 1
        return None

    def close(self):
        pass


class DecideServiceClient(_BaseClient):
    async def decide(self, req: DecideRequest, **kwargs: Any):
        return self._decide_impl(req)

    async def report(self, rep: ReportRequest, **kwargs: Any):
        return self._report_impl(rep)

    async def aclose(self):
        pass


class DecideServiceClientSync(_BaseClient):
    def decide(self, req: DecideRequest, **kwargs: Any):
        return self._decide_impl(req)

    def report(self, rep: ReportRequest, **kwargs: Any):
        return self._report_impl(rep)


# Register decide modules
mod_connect.DecideServiceClient = DecideServiceClient
mod_connect.DecideServiceClientSync = DecideServiceClientSync

# Install in sys.modules
sys.modules.setdefault("arcjet.proto", mod_proto)
sys.modules.setdefault("arcjet.proto.decide", mod_decide)
sys.modules.setdefault("arcjet.proto.decide.v1alpha1", mod_v1)
sys.modules.setdefault("arcjet.proto.decide.v1alpha1.decide_pb2", mod_pb2)
sys.modules.setdefault(
    "arcjet.proto.decide.v1alpha1.decide_connect", mod_connect)


@pytest.fixture(autouse=True)
def _reset_stub_clients_env(monkeypatch):
    # Default to development env for permissive behavior in tests unless overridden
    monkeypatch.setenv("ARCJET_ENV", "development")
    # Reset counters/behaviors on every test
    DecideServiceClient.decide_calls = 0
    DecideServiceClient.report_calls = 0
    DecideServiceClient.decide_behavior = None
    DecideServiceClientSync.decide_calls = 0
    DecideServiceClientSync.report_calls = 0
    DecideServiceClientSync.decide_behavior = None
    yield


# Convenience factory for a stub Decision message used by multiple tests
class Stub:
    pb2 = mod_pb2
    connect = mod_connect
    _DecideResponse = _DecideResponse


# Helper functions for creating test decisions and responses
def make_allow_decision(ttl: int = 0, id: str = "d-allow") -> Decision:
    """Create a simple ALLOW decision for testing."""
    return Decision(id=id, conclusion=CONCLUSION_ALLOW, ttl=ttl)


def make_deny_decision(ttl: int = 0, id: str = "d-deny") -> Decision:
    """Create a simple DENY decision for testing."""
    return Decision(id=id, conclusion=CONCLUSION_DENY, ttl=ttl)


def make_error_decision(message: str = "Test error", id: str = "d-error") -> Decision:
    """Create an ERROR decision for testing."""
    return Decision(
        id=id,
        conclusion=CONCLUSION_ERROR,
        reason=_Reason(error=ErrorReason(message=message)),
    )


def make_decide_response(decision: Optional[Decision] = None):
    """Create a mock decide response with the given decision."""
    if decision is None:
        decision = make_allow_decision()
    return _DecideResponse(decision=decision)


def capture_request_field(field_name: str):
    """Create a decide behavior that captures a specific request field.
    
    Returns a tuple of (behavior_function, captured_dict).
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
    headers: Optional[List[tuple[str, str]]] = None,
    client: Optional[tuple[str, int]] = None,
) -> dict:
    """Create a basic HTTP context for testing."""
    ctx = {
        "type": "http",
        "headers": headers or [],
    }
    if client is not None:
        ctx["client"] = client
    return ctx
