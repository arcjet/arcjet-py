"""Protobuf stub fixtures for testing without real protobuf dependencies.

This module provides pytest fixtures for mocking protobuf modules and clients.
It uses proper fixture scoping to avoid cross-contamination between tests.
"""

from __future__ import annotations

import sys
import types
from typing import Any, Callable, Optional

import pytest

# Constants for stub enums
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
EMAIL_TYPE_UNSPECIFIED = 0

RATE_LIMIT_ALGORITHM_TOKEN_BUCKET = 1
RATE_LIMIT_ALGORITHM_FIXED_WINDOW = 2
RATE_LIMIT_ALGORITHM_SLIDING_WINDOW = 3


class _Conclusion:
    """Stub for Conclusion enum."""

    _names = {
        CONCLUSION_ALLOW: "ALLOW",
        CONCLUSION_DENY: "DENY",
        CONCLUSION_CHALLENGE: "CHALLENGE",
        CONCLUSION_ERROR: "ERROR",
    }

    @staticmethod
    def Name(value: int) -> str:
        return _Conclusion._names.get(value, str(value))


class StubRequestDetails:
    """Stub for protobuf RequestDetails message."""

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
        self.headers: dict[str, str] = {}
        self.extra: dict[str, str] = {}

    def _as_dict(self) -> dict:
        """Convert to dict for MessageToDict compatibility."""
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


class StubShieldRule:
    """Stub for protobuf ShieldRule message."""

    def __init__(self, mode: int) -> None:
        self.mode = mode
        self.characteristics: list[str] = []


class StubBotV2Rule:
    """Stub for protobuf BotV2Rule message."""

    def __init__(self, mode: int) -> None:
        self.mode = mode
        self.allow: list[str] = []
        self.deny: list[str] = []


class StubRateLimitRule:
    """Stub for protobuf RateLimitRule message."""

    def __init__(self, mode: int, algorithm: int, **kwargs: Any) -> None:
        self.mode = mode
        self.algorithm = algorithm
        # Common numeric params
        for k, v in kwargs.items():
            setattr(self, k, v)
        self.characteristics: list[str] = []


class StubEmailRule:
    """Stub for protobuf EmailRule message."""

    def __init__(
        self, mode: int, require_top_level_domain: bool, allow_domain_literal: bool
    ) -> None:
        self.mode = mode
        self.require_top_level_domain = require_top_level_domain
        self.allow_domain_literal = allow_domain_literal
        self.allow: list[int] = []
        self.deny: list[int] = []


class StubRule:
    """Stub for protobuf Rule message (oneof wrapper)."""

    def __init__(self, **kwargs: Any) -> None:
        # oneof: shield | bot_v2 | rate_limit | email
        self.shield = kwargs.get("shield")
        self.bot_v2 = kwargs.get("bot_v2")
        self.rate_limit = kwargs.get("rate_limit")
        self.email = kwargs.get("email")


class StubErrorReason:
    """Stub for protobuf ErrorReason message."""

    def __init__(self, message: str) -> None:
        self.message = message


class StubReason:
    """Stub for protobuf Reason message."""

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
        """Return which field is set in this oneof."""
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


class StubIpDetails:
    """Stub for protobuf IpDetails message."""

    def __init__(self) -> None:
        self.is_hosting = False
        self.is_vpn = False
        self.is_proxy = False
        self.is_tor = False


class StubRuleResult:
    """Stub for protobuf RuleResult message."""

    def __init__(
        self,
        rule_id: str = "",
        state: int = 0,
        conclusion: int = CONCLUSION_ALLOW,
        reason: Optional[StubReason] = None,
        fingerprint: str | None = None,
    ) -> None:
        self.rule_id = rule_id
        self.state = state
        self.conclusion = conclusion
        self.reason = reason
        self.fingerprint = fingerprint or ""


class StubDecision:
    """Stub for protobuf Decision message."""

    def __init__(
        self,
        id: str = "",
        conclusion: int = CONCLUSION_ALLOW,
        ttl: int = 0,
        reason: Optional[StubReason] = None,
        ip: Optional[Any] = None,
        ip_details: Optional[StubIpDetails] = None,
        rule_results: Optional[list[StubRuleResult]] = None,
    ) -> None:
        self.id = id
        self.conclusion = conclusion
        self.ttl = ttl
        self.reason = reason
        self.ip = ip
        self.ip_details = ip_details
        self.rule_results: list[StubRuleResult] = list(rule_results or [])

    def HasField(self, name: str) -> bool:
        """Check if a field has a value."""
        return getattr(self, name, None) is not None

    def _as_dict(self) -> dict[str, Any]:
        """Convert to dict for MessageToDict compatibility."""
        return {
            "id": self.id,
            "conclusion": self.conclusion,
            "ttl": self.ttl,
            "reason": self.reason,
            "ip": self.ip,
            "ip_details": self.ip_details,
            "rule_results": self.rule_results,
        }


class StubEmailType(int):
    """Stub for protobuf EmailType enum."""

    EMAIL_TYPE_DISPOSABLE = EMAIL_TYPE_DISPOSABLE
    EMAIL_TYPE_FREE = EMAIL_TYPE_FREE
    EMAIL_TYPE_NO_MX_RECORDS = EMAIL_TYPE_NO_MX_RECORDS
    EMAIL_TYPE_NO_GRAVATAR = EMAIL_TYPE_NO_GRAVATAR
    EMAIL_TYPE_INVALID = EMAIL_TYPE_INVALID


class StubDecideResponse:
    """Stub for protobuf DecideResponse."""

    def __init__(self, decision: StubDecision) -> None:
        self.decision = decision

    def HasField(self, field: str) -> bool:
        return field == "decision"


class StubReportRequest:
    """Stub for protobuf ReportRequest."""

    def __init__(
        self,
        sdk_stack: int = 0,
        sdk_version: str = "",
        details: Optional[StubRequestDetails] = None,
        decision: Optional[StubDecision] = None,
    ) -> None:
        self.sdk_stack = sdk_stack
        self.sdk_version = sdk_version
        self.details = details
        self.decision = decision
        self.rules: list[StubRule] = []


class StubDecideRequest:
    """Stub for protobuf DecideRequest."""

    def __init__(
        self,
        sdk_stack: int = 0,
        sdk_version: str = "",
        details: Optional[StubRequestDetails] = None,
    ) -> None:
        self.sdk_stack = sdk_stack
        self.sdk_version = sdk_version
        self.details = details
        self.rules: list[StubRule] = []


class StubDecideServiceClient:
    """Stub for async DecideServiceClient.

    Supports behavior injection for testing via class attributes:
    - decide_behavior: Callable to customize decide() response
    - decide_calls: Counter for number of decide() calls
    """

    decide_calls = 0
    decide_behavior: Optional[Callable[[Any], Any]] = None

    def __init__(self, base_url: str, **kwargs: Any) -> None:
        self.base_url = base_url

    async def decide(self, request: Any, **kwargs: Any) -> StubDecideResponse:
        """Async decide method."""
        type(self).decide_calls += 1
        if callable(type(self).decide_behavior):
            return type(self).decide_behavior(request)  # type: ignore[misc]
        return StubDecideResponse(
            StubDecision(id="test_decision", conclusion=CONCLUSION_ALLOW, ttl=0)
        )

    async def report(self, request: StubReportRequest, **kwargs: Any) -> None:
        """Async report method (no-op)."""
        pass


class StubDecideServiceClientSync:
    """Stub for sync DecideServiceClient."""

    decide_calls = 0
    decide_behavior: Optional[Callable[[Any], Any]] = None

    def __init__(self, base_url: str, **kwargs: Any) -> None:
        self.base_url = base_url

    def decide(self, request: Any, **kwargs: Any) -> StubDecideResponse:
        """Sync decide method."""
        type(self).decide_calls += 1
        if callable(type(self).decide_behavior):
            return type(self).decide_behavior(request)  # type: ignore[misc]
        return StubDecideResponse(
            StubDecision(id="test_decision", conclusion=CONCLUSION_ALLOW, ttl=0)
        )

    def report(self, request: StubReportRequest, **kwargs: Any) -> None:
        """Sync report method (no-op)."""
        pass


def _message_to_dict(x: Any, preserving_proto_field_name: bool = True) -> dict:
    """Stub for MessageToDict function."""
    if hasattr(x, "_as_dict"):
        return x._as_dict()
    if hasattr(x, "__dict__"):
        return {
            k: v
            for k, v in vars(x).items()
            if not k.startswith("_") and not callable(v)
        }
    return {}


@pytest.fixture(scope="function")
def mock_protobuf_modules(monkeypatch: pytest.MonkeyPatch):  # type: ignore[misc]
    """Fixture to mock protobuf modules for a single test.

    This fixture creates and installs stub protobuf modules into sys.modules
    for the duration of the test, then automatically cleans them up.

    Usage:
        def test_something(mock_protobuf_modules):
            # Protobuf modules are mocked here
            from arcjet.proto.decide.v1alpha1 import decide_pb2
            # Test code...
            # Automatic cleanup after test
    """
    # Create module stubs
    mod_google = types.ModuleType("google")
    mod_protobuf = types.ModuleType("google.protobuf")
    mod_json_format = types.ModuleType("google.protobuf.json_format")
    mod_json_format.MessageToDict = _message_to_dict  # type: ignore[attr-defined]

    mod_proto = types.ModuleType("arcjet.proto")
    mod_decide = types.ModuleType("arcjet.proto.decide")
    mod_v1 = types.ModuleType("arcjet.proto.decide.v1alpha1")
    mod_pb2 = types.ModuleType("arcjet.proto.decide.v1alpha1.decide_pb2")
    mod_connect = types.ModuleType("arcjet.proto.decide.v1alpha1.decide_connect")

    # Populate decide_pb2 module
    # Type checkers don't understand dynamic module attribute assignment
    mod_pb2.MODE_DRY_RUN = MODE_DRY_RUN  # type: ignore[attr-defined]
    mod_pb2.MODE_LIVE = MODE_LIVE  # type: ignore[attr-defined]
    mod_pb2.SDK_STACK_PYTHON = SDK_STACK_PYTHON  # type: ignore[attr-defined]
    mod_pb2.CONCLUSION_ALLOW = CONCLUSION_ALLOW  # type: ignore[attr-defined]
    mod_pb2.CONCLUSION_DENY = CONCLUSION_DENY  # type: ignore[attr-defined]
    mod_pb2.CONCLUSION_CHALLENGE = CONCLUSION_CHALLENGE  # type: ignore[attr-defined]
    mod_pb2.CONCLUSION_ERROR = CONCLUSION_ERROR  # type: ignore[attr-defined]
    mod_pb2.EMAIL_TYPE_DISPOSABLE = EMAIL_TYPE_DISPOSABLE  # type: ignore[attr-defined]
    mod_pb2.EMAIL_TYPE_FREE = EMAIL_TYPE_FREE  # type: ignore[attr-defined]
    mod_pb2.EMAIL_TYPE_NO_MX_RECORDS = EMAIL_TYPE_NO_MX_RECORDS  # type: ignore[attr-defined]
    mod_pb2.EMAIL_TYPE_NO_GRAVATAR = EMAIL_TYPE_NO_GRAVATAR  # type: ignore[attr-defined]
    mod_pb2.EMAIL_TYPE_INVALID = EMAIL_TYPE_INVALID  # type: ignore[attr-defined]
    mod_pb2.EMAIL_TYPE_UNSPECIFIED = EMAIL_TYPE_UNSPECIFIED  # type: ignore[attr-defined]
    mod_pb2.RATE_LIMIT_ALGORITHM_TOKEN_BUCKET = RATE_LIMIT_ALGORITHM_TOKEN_BUCKET  # type: ignore[attr-defined]
    mod_pb2.RATE_LIMIT_ALGORITHM_FIXED_WINDOW = RATE_LIMIT_ALGORITHM_FIXED_WINDOW  # type: ignore[attr-defined]
    mod_pb2.RATE_LIMIT_ALGORITHM_SLIDING_WINDOW = RATE_LIMIT_ALGORITHM_SLIDING_WINDOW  # type: ignore[attr-defined]
    mod_pb2.Conclusion = _Conclusion  # type: ignore[attr-defined]
    mod_pb2.RequestDetails = StubRequestDetails  # type: ignore[attr-defined]
    mod_pb2.ShieldRule = StubShieldRule  # type: ignore[attr-defined]
    mod_pb2.BotV2Rule = StubBotV2Rule  # type: ignore[attr-defined]
    mod_pb2.RateLimitRule = StubRateLimitRule  # type: ignore[attr-defined]
    mod_pb2.EmailRule = StubEmailRule  # type: ignore[attr-defined]
    mod_pb2.Rule = StubRule  # type: ignore[attr-defined]
    mod_pb2.ErrorReason = StubErrorReason  # type: ignore[attr-defined]
    mod_pb2.Reason = StubReason  # type: ignore[attr-defined]
    mod_pb2.IpDetails = StubIpDetails  # type: ignore[attr-defined]
    mod_pb2.RuleResult = StubRuleResult  # type: ignore[attr-defined]
    mod_pb2.Decision = StubDecision  # type: ignore[attr-defined]
    mod_pb2.DecideRequest = StubDecideRequest  # type: ignore[attr-defined]
    mod_pb2.ReportRequest = StubReportRequest  # type: ignore[attr-defined]
    mod_pb2.EmailType = StubEmailType  # type: ignore[attr-defined]

    # Populate decide_connect module
    mod_connect.DecideServiceClient = StubDecideServiceClient  # type: ignore[attr-defined]
    mod_connect.DecideServiceClientSync = StubDecideServiceClientSync  # type: ignore[attr-defined]

    # Install modules using monkeypatch for automatic cleanup
    monkeypatch.setitem(sys.modules, "google", mod_google)
    monkeypatch.setitem(sys.modules, "google.protobuf", mod_protobuf)
    monkeypatch.setitem(sys.modules, "google.protobuf.json_format", mod_json_format)
    monkeypatch.setitem(sys.modules, "arcjet.proto", mod_proto)
    monkeypatch.setitem(sys.modules, "arcjet.proto.decide", mod_decide)
    monkeypatch.setitem(sys.modules, "arcjet.proto.decide.v1alpha1", mod_v1)
    monkeypatch.setitem(sys.modules, "arcjet.proto.decide.v1alpha1.decide_pb2", mod_pb2)
    monkeypatch.setitem(
        sys.modules, "arcjet.proto.decide.v1alpha1.decide_connect", mod_connect
    )

    # Reset client call counters for each test
    StubDecideServiceClient.decide_calls = 0
    StubDecideServiceClient.decide_behavior = None
    StubDecideServiceClientSync.decide_calls = 0
    StubDecideServiceClientSync.decide_behavior = None

    # Clear any cached arcjet modules that might have imported protobuf already
    # This prevents cross-contamination when tests run in different orders
    modules_to_clear = [
        key
        for key in list(sys.modules.keys())
        if key.startswith("arcjet") and not key.startswith("arcjet.proto")
    ]
    for module_name in modules_to_clear:
        monkeypatch.delitem(sys.modules, module_name, raising=False)

    yield {
        "pb2": mod_pb2,
        "connect": mod_connect,
        "Decision": StubDecision,
        "DecideResponse": StubDecideResponse,
        "DecideServiceClient": StubDecideServiceClient,
        "DecideServiceClientSync": StubDecideServiceClientSync,
    }

    # Reset client state after test to prevent cross-contamination
    StubDecideServiceClient.decide_calls = 0
    StubDecideServiceClient.decide_behavior = None
    StubDecideServiceClientSync.decide_calls = 0
    StubDecideServiceClientSync.decide_behavior = None
    # Cleanup happens automatically via monkeypatch


@pytest.fixture
def make_allow_decision():
    """Factory fixture for creating ALLOW decisions."""

    def _make(ttl: int = 0, decision_id: str = "test_allow") -> StubDecision:
        return StubDecision(id=decision_id, conclusion=CONCLUSION_ALLOW, ttl=ttl)

    return _make


@pytest.fixture
def make_deny_decision():
    """Factory fixture for creating DENY decisions."""

    def _make(ttl: int = 0, decision_id: str = "test_deny") -> StubDecision:
        return StubDecision(id=decision_id, conclusion=CONCLUSION_DENY, ttl=ttl)

    return _make


@pytest.fixture
def make_error_decision():
    """Factory fixture for creating ERROR decisions."""

    def _make(ttl: int = 0, decision_id: str = "test_error") -> StubDecision:
        return StubDecision(id=decision_id, conclusion=CONCLUSION_ERROR, ttl=ttl)

    return _make
