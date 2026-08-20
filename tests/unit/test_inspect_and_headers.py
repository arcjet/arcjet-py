"""Inspect helpers and IETF rate-limit response headers."""

from __future__ import annotations

import types

from arcjet._decision import (
    Decision,
    is_missing_user_agent,
    is_verified_bot,
)
from arcjet._decision import RuleResult as SDKRuleResult


def _bot_result(mock_protobuf_modules, *, spoofed, verified, state):
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    bot_v2 = types.SimpleNamespace(spoofed=spoofed, verified=verified)
    rr = decide_pb2.RuleResult(
        rule_id="r1",
        state=state,
        conclusion=decide_pb2.CONCLUSION_DENY,
        reason=decide_pb2.Reason(bot_v2=bot_v2),  # type: ignore[arg-type]
    )
    return SDKRuleResult(rr)


def test_is_verified_bot_live(mock_protobuf_modules):
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    rr = _bot_result(
        mock_protobuf_modules,
        spoofed=False,
        verified=True,
        state=decide_pb2.RULE_STATE_RUN,
    )
    assert is_verified_bot(rr) is True


def test_is_verified_bot_ignores_dry_run(mock_protobuf_modules):
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    rr = _bot_result(
        mock_protobuf_modules,
        spoofed=False,
        verified=True,
        state=decide_pb2.RULE_STATE_DRY_RUN,
    )
    assert is_verified_bot(rr) is False


def test_is_missing_user_agent(mock_protobuf_modules):
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    rr = decide_pb2.RuleResult(
        rule_id="r1",
        state=decide_pb2.RULE_STATE_RUN,
        conclusion=decide_pb2.CONCLUSION_ERROR,
        reason=decide_pb2.Reason(
            error=decide_pb2.ErrorReason(message="missing User-Agent header")
        ),
    )
    assert is_missing_user_agent(SDKRuleResult(rr)) is True


def test_is_missing_user_agent_ignores_dry_run(mock_protobuf_modules):
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    rr = decide_pb2.RuleResult(
        rule_id="r1",
        state=decide_pb2.RULE_STATE_DRY_RUN,
        conclusion=decide_pb2.CONCLUSION_ERROR,
        reason=decide_pb2.Reason(
            error=decide_pb2.ErrorReason(message="missing User-Agent header")
        ),
    )
    assert is_missing_user_agent(SDKRuleResult(rr)) is False


def test_helpers_false_for_non_bot_reason(mock_protobuf_modules):
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    rr = decide_pb2.RuleResult(
        rule_id="r1",
        state=decide_pb2.RULE_STATE_RUN,
        conclusion=decide_pb2.CONCLUSION_DENY,
        reason=decide_pb2.Reason(
            error=decide_pb2.ErrorReason(message="something else")
        ),
    )
    wrapped = SDKRuleResult(rr)
    assert is_verified_bot(wrapped) is False
    assert is_missing_user_agent(wrapped) is False


def test_sets_ietf_headers(mock_protobuf_modules):
    from fixtures.protobuf_stubs import StubRateLimitReason

    from arcjet import set_rate_limit_headers
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    rl = StubRateLimitReason(
        max=100, remaining=3, reset_in_seconds=9, window_in_seconds=60
    )
    decision = Decision(
        decide_pb2.Decision(
            id="d1",
            conclusion=decide_pb2.CONCLUSION_ALLOW,
            reason=decide_pb2.Reason(rate_limit=rl),  # type: ignore[arg-type]
        )
    )
    headers: dict[str, str] = {}
    set_rate_limit_headers(headers, decision)
    assert headers["RateLimit"] == "limit=100, remaining=3, reset=9"
    assert headers["RateLimit-Policy"] == "100;w=60"


def test_uses_response_headers_attribute(mock_protobuf_modules):
    from fixtures.protobuf_stubs import StubRateLimitReason

    from arcjet import set_rate_limit_headers
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    class Response:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}

    rl = StubRateLimitReason(
        max=10, remaining=0, reset_in_seconds=4, window_in_seconds=10
    )
    decision = Decision(
        decide_pb2.Decision(
            id="d1",
            conclusion=decide_pb2.CONCLUSION_DENY,
            reason=decide_pb2.Reason(rate_limit=rl),  # type: ignore[arg-type]
        )
    )
    response = Response()
    set_rate_limit_headers(response, decision)
    assert "RateLimit" in response.headers


def test_noop_when_not_rate_limited(mock_protobuf_modules):
    from arcjet import set_rate_limit_headers
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    decision = Decision(
        decide_pb2.Decision(id="d1", conclusion=decide_pb2.CONCLUSION_ALLOW)
    )
    headers: dict[str, str] = {}
    set_rate_limit_headers(headers, decision)
    assert headers == {}


def _decision_with_reasons(mock_protobuf_modules, *reasons):
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    results = [
        decide_pb2.RuleResult(
            rule_id=f"r{i}",
            state=decide_pb2.RULE_STATE_RUN,
            conclusion=decide_pb2.CONCLUSION_ALLOW,
            reason=decide_pb2.Reason(rate_limit=reason),
        )
        for i, reason in enumerate(reasons)
    ]
    return Decision(
        decide_pb2.Decision(
            id="d1",
            conclusion=decide_pb2.CONCLUSION_ALLOW,
            rule_results=results,
        )
    )


def test_nearest_remaining_wins(mock_protobuf_modules):
    from fixtures.protobuf_stubs import StubRateLimitReason

    from arcjet import set_rate_limit_headers

    decision = _decision_with_reasons(
        mock_protobuf_modules,
        StubRateLimitReason(
            max=100, remaining=5, reset_in_seconds=20, window_in_seconds=60
        ),
        StubRateLimitReason(
            max=10, remaining=1, reset_in_seconds=30, window_in_seconds=10
        ),
    )
    headers: dict[str, str] = {}
    set_rate_limit_headers(headers, decision)
    assert headers["RateLimit"] == "limit=10, remaining=1, reset=30"
    assert headers["RateLimit-Policy"] == "10;w=10, 100;w=60"


def test_duplicate_max_aborts(mock_protobuf_modules):
    from fixtures.protobuf_stubs import StubRateLimitReason

    from arcjet import set_rate_limit_headers

    decision = _decision_with_reasons(
        mock_protobuf_modules,
        StubRateLimitReason(
            max=10, remaining=5, reset_in_seconds=9, window_in_seconds=60
        ),
        StubRateLimitReason(
            max=10, remaining=1, reset_in_seconds=4, window_in_seconds=10
        ),
    )
    headers: dict[str, str] = {}
    set_rate_limit_headers(headers, decision)
    assert headers == {}


def test_fetch_style_headers(mock_protobuf_modules):
    from fixtures.protobuf_stubs import StubRateLimitReason

    from arcjet import set_rate_limit_headers
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    class FetchHeaders:
        def __init__(self) -> None:
            self._data: dict[str, str] = {}

        def has(self, name: str) -> bool:
            return name in self._data

        def get(self, name: str) -> str | None:
            return self._data.get(name)

        def set(self, name: str, value: str) -> None:
            self._data[name] = value

    rl = StubRateLimitReason(
        max=10, remaining=2, reset_in_seconds=8, window_in_seconds=10
    )
    decision = Decision(
        decide_pb2.Decision(
            id="d1",
            conclusion=decide_pb2.CONCLUSION_ALLOW,
            reason=decide_pb2.Reason(rate_limit=rl),  # type: ignore[arg-type]
        )
    )
    headers = FetchHeaders()
    set_rate_limit_headers(headers, decision)
    assert headers.get("RateLimit") == "limit=10, remaining=2, reset=8"
    assert headers.get("RateLimit-Policy") == "10;w=10"


def test_set_header_style_response(mock_protobuf_modules):
    from fixtures.protobuf_stubs import StubRateLimitReason

    from arcjet import set_rate_limit_headers
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    class Outgoing:
        def __init__(self) -> None:
            self.headersSent = False
            self._data: dict[str, str] = {}

        def hasHeader(self, name: str) -> bool:
            return name in self._data

        def getHeader(self, name: str) -> str | None:
            return self._data.get(name)

        def setHeader(self, name: str, value: str) -> None:
            self._data[name] = value

    rl = StubRateLimitReason(
        max=5, remaining=0, reset_in_seconds=3, window_in_seconds=5
    )
    decision = Decision(
        decide_pb2.Decision(
            id="d1",
            conclusion=decide_pb2.CONCLUSION_DENY,
            reason=decide_pb2.Reason(rate_limit=rl),  # type: ignore[arg-type]
        )
    )
    response = Outgoing()
    set_rate_limit_headers(response, decision)
    assert response.getHeader("RateLimit") == "limit=5, remaining=0, reset=3"
