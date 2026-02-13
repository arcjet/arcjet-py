"""Unit tests for Decision and RuleResult classes.

Tests decision helpers and utilities without requiring real protobuf dependencies.
"""

from __future__ import annotations

import types

import pytest

from arcjet.decision import Decision, is_spoofed_bot
from arcjet.decision import RuleResult as SDKRuleResult


def test_decision_and_reason_helpers(mock_protobuf_modules):
    """Test Decision class helpers for checking allow/deny status and reasons."""
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    # Build a decision with a bot_v2 reason and a ttl
    rr_pb = decide_pb2.RuleResult(
        rule_id="r1",
        conclusion=decide_pb2.CONCLUSION_DENY,
        reason=decide_pb2.Reason(bot_v2=object()),  # type: ignore[arg-type]
        fingerprint="fp1",
    )
    dec_pb = decide_pb2.Decision(
        id="d1",
        conclusion=decide_pb2.CONCLUSION_DENY,
        ttl=42,
        reason=decide_pb2.Reason(bot_v2=types.SimpleNamespace(spoofed=True)),  # type: ignore[arg-type]
        rule_results=[rr_pb],
    )
    d = Decision(dec_pb)

    # Test decision status helpers
    assert d.is_denied() is True
    assert d.is_allowed() is False
    assert d.ttl == 42

    # Test results proxy
    results = d.results
    assert len(results) == 1
    assert results[0].is_denied() is True

    # Test reason helpers
    with pytest.warns(DeprecationWarning, match="Use `reason_v2` property instead"):
        assert d.reason.is_bot() is True


def test_is_spoofed_bot_helper(mock_protobuf_modules):
    """Test the is_spoofed_bot helper function."""
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    bot_v2 = types.SimpleNamespace(spoofed=True)
    rr_pb = decide_pb2.RuleResult(
        rule_id="r1",
        conclusion=decide_pb2.CONCLUSION_DENY,
        reason=decide_pb2.Reason(bot_v2=bot_v2),  # type: ignore[arg-type]
    )
    rr = SDKRuleResult(rr_pb)
    assert is_spoofed_bot(rr) is True

def test_decision_with_ip_details(mock_protobuf_modules):
    """Test Decision with IP details."""
    from arcjet.decision import Decision
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    ip_details = decide_pb2.IpDetails()
    ip_details.is_hosting = True
    ip_details.is_vpn = False

    dec = decide_pb2.Decision(
        id="test",
        conclusion=decide_pb2.CONCLUSION_ALLOW,
        ip_details=ip_details
    )
    decision = Decision(dec)

    # Test IP analysis methods
    assert decision.ip.is_hosting() is True
    assert decision.ip.is_vpn() is False
    assert decision.ip.is_proxy() is False
    assert decision.ip.is_tor() is False


def test_reason_which_method(mock_protobuf_modules):
    """Test Reason.which() method."""
    from arcjet.decision import Reason
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    # Test with None
    reason = Reason(None)
    assert reason.which() is None

    # Test with a reason
    reason_pb = decide_pb2.Reason(error=decide_pb2.ErrorReason(message="test"))
    reason = Reason(reason_pb)
    assert reason.which() == "error"


def test_reason_raw_and_to_dict(mock_protobuf_modules):
    """Test Reason.raw and to_dict methods."""
    from arcjet.decision import Reason
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    reason_pb = decide_pb2.Reason(error=decide_pb2.ErrorReason(message="test"))
    reason = Reason(reason_pb)

    # Test raw property
    assert reason.raw is reason_pb

    # Test to_dict
    d = reason.to_dict()
    assert d is not None
    assert isinstance(d, dict)


def test_reason_to_json_returns_null_for_none(mock_protobuf_modules):
    """Test Reason.to_json() returns 'null' for None."""
    from arcjet.decision import Reason

    reason = Reason(None)
    assert reason.to_json() == "null"


def test_rule_result_properties(mock_protobuf_modules):
    """Test RuleResult properties."""
    from arcjet.decision import RuleResult
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    rr = decide_pb2.RuleResult(
        rule_id="my_rule",
        state=2,
        conclusion=decide_pb2.CONCLUSION_DENY,
        fingerprint="fp_123"
    )
    result = RuleResult(rr)

    assert result.rule_id == "my_rule"
    assert result.state == 2
    assert result.conclusion == decide_pb2.CONCLUSION_DENY
    assert result.fingerprint == "fp_123"
    assert result.raw is rr


def test_rule_result_empty_fingerprint(mock_protobuf_modules):
    """Test RuleResult with empty fingerprint."""
    from arcjet.decision import RuleResult
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    rr = decide_pb2.RuleResult(
        rule_id="test",
        fingerprint=""
    )
    result = RuleResult(rr)

    assert result.fingerprint is None
