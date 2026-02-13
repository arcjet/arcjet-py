"""Unit tests for Decision and RuleResult classes.

Tests decision helpers and utilities without requiring real protobuf dependencies.
"""

from __future__ import annotations

import types

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
