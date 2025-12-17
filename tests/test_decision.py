from __future__ import annotations

from arcjet.decision import (
    Decision,
    RuleResult as SDKRuleResult,
    is_spoofed_bot,
)
from proto.decide.v1alpha1 import decide_pb2
import types


def test_decision_and_reason_helpers():
    # Build a decision with a bot_v2 reason and a ttl
    rr_pb = decide_pb2.RuleResult(
        rule_id="r1",
        conclusion=decide_pb2.CONCLUSION_DENY,
        reason=decide_pb2.Reason(bot_v2=object()),
        fingerprint="fp1",
    )
    dec_pb = decide_pb2.Decision(
        id="d1",
        conclusion=decide_pb2.CONCLUSION_DENY,
        ttl=42,
        reason=decide_pb2.Reason(bot_v2=types.SimpleNamespace(spoofed=True)),
        rule_results=[rr_pb],
    )
    d = Decision(dec_pb)

    assert d.is_denied() is True
    assert d.is_allowed() is False
    assert d.ttl == 42

    # Results proxy
    results = d.results
    assert len(results) == 1
    assert results[0].is_denied() is True

    # Reason helpers
    assert d.reason.is_bot() is True


def test_is_spoofed_bot_helper():
    bot_v2 = types.SimpleNamespace(spoofed=True)
    rr_pb = decide_pb2.RuleResult(
        rule_id="r1",
        conclusion=decide_pb2.CONCLUSION_DENY,
        reason=decide_pb2.Reason(bot_v2=bot_v2),
    )
    rr = SDKRuleResult(rr_pb)
    assert is_spoofed_bot(rr) is True
