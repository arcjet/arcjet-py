"""is_ai_agent reads the Arcjet Cloud bot identity and ignores DRY_RUN results."""

from __future__ import annotations

from arcjet import is_ai_agent
from arcjet._dataclasses import BotReason
from arcjet._decision import RuleResult
from arcjet.proto.decide.v1alpha1 import decide_pb2


def _bot_result(
    identity: decide_pb2.BotIdentity | None,
    *,
    state: int = decide_pb2.RULE_STATE_RUN,
) -> RuleResult:
    bot_v2 = decide_pb2.BotV2Reason()
    if identity is not None:
        bot_v2.identity.CopyFrom(identity)
    rr = decide_pb2.RuleResult(
        rule_id="r1",
        state=state,  # type: ignore[arg-type]
        conclusion=decide_pb2.CONCLUSION_ALLOW,
        reason=decide_pb2.Reason(bot_v2=bot_v2),
    )
    return RuleResult(rr)


def _identity(kind: int, evidence: int = decide_pb2.BOT_EVIDENCE_IP):
    return decide_pb2.BotIdentity(
        kind=kind,  # type: ignore[arg-type]
        bot_id="CHATGPT_AGENT",
        evidence=evidence,  # type: ignore[arg-type]
    )


def test_is_ai_agent_live():
    assert is_ai_agent(_bot_result(_identity(decide_pb2.BOT_KIND_AI_AGENT))) is True


def test_is_ai_agent_ignores_dry_run():
    rr = _bot_result(
        _identity(decide_pb2.BOT_KIND_AI_AGENT),
        state=decide_pb2.RULE_STATE_DRY_RUN,
    )
    assert is_ai_agent(rr) is False


def test_is_ai_agent_false_for_other_kinds():
    for kind in (
        decide_pb2.BOT_KIND_AI_CRAWLER,
        decide_pb2.BOT_KIND_AUTOMATION,
        decide_pb2.BOT_KIND_OTHER,
        decide_pb2.BOT_KIND_UNSPECIFIED,
    ):
        assert is_ai_agent(_bot_result(_identity(kind))) is False


def test_is_ai_agent_false_when_spoofed():
    identity = _identity(
        decide_pb2.BOT_KIND_AI_AGENT, evidence=decide_pb2.BOT_EVIDENCE_UNVERIFIED
    )
    identity.spoofed = True
    assert is_ai_agent(_bot_result(identity)) is False


def test_is_ai_agent_true_when_not_spoofed_and_unverified():
    identity = _identity(
        decide_pb2.BOT_KIND_AI_AGENT, evidence=decide_pb2.BOT_EVIDENCE_UNVERIFIED
    )
    assert is_ai_agent(_bot_result(identity)) is True


def test_is_ai_agent_false_without_identity():
    assert is_ai_agent(_bot_result(None)) is False


def test_is_ai_agent_false_for_unknown_enum_values():
    assert is_ai_agent(_bot_result(_identity(99))) is False
    # A known kind with unknown evidence is not trusted either.
    rr = _bot_result(_identity(decide_pb2.BOT_KIND_AI_AGENT, evidence=99))
    assert is_ai_agent(rr) is False


def test_is_ai_agent_false_for_non_bot_reason():
    rr = decide_pb2.RuleResult(
        rule_id="r1",
        state=decide_pb2.RULE_STATE_RUN,
        conclusion=decide_pb2.CONCLUSION_DENY,
        reason=decide_pb2.Reason(error=decide_pb2.ErrorReason(message="boom")),
    )
    assert is_ai_agent(RuleResult(rr)) is False


def test_is_ai_agent_false_without_reason():
    rr = decide_pb2.RuleResult(rule_id="r1", state=decide_pb2.RULE_STATE_RUN)
    assert is_ai_agent(RuleResult(rr)) is False


def test_reason_v2_exposes_identity():
    rr = _bot_result(
        decide_pb2.BotIdentity(
            kind=decide_pb2.BOT_KIND_AI_AGENT,
            bot_id="CHATGPT_AGENT",
            operator="chatgpt.com",
            evidence=decide_pb2.BOT_EVIDENCE_SIGNATURE,
        )
    )
    reason = rr.reason_v2
    assert isinstance(reason, BotReason)
    assert reason.identity is not None
    assert reason.identity.kind == "AI_AGENT"
    assert reason.identity.operator == "chatgpt.com"
    assert reason.identity.evidence == "SIGNATURE"
    assert reason.identity.spoofed is False
    assert reason.identity.delegated is False


def test_reason_v2_exposes_delegated_identity():
    rr = _bot_result(
        decide_pb2.BotIdentity(
            kind=decide_pb2.BOT_KIND_AI_AGENT,
            bot_id="CHATGPT_AGENT",
            operator="chatgpt.com",
            evidence=decide_pb2.BOT_EVIDENCE_SIGNATURE,
            delegated=True,
        )
    )
    reason = rr.reason_v2
    assert isinstance(reason, BotReason)
    assert reason.identity is not None
    assert reason.identity.delegated is True


def test_reason_v2_exposes_spoofed_identity():
    rr = _bot_result(
        decide_pb2.BotIdentity(
            kind=decide_pb2.BOT_KIND_AI_AGENT,
            bot_id="CHATGPT_AGENT",
            evidence=decide_pb2.BOT_EVIDENCE_UNVERIFIED,
            spoofed=True,
        )
    )
    reason = rr.reason_v2
    assert isinstance(reason, BotReason)
    assert reason.identity is not None
    assert reason.identity.spoofed is True
    assert reason.identity.evidence == "UNVERIFIED"
