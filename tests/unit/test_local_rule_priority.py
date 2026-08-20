"""Local WASM rules evaluate in JS priority order."""

from __future__ import annotations

from unittest.mock import patch


def test_sort_matches_js_priority(mock_protobuf_modules):
    from arcjet._client import _sort_rules_for_local
    from arcjet._rules import (
        BotDetection,
        EmailValidation,
        Filter,
        Mode,
        SensitiveInfoDetection,
        Shield,
        SlidingWindow,
        detect_bot,
        detect_sensitive_info,
        filter_request,
        shield,
        sliding_window,
        validate_email,
    )

    bot = detect_bot(mode=Mode.LIVE, deny=["CURL"])
    email = validate_email(mode=Mode.LIVE, deny=["INVALID"])
    filt = filter_request(mode=Mode.LIVE, deny=["ip.src == 1"])
    rl = sliding_window(mode=Mode.LIVE, max=5, interval=60)
    sh = shield(mode=Mode.LIVE)
    sensi = detect_sensitive_info(mode=Mode.LIVE, deny=["EMAIL"])
    ordered = _sort_rules_for_local((bot, email, filt, rl, sh, sensi))
    assert [type(r) for r in ordered] == [
        SensitiveInfoDetection,
        Filter,
        Shield,
        SlidingWindow,
        BotDetection,
        EmailValidation,
    ]


def test_sensitive_info_denies_before_later_bot(mock_protobuf_modules):
    from arcjet._client import _run_local_rules
    from arcjet._context import RequestContext
    from arcjet._rules import Mode, detect_bot, detect_sensitive_info
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    bot = detect_bot(mode=Mode.LIVE, deny=["CURL"])
    sensi = detect_sensitive_info(mode=Mode.LIVE, deny=["EMAIL"])
    si_deny = decide_pb2.RuleResult(
        rule_id="si",
        state=decide_pb2.RULE_STATE_RUN,
        conclusion=decide_pb2.CONCLUSION_DENY,
        reason=decide_pb2.Reason(error=decide_pb2.ErrorReason(message="pii")),
    )
    bot_deny = decide_pb2.RuleResult(
        rule_id="bot",
        state=decide_pb2.RULE_STATE_RUN,
        conclusion=decide_pb2.CONCLUSION_DENY,
        reason=decide_pb2.Reason(error=decide_pb2.ErrorReason(message="bot")),
    )
    calls: list[str] = []

    def track_si(_ctx, _rule):
        calls.append("si")
        return si_deny

    def track_bot(_ctx, _rule):
        calls.append("bot")
        return bot_deny

    ctx = RequestContext(ip="1.2.3.4")
    with (
        patch("arcjet._client.evaluate_sensitive_info_locally", side_effect=track_si),
        patch("arcjet._client.evaluate_filter_locally", return_value=None),
        patch("arcjet._client.evaluate_bot_locally", side_effect=track_bot),
        patch("arcjet._client.evaluate_email_locally", return_value=None),
    ):
        decision = _run_local_rules(ctx, (bot, sensi))

    assert calls == ["si"]
    assert decision is not None
    assert decision.results[0].rule_id == "si"
