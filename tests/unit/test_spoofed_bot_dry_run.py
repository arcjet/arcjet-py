"""is_spoofed_bot ignores DRY_RUN results (JS isActive)."""

from __future__ import annotations

import types

from arcjet._decision import RuleResult as SDKRuleResult
from arcjet._decision import is_spoofed_bot


def _bot_result(mock_protobuf_modules, *, spoofed: bool, state: int) -> SDKRuleResult:
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    bot_v2 = types.SimpleNamespace(spoofed=spoofed, verified=False)
    rr = decide_pb2.RuleResult(
        rule_id="r1",
        state=state,
        conclusion=decide_pb2.CONCLUSION_DENY,
        reason=decide_pb2.Reason(bot_v2=bot_v2),  # type: ignore[arg-type]
    )
    return SDKRuleResult(rr)


def test_is_spoofed_bot_live(mock_protobuf_modules):
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    rr = _bot_result(
        mock_protobuf_modules,
        spoofed=True,
        state=decide_pb2.RULE_STATE_RUN,
    )
    assert is_spoofed_bot(rr) is True


def test_is_spoofed_bot_ignores_dry_run(mock_protobuf_modules):
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    rr = _bot_result(
        mock_protobuf_modules,
        spoofed=True,
        state=decide_pb2.RULE_STATE_DRY_RUN,
    )
    assert is_spoofed_bot(rr) is False
