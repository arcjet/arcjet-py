"""Unit tests for LocalCustomRule — subclassing, evaluate, type safety."""

from __future__ import annotations

import asyncio
from typing import TypedDict

from arcjet.guard import (
    CustomEvaluateResult,
    LocalCustomRule,
    LocalCustomWithInput,
    RuleResultCustom,
    TypedCustomResult,
)
from arcjet.guard.convert import decision_from_proto, rule_to_proto
from arcjet.guard.proto.decide.v2 import decide_pb2 as pb

from .conftest import make_response


class TopicConfig(TypedDict):
    blocked_topic: str


class TopicInput(TypedDict):
    topic: str


class TopicData(TypedDict):
    matched: str


class TopicBlockRule(LocalCustomRule[TopicConfig, TopicInput, TopicData]):
    def evaluate(
        self,
        config: TopicConfig,
        input: TopicInput,
    ) -> CustomEvaluateResult:
        if input["topic"] == config["blocked_topic"]:
            return CustomEvaluateResult(
                conclusion="DENY", data={"matched": input["topic"]}
            )
        return CustomEvaluateResult(conclusion="ALLOW")


class AsyncTopicBlockRule(LocalCustomRule[TopicConfig, TopicInput, TopicData]):
    async def evaluate_async(
        self,
        config: TopicConfig,
        input: TopicInput,
    ) -> CustomEvaluateResult:
        if input["topic"] == config["blocked_topic"]:
            return CustomEvaluateResult(
                conclusion="DENY", data={"matched": input["topic"]}
            )
        return CustomEvaluateResult(conclusion="ALLOW")


class ErrorRule(LocalCustomRule[TopicConfig, TopicInput, TopicData]):
    def evaluate(
        self,
        config: TopicConfig,
        input: TopicInput,
    ) -> CustomEvaluateResult:
        raise RuntimeError("boom")


class TestCustomRuleFactory:
    def test_call_returns_custom_with_input(self) -> None:
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        inp = rule(data={"topic": "weapons"})
        assert isinstance(inp, LocalCustomWithInput)

    def test_config_id_is_stable(self) -> None:
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        a = rule(data={"topic": "cooking"})
        b = rule(data={"topic": "weapons"})
        assert a._config_id == b._config_id
        assert a._input_id != b._input_id

    def test_different_configs_different_ids(self) -> None:
        r1 = TopicBlockRule(config={"blocked_topic": "weapons"})
        r2 = TopicBlockRule(config={"blocked_topic": "gambling"})
        assert r1.config_id != r2.config_id

    def test_config_data_preserved(self) -> None:
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        inp = rule(data={"topic": "weapons"})
        assert inp.config_data == {"blocked_topic": "weapons"}

    def test_input_data_preserved(self) -> None:
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        inp = rule(data={"topic": "cooking"})
        assert inp.input_data == {"topic": "cooking"}


class TestCustomRuleSyncEvaluate:
    def test_deny_result_captured(self) -> None:
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        inp = rule(data={"topic": "weapons"})
        assert inp.evaluate_result is not None
        assert inp.evaluate_result.conclusion == "DENY"
        assert inp.evaluate_result.data == {"matched": "weapons"}

    def test_allow_result_captured(self) -> None:
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        inp = rule(data={"topic": "cooking"})
        assert inp.evaluate_result is not None
        assert inp.evaluate_result.conclusion == "ALLOW"

    def test_error_captured(self) -> None:
        rule = ErrorRule(config={"blocked_topic": "weapons"})
        inp = rule(data={"topic": "weapons"})
        assert inp.evaluate_result is None
        assert inp.evaluate_error is not None
        assert "boom" in inp.evaluate_error

    def test_default_evaluate_allows(self) -> None:
        """Base class evaluate returns ALLOW."""

        class Bare(LocalCustomRule[TopicConfig, TopicInput, TopicData]):
            pass

        rule = Bare(config={"blocked_topic": "weapons"})
        inp = rule(data={"topic": "weapons"})
        assert inp.evaluate_result is not None
        assert inp.evaluate_result.conclusion == "ALLOW"


class TestCustomRuleAsyncEvaluate:
    def test_async_deny(self) -> None:
        rule = AsyncTopicBlockRule(config={"blocked_topic": "weapons"})
        inp = asyncio.run(rule.call_async(data={"topic": "weapons"}))
        assert inp.evaluate_result is not None
        assert inp.evaluate_result.conclusion == "DENY"
        assert inp.evaluate_result.data == {"matched": "weapons"}

    def test_async_allow(self) -> None:
        rule = AsyncTopicBlockRule(config={"blocked_topic": "weapons"})
        inp = asyncio.run(rule.call_async(data={"topic": "cooking"}))
        assert inp.evaluate_result is not None
        assert inp.evaluate_result.conclusion == "ALLOW"

    def test_async_fallback_to_sync(self) -> None:
        """If only sync evaluate is defined, async falls back to it."""
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        inp = asyncio.run(rule.call_async(data={"topic": "weapons"}))
        assert inp.evaluate_result is not None
        assert inp.evaluate_result.conclusion == "DENY"


class TestCustomRuleMetadata:
    def test_mode_preserved(self) -> None:
        rule = TopicBlockRule(config={"blocked_topic": "weapons"}, mode="DRY_RUN")
        inp = rule(data={"topic": "cooking"})
        assert inp.mode == "DRY_RUN"

    def test_label_preserved(self) -> None:
        rule = TopicBlockRule(config={"blocked_topic": "weapons"}, label="topic-filter")
        inp = rule(data={"topic": "cooking"})
        assert inp.label == "topic-filter"

    def test_metadata_merged(self) -> None:
        rule = TopicBlockRule(
            config={"blocked_topic": "weapons"}, metadata={"env": "prod"}
        )
        inp = rule(data={"topic": "cooking"}, metadata={"req": "abc"})
        assert inp.metadata == {"env": "prod", "req": "abc"}


class TestCustomRuleProtoConversion:
    def test_rule_to_proto_allow(self) -> None:
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        inp = rule(data={"topic": "cooking"})
        proto = rule_to_proto(inp)

        assert proto.rule.WhichOneof("rule") == "local_custom"
        cu = proto.rule.local_custom
        assert dict(cu.config_data) == {"blocked_topic": "weapons"}
        assert dict(cu.input_data) == {"topic": "cooking"}
        assert cu.result_computed.conclusion == pb.GUARD_CONCLUSION_ALLOW

    def test_rule_to_proto_deny(self) -> None:
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        inp = rule(data={"topic": "weapons"})
        proto = rule_to_proto(inp)

        cu = proto.rule.local_custom
        assert cu.result_computed.conclusion == pb.GUARD_CONCLUSION_DENY
        assert dict(cu.result_computed.data) == {"matched": "weapons"}

    def test_rule_to_proto_error(self) -> None:
        rule = ErrorRule(config={"blocked_topic": "weapons"})
        inp = rule(data={"topic": "weapons"})
        proto = rule_to_proto(inp)

        cu = proto.rule.local_custom
        assert cu.result_error.code == "EVALUATE_ERROR"
        assert "boom" in cu.result_error.message

    def test_rule_to_proto_dry_run(self) -> None:
        rule = TopicBlockRule(config={"blocked_topic": "weapons"}, mode="DRY_RUN")
        inp = rule(data={"topic": "weapons"})
        proto = rule_to_proto(inp)
        assert proto.mode == pb.GUARD_RULE_MODE_DRY_RUN


class TestCustomRuleDecisionFromProto:
    def test_allow_result(self) -> None:
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        inp = rule(data={"topic": "cooking"})

        response = make_response(
            pb.GUARD_CONCLUSION_ALLOW,
            [
                pb.GuardRuleResult(
                    result_id="gres_1",
                    config_id=inp._config_id,
                    input_id=inp._input_id,
                    type=pb.GUARD_RULE_TYPE_LOCAL_CUSTOM,
                    local_custom=pb.ResultLocalCustom(
                        conclusion=pb.GUARD_CONCLUSION_ALLOW,
                        data={},
                    ),
                ),
            ],
        )
        decision = decision_from_proto(response)
        assert decision.conclusion == "ALLOW"
        r = inp.result(decision)
        assert r is not None
        assert r.conclusion == "ALLOW"
        assert r.type == "CUSTOM"

    def test_deny_result_with_data(self) -> None:
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        inp = rule(data={"topic": "weapons"})

        response = make_response(
            pb.GUARD_CONCLUSION_DENY,
            [
                pb.GuardRuleResult(
                    result_id="gres_1",
                    config_id=inp._config_id,
                    input_id=inp._input_id,
                    type=pb.GUARD_RULE_TYPE_LOCAL_CUSTOM,
                    local_custom=pb.ResultLocalCustom(
                        conclusion=pb.GUARD_CONCLUSION_DENY,
                        data={"matched": "weapons"},
                    ),
                ),
            ],
        )
        decision = decision_from_proto(response)
        assert decision.conclusion == "DENY"
        assert decision.reason == "CUSTOM"

        r = inp.result(decision)
        assert r is not None
        assert r.data == {"matched": "weapons"}

    def test_denied_result_none_on_allow(self) -> None:
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        inp = rule(data={"topic": "cooking"})

        response = make_response(
            pb.GUARD_CONCLUSION_ALLOW,
            [
                pb.GuardRuleResult(
                    result_id="gres_1",
                    config_id=inp._config_id,
                    input_id=inp._input_id,
                    type=pb.GUARD_RULE_TYPE_LOCAL_CUSTOM,
                    local_custom=pb.ResultLocalCustom(
                        conclusion=pb.GUARD_CONCLUSION_ALLOW,
                    ),
                ),
            ],
        )
        decision = decision_from_proto(response)
        assert inp.denied_result(decision) is None

    def test_config_results_and_denied(self) -> None:
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        i1 = rule(data={"topic": "cooking"})
        i2 = rule(data={"topic": "weapons"})

        response = make_response(
            pb.GUARD_CONCLUSION_DENY,
            [
                pb.GuardRuleResult(
                    result_id="gres_1",
                    config_id=i1._config_id,
                    input_id=i1._input_id,
                    type=pb.GUARD_RULE_TYPE_LOCAL_CUSTOM,
                    local_custom=pb.ResultLocalCustom(
                        conclusion=pb.GUARD_CONCLUSION_ALLOW,
                    ),
                ),
                pb.GuardRuleResult(
                    result_id="gres_2",
                    config_id=i2._config_id,
                    input_id=i2._input_id,
                    type=pb.GUARD_RULE_TYPE_LOCAL_CUSTOM,
                    local_custom=pb.ResultLocalCustom(
                        conclusion=pb.GUARD_CONCLUSION_DENY,
                        data={"matched": "weapons"},
                    ),
                ),
            ],
        )
        decision = decision_from_proto(response)

        results = rule.results(decision)
        assert len(results) == 2

        denied = rule.denied_result(decision)
        assert denied is not None
        assert denied.conclusion == "DENY"


class TestCustomRuleTypeAssertions:
    """Pyright-verifiable type narrowing tests.

    These tests use explicit type assertions that pyright checks
    statically.  If the types are wrong, pyright will report errors
    on these lines.
    """

    def test_evaluate_result_type(self) -> None:
        result = CustomEvaluateResult(conclusion="DENY", data={"matched": "weapons"})
        c: str = result.conclusion
        d: dict[str, str] | None = dict(result.data) if result.data else None
        assert c == "DENY"
        assert d is not None

    def test_rule_result_custom_discriminant(self) -> None:
        r = RuleResultCustom(conclusion="DENY", data={"k": "v"})
        assert r.type == "CUSTOM"
        assert r.reason == "CUSTOM"
        assert r.conclusion == "DENY"
        assert dict(r.data) == {"k": "v"}

    def test_custom_with_input_result_returns_typed_custom_result(self) -> None:
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        inp = rule(data={"topic": "weapons"})

        response = make_response(
            pb.GUARD_CONCLUSION_DENY,
            [
                pb.GuardRuleResult(
                    result_id="gres_1",
                    config_id=inp._config_id,
                    input_id=inp._input_id,
                    type=pb.GUARD_RULE_TYPE_LOCAL_CUSTOM,
                    local_custom=pb.ResultLocalCustom(
                        conclusion=pb.GUARD_CONCLUSION_DENY,
                        data={"matched": "weapons"},
                    ),
                ),
            ],
        )
        decision = decision_from_proto(response)
        r = inp.result(decision)
        assert r is not None
        assert isinstance(r, TypedCustomResult)
        # .data is typed as TopicData (a TypedDict with key "matched")
        matched: str = r.data["matched"]
        assert matched == "weapons"
        assert r.type == "CUSTOM"
        assert r.reason == "CUSTOM"

    def test_typed_result_from_config_results(self) -> None:
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        inp = rule(data={"topic": "weapons"})

        response = make_response(
            pb.GUARD_CONCLUSION_DENY,
            [
                pb.GuardRuleResult(
                    result_id="gres_1",
                    config_id=inp._config_id,
                    input_id=inp._input_id,
                    type=pb.GUARD_RULE_TYPE_LOCAL_CUSTOM,
                    local_custom=pb.ResultLocalCustom(
                        conclusion=pb.GUARD_CONCLUSION_DENY,
                        data={"matched": "weapons"},
                    ),
                ),
            ],
        )
        decision = decision_from_proto(response)
        results = rule.results(decision)
        assert len(results) == 1
        r = results[0]
        assert isinstance(r, TypedCustomResult)
        matched: str = r.data["matched"]
        assert matched == "weapons"

    def test_typed_denied_result(self) -> None:
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        inp = rule(data={"topic": "weapons"})

        response = make_response(
            pb.GUARD_CONCLUSION_DENY,
            [
                pb.GuardRuleResult(
                    result_id="gres_1",
                    config_id=inp._config_id,
                    input_id=inp._input_id,
                    type=pb.GUARD_RULE_TYPE_LOCAL_CUSTOM,
                    local_custom=pb.ResultLocalCustom(
                        conclusion=pb.GUARD_CONCLUSION_DENY,
                        data={"matched": "weapons"},
                    ),
                ),
            ],
        )
        decision = decision_from_proto(response)
        denied = rule.denied_result(decision)
        assert denied is not None
        assert isinstance(denied, TypedCustomResult)
        matched: str = denied.data["matched"]
        assert matched == "weapons"

    def test_custom_with_input_is_generic(self) -> None:
        """LocalCustomWithInput preserves TData through Generic."""
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        inp = rule(data={"topic": "weapons"})
        assert isinstance(inp, LocalCustomWithInput)
        assert inp.evaluate_result is not None

    def test_config_type_checked(self) -> None:
        """Verify config kwarg expects TopicConfig shape."""
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        assert rule._config == {"blocked_topic": "weapons"}

    def test_input_type_checked(self) -> None:
        """Verify data kwarg expects TopicInput shape."""
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        inp = rule(data={"topic": "cooking"})
        assert inp.input_data == {"topic": "cooking"}


class TestCustomRuleEvaluateDuration:
    def test_duration_captured(self) -> None:
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        inp = rule(data={"topic": "weapons"})
        assert isinstance(inp.evaluate_duration_ms, int)
        assert inp.evaluate_duration_ms >= 0


class TestCustomRuleConfigIdProperty:
    def test_config_id_accessible(self) -> None:
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        assert isinstance(rule.config_id, str)
        assert len(rule.config_id) > 0


class TestCustomRuleNoMatchResult:
    def test_result_none_when_no_match(self) -> None:
        """result() returns None when decision has no matching result."""
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        inp = rule(data={"topic": "weapons"})

        from arcjet.guard import TokenBucket

        tb = TokenBucket(refill_rate=10, interval_seconds=60, max_tokens=100)
        tb_inp = tb(key="user_1")
        response = make_response(
            pb.GUARD_CONCLUSION_ALLOW,
            [
                pb.GuardRuleResult(
                    result_id="gres_1",
                    config_id=tb_inp._config_id,
                    input_id=tb_inp._input_id,
                    type=pb.GUARD_RULE_TYPE_TOKEN_BUCKET,
                    token_bucket=pb.ResultTokenBucket(
                        conclusion=pb.GUARD_CONCLUSION_ALLOW,
                        remaining_tokens=99,
                    ),
                ),
            ],
        )
        decision = decision_from_proto(response)
        assert inp.result(decision) is None


class TestCustomEvaluateResultDefaults:
    def test_data_defaults_to_empty(self) -> None:
        r = CustomEvaluateResult(conclusion="ALLOW")
        assert dict(r.data) == {}

    def test_data_can_be_set(self) -> None:
        r = CustomEvaluateResult(conclusion="DENY", data={"matched": "weapons"})
        assert r.data == {"matched": "weapons"}


class TestCustomRuleErrorInAsyncEvaluate:
    def test_async_error_captured(self) -> None:
        class AsyncErrorRule(LocalCustomRule[TopicConfig, TopicInput, TopicData]):
            async def evaluate_async(
                self,
                config: TopicConfig,
                input: TopicInput,
            ) -> CustomEvaluateResult:
                raise ValueError("async boom")

        rule = AsyncErrorRule(config={"blocked_topic": "weapons"})
        inp = asyncio.run(rule.call_async(data={"topic": "weapons"}))
        assert inp.evaluate_result is None
        assert inp.evaluate_error is not None
        assert "async boom" in inp.evaluate_error


class TestCustomRuleWithMultipleRules:
    """Custom rule mixed with built-in rules in a single decision."""

    def test_mixed_rules_in_decision(self) -> None:
        from arcjet.guard import TokenBucket

        topic = TopicBlockRule(config={"blocked_topic": "weapons"})
        tb = TokenBucket(refill_rate=10, interval_seconds=60, max_tokens=100)

        topic_inp = topic(data={"topic": "weapons"})
        tb_inp = tb(key="user_1")

        response = make_response(
            pb.GUARD_CONCLUSION_DENY,
            [
                pb.GuardRuleResult(
                    result_id="gres_1",
                    config_id=tb_inp._config_id,
                    input_id=tb_inp._input_id,
                    type=pb.GUARD_RULE_TYPE_TOKEN_BUCKET,
                    token_bucket=pb.ResultTokenBucket(
                        conclusion=pb.GUARD_CONCLUSION_ALLOW,
                        remaining_tokens=99,
                    ),
                ),
                pb.GuardRuleResult(
                    result_id="gres_2",
                    config_id=topic_inp._config_id,
                    input_id=topic_inp._input_id,
                    type=pb.GUARD_RULE_TYPE_LOCAL_CUSTOM,
                    local_custom=pb.ResultLocalCustom(
                        conclusion=pb.GUARD_CONCLUSION_DENY,
                        data={"matched": "weapons"},
                    ),
                ),
            ],
        )
        decision = decision_from_proto(response)

        tb_r = tb_inp.result(decision)
        assert tb_r is not None
        assert tb_r.type == "TOKEN_BUCKET"

        topic_r = topic_inp.result(decision)
        assert topic_r is not None
        assert topic_r.type == "CUSTOM"
        assert topic_r.data == {"matched": "weapons"}


class TestCustomWithInputResultsList:
    """LocalCustomWithInput.results() returns a list (empty or single-element)."""

    def test_input_results_returns_list(self) -> None:
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        inp = rule(data={"topic": "weapons"})

        response = make_response(
            pb.GUARD_CONCLUSION_DENY,
            [
                pb.GuardRuleResult(
                    result_id="gres_1",
                    config_id=inp._config_id,
                    input_id=inp._input_id,
                    type=pb.GUARD_RULE_TYPE_LOCAL_CUSTOM,
                    local_custom=pb.ResultLocalCustom(
                        conclusion=pb.GUARD_CONCLUSION_DENY,
                        data={"matched": "weapons"},
                    ),
                ),
            ],
        )
        decision = decision_from_proto(response)
        results = inp.results(decision)
        assert len(results) == 1
        assert results[0].data == {"matched": "weapons"}

    def test_input_results_empty_when_not_in_decision(self) -> None:
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        inp = rule(data={"topic": "weapons"})
        other = rule(data={"topic": "cooking"})

        response = make_response(
            pb.GUARD_CONCLUSION_ALLOW,
            [
                pb.GuardRuleResult(
                    result_id="gres_1",
                    config_id=other._config_id,
                    input_id=other._input_id,
                    type=pb.GUARD_RULE_TYPE_LOCAL_CUSTOM,
                    local_custom=pb.ResultLocalCustom(
                        conclusion=pb.GUARD_CONCLUSION_ALLOW,
                    ),
                ),
            ],
        )
        decision = decision_from_proto(response)
        assert inp.results(decision) == []


class TestCustomRuleConfigResult:
    """LocalCustomRule.result() returns first result or None."""

    def test_config_result_returns_first(self) -> None:
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        i1 = rule(data={"topic": "weapons"})
        i2 = rule(data={"topic": "cooking"})

        response = make_response(
            pb.GUARD_CONCLUSION_DENY,
            [
                pb.GuardRuleResult(
                    result_id="gres_1",
                    config_id=i1._config_id,
                    input_id=i1._input_id,
                    type=pb.GUARD_RULE_TYPE_LOCAL_CUSTOM,
                    local_custom=pb.ResultLocalCustom(
                        conclusion=pb.GUARD_CONCLUSION_DENY,
                        data={"matched": "weapons"},
                    ),
                ),
                pb.GuardRuleResult(
                    result_id="gres_2",
                    config_id=i2._config_id,
                    input_id=i2._input_id,
                    type=pb.GUARD_RULE_TYPE_LOCAL_CUSTOM,
                    local_custom=pb.ResultLocalCustom(
                        conclusion=pb.GUARD_CONCLUSION_ALLOW,
                    ),
                ),
            ],
        )
        decision = decision_from_proto(response)
        r = rule.result(decision)
        assert r is not None
        assert r.conclusion == "DENY"
        assert r.data == {"matched": "weapons"}

    def test_config_result_none_when_no_results(self) -> None:
        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        other = TopicBlockRule(config={"blocked_topic": "other"})
        inp = other(data={"topic": "other"})

        response = make_response(
            pb.GUARD_CONCLUSION_ALLOW,
            [
                pb.GuardRuleResult(
                    result_id="gres_1",
                    config_id=inp._config_id,
                    input_id=inp._input_id,
                    type=pb.GUARD_RULE_TYPE_LOCAL_CUSTOM,
                    local_custom=pb.ResultLocalCustom(
                        conclusion=pb.GUARD_CONCLUSION_ALLOW,
                    ),
                ),
            ],
        )
        decision = decision_from_proto(response)
        assert rule.result(decision) is None
