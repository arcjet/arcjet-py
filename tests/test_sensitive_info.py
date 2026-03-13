"""Tests for SensitiveInfoDetection rule and local evaluation.

Ported from arcjet-js/arcjet/test/sensitive-info.test.ts with adaptations for
the Python SDK's architecture (rule builder + mocked WASM component + local
evaluator).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from arcjet_analyze import (
    DetectedSensitiveInfoEntity,
    SensitiveInfoConfig,
    SensitiveInfoEntitiesAllow,
    SensitiveInfoEntitiesDeny,
    SensitiveInfoEntityCreditCardNumber,
    SensitiveInfoEntityCustom,
    SensitiveInfoEntityEmail,
    SensitiveInfoEntityIpAddress,
    SensitiveInfoEntityPhoneNumber,
    SensitiveInfoResult,
)

from arcjet._enums import Mode
from arcjet._local import evaluate_sensitive_info_locally
from arcjet.client import _run_local_rules
from arcjet.context import RequestContext
from arcjet.proto.decide.v1alpha1 import decide_pb2
from arcjet.rules import (
    SensitiveInfoDetection,
    SensitiveInfoEntityType,
    detect_sensitive_info,
)

# ---------------------------------------------------------------------------
# detect_sensitive_info() factory — validation
# ---------------------------------------------------------------------------


class TestDetectSensitiveInfoFactory:
    """Ported from JS: sensitiveInfo() option validation tests."""

    def test_creates_rule_with_deny(self):
        """JS: 'allows specifying sensitive info entities to allow'."""
        rule = detect_sensitive_info(
            deny=[
                SensitiveInfoEntityType.EMAIL,
                SensitiveInfoEntityType.CREDIT_CARD_NUMBER,
            ],
        )
        assert isinstance(rule, SensitiveInfoDetection)
        assert rule.mode == Mode.LIVE
        assert len(rule.deny) == 2
        assert rule.allow == ()

    def test_creates_rule_with_allow(self):
        rule = detect_sensitive_info(
            allow=[SensitiveInfoEntityType.EMAIL, SensitiveInfoEntityType.PHONE_NUMBER],
        )
        assert isinstance(rule, SensitiveInfoDetection)
        assert len(rule.allow) == 2
        assert rule.deny == ()

    def test_accepts_string_entity_types(self):
        rule = detect_sensitive_info(deny=["EMAIL", "CUSTOM_TYPE"])
        assert rule.deny == ("EMAIL", "CUSTOM_TYPE")

    def test_accepts_enum_entity_types(self):
        rule = detect_sensitive_info(deny=[SensitiveInfoEntityType.EMAIL])
        assert rule.deny == (SensitiveInfoEntityType.EMAIL,)

    def test_default_mode_is_live(self):
        rule = detect_sensitive_info(deny=["EMAIL"])
        assert rule.mode == Mode.LIVE

    def test_dry_run_mode(self):
        rule = detect_sensitive_info(mode=Mode.DRY_RUN, deny=["EMAIL"])
        assert rule.mode == Mode.DRY_RUN

    def test_mode_string_coercion(self):
        rule = detect_sensitive_info(mode="DRY_RUN", deny=["EMAIL"])
        assert rule.mode == Mode.DRY_RUN

    def test_context_window_size(self):
        rule = detect_sensitive_info(deny=["EMAIL"], context_window_size=3)
        assert rule.context_window_size == 3

    def test_characteristics(self):
        rule = detect_sensitive_info(deny=["EMAIL"], characteristics=["user_id"])
        assert rule.characteristics == ("user_id",)

    def test_empty_string_entity_rejected(self):
        """JS: validates entity types contain non-empty strings."""
        with pytest.raises(ValueError, match="cannot be empty"):
            detect_sensitive_info(deny=[""])


# ---------------------------------------------------------------------------
# SensitiveInfoDetection dataclass — validation
# ---------------------------------------------------------------------------


class TestSensitiveInfoDetectionValidation:
    """Ported from JS: validation of allow/deny options."""

    def test_mode_must_be_enum(self):
        with pytest.raises(TypeError, match="mode must be a Mode"):
            SensitiveInfoDetection(mode="invalid")  # type: ignore[arg-type]

    def test_allow_must_be_tuple(self):
        with pytest.raises(TypeError, match="must be a tuple"):
            SensitiveInfoDetection(mode=Mode.LIVE, allow=["EMAIL"])  # type: ignore[arg-type]

    def test_deny_must_be_tuple(self):
        with pytest.raises(TypeError, match="must be a tuple"):
            SensitiveInfoDetection(mode=Mode.LIVE, deny=["EMAIL"])  # type: ignore[arg-type]

    def test_characteristics_must_be_tuple(self):
        with pytest.raises(TypeError, match="characteristics must be a tuple"):
            SensitiveInfoDetection(
                mode=Mode.LIVE,
                deny=("EMAIL",),
                characteristics=["a"],  # type: ignore[arg-type]
            )


# ---------------------------------------------------------------------------
# SensitiveInfoDetection.to_proto()
# ---------------------------------------------------------------------------


class TestSensitiveInfoToProto:
    def test_deny_to_proto(self):
        rule = detect_sensitive_info(
            deny=[
                SensitiveInfoEntityType.EMAIL,
                SensitiveInfoEntityType.CREDIT_CARD_NUMBER,
            ],
        )
        proto = rule.to_proto()
        assert proto.HasField("sensitive_info")
        assert list(proto.sensitive_info.deny) == ["EMAIL", "CREDIT_CARD_NUMBER"]
        assert list(proto.sensitive_info.allow) == []

    def test_allow_to_proto(self):
        rule = detect_sensitive_info(
            allow=[SensitiveInfoEntityType.EMAIL, SensitiveInfoEntityType.PHONE_NUMBER],
        )
        proto = rule.to_proto()
        assert proto.HasField("sensitive_info")
        assert list(proto.sensitive_info.allow) == ["EMAIL", "PHONE_NUMBER"]
        assert list(proto.sensitive_info.deny) == []

    def test_custom_entity_type_to_proto(self):
        rule = detect_sensitive_info(deny=["CUSTOM_SSN"])
        proto = rule.to_proto()
        assert list(proto.sensitive_info.deny) == ["CUSTOM_SSN"]


# ---------------------------------------------------------------------------
# evaluate_sensitive_info_locally — mocked component
# ---------------------------------------------------------------------------


class TestEvaluateSensitiveInfoLocally:
    """Ported from JS: sensitive info rule protect() tests, adapted to the
    Python SDK's architecture where the WASM component is mocked."""

    def test_returns_none_when_component_unavailable(self):
        ctx = RequestContext(sensitive_info_content="test@example.com")
        rule = detect_sensitive_info(deny=[SensitiveInfoEntityType.EMAIL])
        with patch("arcjet._local._get_component", return_value=None):
            result = evaluate_sensitive_info_locally(ctx, rule)
        assert result is None

    def test_returns_none_when_no_content(self):
        """JS: 'it returns an error decision when body is not available'.
        In Python, missing content means the evaluator returns None (skip)."""
        ctx = RequestContext()
        rule = detect_sensitive_info(deny=[SensitiveInfoEntityType.EMAIL])
        with patch("arcjet._local._get_component", return_value=MagicMock()):
            result = evaluate_sensitive_info_locally(ctx, rule)
        assert result is None

    def test_no_sensitive_content_returns_allow(self):
        """JS: 'it doesnt detect any entities in a non sensitive body'."""
        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[], denied=[]
        )

        ctx = RequestContext(sensitive_info_content="none of this is sensitive")
        rule = detect_sensitive_info(mode=Mode.LIVE, allow=[])

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_sensitive_info_locally(ctx, rule)

        assert result is not None
        assert result.conclusion == decide_pb2.CONCLUSION_ALLOW
        assert result.state == decide_pb2.RULE_STATE_RUN

    def test_identifies_builtin_entities_deny(self):
        """JS: 'it identifies built-in entities' — deny all with allow=[]."""
        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[],
            denied=[
                DetectedSensitiveInfoEntity(
                    start=0, end=9, identified_type=SensitiveInfoEntityIpAddress()
                ),
                DetectedSensitiveInfoEntity(
                    start=10, end=26, identified_type=SensitiveInfoEntityEmail()
                ),
                DetectedSensitiveInfoEntity(
                    start=27,
                    end=43,
                    identified_type=SensitiveInfoEntityCreditCardNumber(),
                ),
                DetectedSensitiveInfoEntity(
                    start=44,
                    end=60,
                    identified_type=SensitiveInfoEntityPhoneNumber(),
                ),
            ],
        )

        ctx = RequestContext(
            sensitive_info_content="127.0.0.1 test@example.com 4242424242424242 +353 87 123 4567"
        )
        rule = detect_sensitive_info(mode=Mode.LIVE, allow=[])

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_sensitive_info_locally(ctx, rule)

        assert result is not None
        assert result.conclusion == decide_pb2.CONCLUSION_DENY
        assert result.state == decide_pb2.RULE_STATE_RUN

        si = result.reason.sensitive_info
        assert len(si.denied) == 4
        assert len(si.allowed) == 0

        # Verify entity types and positions match JS test expectations
        assert si.denied[0].identified_type == "IP_ADDRESS"
        assert si.denied[0].start == 0
        assert si.denied[0].end == 9
        assert si.denied[1].identified_type == "EMAIL"
        assert si.denied[1].start == 10
        assert si.denied[1].end == 26
        assert si.denied[2].identified_type == "CREDIT_CARD_NUMBER"
        assert si.denied[2].start == 27
        assert si.denied[2].end == 43
        assert si.denied[3].identified_type == "PHONE_NUMBER"
        assert si.denied[3].start == 44
        assert si.denied[3].end == 60

    def test_allows_entities_on_allow_list(self):
        """JS: 'it allows entities on the allow list'."""
        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[
                DetectedSensitiveInfoEntity(
                    start=10, end=26, identified_type=SensitiveInfoEntityEmail()
                ),
                DetectedSensitiveInfoEntity(
                    start=44,
                    end=60,
                    identified_type=SensitiveInfoEntityPhoneNumber(),
                ),
            ],
            denied=[
                DetectedSensitiveInfoEntity(
                    start=0, end=9, identified_type=SensitiveInfoEntityIpAddress()
                ),
                DetectedSensitiveInfoEntity(
                    start=27,
                    end=43,
                    identified_type=SensitiveInfoEntityCreditCardNumber(),
                ),
            ],
        )

        ctx = RequestContext(
            sensitive_info_content="127.0.0.1 test@example.com 4242424242424242 +353 87 123 4567"
        )
        rule = detect_sensitive_info(
            mode=Mode.LIVE,
            allow=[SensitiveInfoEntityType.EMAIL, SensitiveInfoEntityType.PHONE_NUMBER],
        )

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_sensitive_info_locally(ctx, rule)

        assert result is not None
        assert result.conclusion == decide_pb2.CONCLUSION_DENY  # still denied entities
        si = result.reason.sensitive_info
        assert len(si.allowed) == 2
        assert si.allowed[0].identified_type == "EMAIL"
        assert si.allowed[1].identified_type == "PHONE_NUMBER"
        assert len(si.denied) == 2
        assert si.denied[0].identified_type == "IP_ADDRESS"
        assert si.denied[1].identified_type == "CREDIT_CARD_NUMBER"

    def test_all_identified_types_allowed_returns_allow(self):
        """JS: 'it returns an allow decision when all identified types are allowed'."""
        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[
                DetectedSensitiveInfoEntity(
                    start=0, end=16, identified_type=SensitiveInfoEntityEmail()
                ),
                DetectedSensitiveInfoEntity(
                    start=17,
                    end=33,
                    identified_type=SensitiveInfoEntityPhoneNumber(),
                ),
            ],
            denied=[],
        )

        ctx = RequestContext(sensitive_info_content="test@example.com +353 87 123 4567")
        rule = detect_sensitive_info(
            mode=Mode.LIVE,
            allow=[SensitiveInfoEntityType.EMAIL, SensitiveInfoEntityType.PHONE_NUMBER],
        )

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_sensitive_info_locally(ctx, rule)

        assert result is not None
        assert result.conclusion == decide_pb2.CONCLUSION_ALLOW
        si = result.reason.sensitive_info
        assert len(si.allowed) == 2
        assert len(si.denied) == 0

    def test_deny_mode_only_denies_listed_entities(self):
        """JS: 'it only denies listed entities when deny mode is set'."""
        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[
                DetectedSensitiveInfoEntity(
                    start=10, end=26, identified_type=SensitiveInfoEntityEmail()
                ),
                DetectedSensitiveInfoEntity(
                    start=27,
                    end=43,
                    identified_type=SensitiveInfoEntityPhoneNumber(),
                ),
            ],
            denied=[
                DetectedSensitiveInfoEntity(
                    start=0, end=9, identified_type=SensitiveInfoEntityIpAddress()
                ),
            ],
        )

        ctx = RequestContext(
            sensitive_info_content="127.0.0.1 test@example.com +353 87 123 4567"
        )
        rule = detect_sensitive_info(
            mode=Mode.LIVE,
            deny=[
                SensitiveInfoEntityType.CREDIT_CARD_NUMBER,
                SensitiveInfoEntityType.IP_ADDRESS,
            ],
        )

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_sensitive_info_locally(ctx, rule)

        assert result is not None
        assert result.conclusion == decide_pb2.CONCLUSION_DENY
        si = result.reason.sensitive_info
        assert len(si.allowed) == 2
        assert si.allowed[0].identified_type == "EMAIL"
        assert si.allowed[1].identified_type == "PHONE_NUMBER"
        assert len(si.denied) == 1
        assert si.denied[0].identified_type == "IP_ADDRESS"

    def test_deny_mode_returns_deny_when_entity_matched(self):
        """JS: 'it returns a deny decision in deny mode when an entity is matched'."""
        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[
                DetectedSensitiveInfoEntity(
                    start=17,
                    end=33,
                    identified_type=SensitiveInfoEntityPhoneNumber(),
                ),
            ],
            denied=[
                DetectedSensitiveInfoEntity(
                    start=0, end=16, identified_type=SensitiveInfoEntityEmail()
                ),
            ],
        )

        ctx = RequestContext(sensitive_info_content="test@example.com +353 87 123 4567")
        rule = detect_sensitive_info(
            mode=Mode.LIVE, deny=[SensitiveInfoEntityType.EMAIL]
        )

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_sensitive_info_locally(ctx, rule)

        assert result is not None
        assert result.conclusion == decide_pb2.CONCLUSION_DENY
        si = result.reason.sensitive_info
        assert len(si.denied) == 1
        assert si.denied[0].identified_type == "EMAIL"
        assert si.denied[0].start == 0
        assert si.denied[0].end == 16
        assert len(si.allowed) == 1
        assert si.allowed[0].identified_type == "PHONE_NUMBER"

    def test_dry_run_mode(self):
        """JS: 'produces a dry run result in DRY_RUN mode'."""
        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[],
            denied=[
                DetectedSensitiveInfoEntity(
                    start=0, end=9, identified_type=SensitiveInfoEntityIpAddress()
                ),
            ],
        )

        ctx = RequestContext(sensitive_info_content="127.0.0.1 test@example.com")
        rule = detect_sensitive_info(mode=Mode.DRY_RUN, allow=[])

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_sensitive_info_locally(ctx, rule)

        assert result is not None
        assert result.conclusion == decide_pb2.CONCLUSION_DENY
        assert result.state == decide_pb2.RULE_STATE_DRY_RUN

    def test_custom_entity_type(self):
        """JS: 'it blocks entities identified by a custom function'.
        In Python, custom detection is via the WASM import callback, but
        the deny list can reference custom entity type strings."""
        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[],
            denied=[
                DetectedSensitiveInfoEntity(
                    start=8,
                    end=11,
                    identified_type=SensitiveInfoEntityCustom(value="CUSTOM"),
                ),
            ],
        )

        ctx = RequestContext(sensitive_info_content="this is bad")
        rule = detect_sensitive_info(mode=Mode.LIVE, deny=["CUSTOM"])

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_sensitive_info_locally(ctx, rule)

        assert result is not None
        assert result.conclusion == decide_pb2.CONCLUSION_DENY
        si = result.reason.sensitive_info
        assert len(si.denied) == 1
        assert si.denied[0].identified_type == "CUSTOM"
        assert si.denied[0].start == 8
        assert si.denied[0].end == 11

    def test_returns_none_on_exception(self):
        mock_component = MagicMock()
        mock_component.detect_sensitive_info.side_effect = RuntimeError("wasm error")

        ctx = RequestContext(sensitive_info_content="test@example.com")
        rule = detect_sensitive_info(deny=[SensitiveInfoEntityType.EMAIL])

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_sensitive_info_locally(ctx, rule)

        assert result is None

    def test_passes_allow_config_to_component(self):
        """Verify SensitiveInfoEntitiesAllow is passed when rule uses allow."""
        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[], denied=[]
        )

        ctx = RequestContext(sensitive_info_content="test content")
        rule = detect_sensitive_info(
            allow=[SensitiveInfoEntityType.EMAIL, SensitiveInfoEntityType.PHONE_NUMBER]
        )

        with patch("arcjet._local._get_component", return_value=mock_component):
            evaluate_sensitive_info_locally(ctx, rule)

        call_args = mock_component.detect_sensitive_info.call_args
        assert call_args[0][0] == "test content"
        config = call_args[0][1]
        assert isinstance(config, SensitiveInfoConfig)
        assert isinstance(config.entities, SensitiveInfoEntitiesAllow)
        assert len(config.entities.entities) == 2
        assert isinstance(config.entities.entities[0], SensitiveInfoEntityEmail)
        assert isinstance(config.entities.entities[1], SensitiveInfoEntityPhoneNumber)

    def test_passes_deny_config_to_component(self):
        """Verify SensitiveInfoEntitiesDeny is passed when rule uses deny."""
        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[], denied=[]
        )

        ctx = RequestContext(sensitive_info_content="test content")
        rule = detect_sensitive_info(
            deny=[
                SensitiveInfoEntityType.CREDIT_CARD_NUMBER,
                SensitiveInfoEntityType.IP_ADDRESS,
            ]
        )

        with patch("arcjet._local._get_component", return_value=mock_component):
            evaluate_sensitive_info_locally(ctx, rule)

        call_args = mock_component.detect_sensitive_info.call_args
        config = call_args[0][1]
        assert isinstance(config, SensitiveInfoConfig)
        assert isinstance(config.entities, SensitiveInfoEntitiesDeny)
        assert len(config.entities.entities) == 2
        assert isinstance(
            config.entities.entities[0], SensitiveInfoEntityCreditCardNumber
        )
        assert isinstance(config.entities.entities[1], SensitiveInfoEntityIpAddress)

    def test_passes_context_window_size(self):
        """JS: 'it provides the right size context window'."""
        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[], denied=[]
        )

        ctx = RequestContext(sensitive_info_content="my email is test@example.com")
        rule = detect_sensitive_info(allow=[], context_window_size=3)

        with patch("arcjet._local._get_component", return_value=mock_component):
            evaluate_sensitive_info_locally(ctx, rule)

        config = mock_component.detect_sensitive_info.call_args[0][1]
        assert config.context_window_size == 3

    def test_custom_entity_type_mapping(self):
        """Custom string entity types map to SensitiveInfoEntityCustom."""
        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[], denied=[]
        )

        ctx = RequestContext(sensitive_info_content="test")
        rule = detect_sensitive_info(deny=["MY_CUSTOM_TYPE"])

        with patch("arcjet._local._get_component", return_value=mock_component):
            evaluate_sensitive_info_locally(ctx, rule)

        config = mock_component.detect_sensitive_info.call_args[0][1]
        assert isinstance(config.entities, SensitiveInfoEntitiesDeny)
        assert len(config.entities.entities) == 1
        entity = config.entities.entities[0]
        assert isinstance(entity, SensitiveInfoEntityCustom)
        assert entity.value == "MY_CUSTOM_TYPE"


# ---------------------------------------------------------------------------
# _run_local_rules integration — sensitive info dispatch
# ---------------------------------------------------------------------------


class TestRunLocalRulesSensitiveInfo:
    def test_dispatches_sensitive_info_rule(self):
        """SensitiveInfoDetection is dispatched to evaluate_sensitive_info_locally."""
        deny_result = decide_pb2.RuleResult(
            rule_id="",
            state=decide_pb2.RULE_STATE_RUN,
            conclusion=decide_pb2.CONCLUSION_DENY,
            reason=decide_pb2.Reason(
                sensitive_info=decide_pb2.SensitiveInfoReason(
                    denied=[
                        decide_pb2.IdentifiedEntity(
                            identified_type="EMAIL", start=0, end=16
                        )
                    ]
                )
            ),
        )
        ctx = RequestContext(sensitive_info_content="test@example.com")
        rule = detect_sensitive_info(deny=[SensitiveInfoEntityType.EMAIL])

        with (
            patch("arcjet.client.evaluate_bot_locally", return_value=None),
            patch("arcjet.client.evaluate_email_locally", return_value=None),
            patch(
                "arcjet.client.evaluate_sensitive_info_locally",
                return_value=deny_result,
            ),
        ):
            decision = _run_local_rules(ctx, (rule,))

        assert decision is not None
        assert decision.conclusion == decide_pb2.CONCLUSION_DENY

    def test_no_short_circuit_on_deny_dry_run(self):
        """DRY_RUN deny does not short-circuit — proceeds to remote API."""
        deny_dry_run = decide_pb2.RuleResult(
            rule_id="",
            state=decide_pb2.RULE_STATE_DRY_RUN,
            conclusion=decide_pb2.CONCLUSION_DENY,
        )
        ctx = RequestContext(sensitive_info_content="test@example.com")
        rule = detect_sensitive_info(
            mode=Mode.DRY_RUN, deny=[SensitiveInfoEntityType.EMAIL]
        )

        with (
            patch("arcjet.client.evaluate_bot_locally", return_value=None),
            patch("arcjet.client.evaluate_email_locally", return_value=None),
            patch(
                "arcjet.client.evaluate_sensitive_info_locally",
                return_value=deny_dry_run,
            ),
        ):
            result = _run_local_rules(ctx, (rule,))

        assert result is None  # no short-circuit in DRY_RUN

    def test_returns_none_when_evaluator_returns_none(self):
        """When WASM component fails, evaluator returns None → proceed to remote."""
        ctx = RequestContext(sensitive_info_content="test@example.com")
        rule = detect_sensitive_info(deny=[SensitiveInfoEntityType.EMAIL])

        with (
            patch("arcjet.client.evaluate_bot_locally", return_value=None),
            patch("arcjet.client.evaluate_email_locally", return_value=None),
            patch("arcjet.client.evaluate_sensitive_info_locally", return_value=None),
        ):
            result = _run_local_rules(ctx, (rule,))

        assert result is None


# ---------------------------------------------------------------------------
# detect callback support
# ---------------------------------------------------------------------------


class TestDetectCallback:
    """Tests for the custom detect callback on SensitiveInfoDetection."""

    def test_factory_accepts_detect_callback(self):
        """detect_sensitive_info() stores the callback on the rule."""

        def my_detect(tokens: list[str]) -> list[str | None]:
            return [None] * len(tokens)

        rule = detect_sensitive_info(deny=["CUSTOM"], detect=my_detect)
        assert rule.detect is my_detect

    def test_factory_default_detect_is_none(self):
        rule = detect_sensitive_info(deny=["EMAIL"])
        assert rule.detect is None

    def test_skip_custom_detect_true_without_callback(self):
        """skip_custom_detect is True when no detect callback is provided."""
        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[], denied=[]
        )

        ctx = RequestContext(sensitive_info_content="test")
        rule = detect_sensitive_info(deny=[SensitiveInfoEntityType.EMAIL])

        with patch("arcjet._local._get_component", return_value=mock_component):
            evaluate_sensitive_info_locally(ctx, rule)

        config = mock_component.detect_sensitive_info.call_args[0][1]
        assert config.skip_custom_detect is True

    def test_skip_custom_detect_false_with_callback(self):
        """skip_custom_detect is False when a detect callback is provided."""
        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[], denied=[]
        )

        ctx = RequestContext(sensitive_info_content="test")
        rule = detect_sensitive_info(
            deny=["CUSTOM"], detect=lambda tokens: [None] * len(tokens)
        )

        with patch("arcjet._local._get_component", return_value=mock_component):
            evaluate_sensitive_info_locally(ctx, rule)

        config = mock_component.detect_sensitive_info.call_args[0][1]
        assert config.skip_custom_detect is False

    def test_detect_callback_passed_to_component(self):
        """The wrapped detect callback is passed as detect= kwarg."""
        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[], denied=[]
        )

        ctx = RequestContext(sensitive_info_content="test")
        rule = detect_sensitive_info(
            deny=["CUSTOM"], detect=lambda tokens: [None] * len(tokens)
        )

        with patch("arcjet._local._get_component", return_value=mock_component):
            evaluate_sensitive_info_locally(ctx, rule)

        call_kwargs = mock_component.detect_sensitive_info.call_args[1]
        assert "detect" in call_kwargs
        assert call_kwargs["detect"] is not None
        assert callable(call_kwargs["detect"])

    def test_detect_callback_not_passed_when_none(self):
        """When no detect callback, detect=None is passed to component."""
        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[], denied=[]
        )

        ctx = RequestContext(sensitive_info_content="test")
        rule = detect_sensitive_info(deny=[SensitiveInfoEntityType.EMAIL])

        with patch("arcjet._local._get_component", return_value=mock_component):
            evaluate_sensitive_info_locally(ctx, rule)

        call_kwargs = mock_component.detect_sensitive_info.call_args[1]
        assert call_kwargs.get("detect") is None

    def test_detect_callback_converts_strings_to_entities(self):
        """User callback returns strings; wrapper converts to SensitiveInfoEntity."""
        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[], denied=[]
        )

        def my_detect(tokens: list[str]) -> list[str | None]:
            return ["CUSTOM_PII" if "secret" in t else None for t in tokens]

        ctx = RequestContext(sensitive_info_content="this is secret data")
        rule = detect_sensitive_info(deny=["CUSTOM_PII"], detect=my_detect)

        with patch("arcjet._local._get_component", return_value=mock_component):
            evaluate_sensitive_info_locally(ctx, rule)

        # Get the wrapped callback that was passed to the component
        wasm_detect = mock_component.detect_sensitive_info.call_args[1]["detect"]

        # Call it directly to verify conversion
        results = wasm_detect(["hello", "secret", "world"])
        assert results[0] is None
        assert isinstance(results[1], SensitiveInfoEntityCustom)
        assert results[1].value == "CUSTOM_PII"
        assert results[2] is None

    def test_detect_callback_converts_builtin_entity_strings(self):
        """User callback returning 'EMAIL' gets converted to SensitiveInfoEntityEmail."""
        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[], denied=[]
        )

        def my_detect(tokens: list[str]) -> list[str | None]:
            return ["EMAIL" if "@" in t else None for t in tokens]

        ctx = RequestContext(sensitive_info_content="test@example.com hello")
        rule = detect_sensitive_info(deny=["EMAIL"], detect=my_detect)

        with patch("arcjet._local._get_component", return_value=mock_component):
            evaluate_sensitive_info_locally(ctx, rule)

        wasm_detect = mock_component.detect_sensitive_info.call_args[1]["detect"]
        results = wasm_detect(["test@example.com", "hello"])
        assert isinstance(results[0], SensitiveInfoEntityEmail)
        assert results[1] is None

    def test_detect_callback_with_deny_produces_deny(self):
        """Full flow: custom detect finds entity → component returns deny → DENY result."""
        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[],
            denied=[
                DetectedSensitiveInfoEntity(
                    start=8,
                    end=14,
                    identified_type=SensitiveInfoEntityCustom(value="CUSTOM_PII"),
                ),
            ],
        )

        def my_detect(tokens: list[str]) -> list[str | None]:
            return ["CUSTOM_PII" if "secret" in t else None for t in tokens]

        ctx = RequestContext(sensitive_info_content="this is secret data")
        rule = detect_sensitive_info(
            mode=Mode.LIVE, deny=["CUSTOM_PII"], detect=my_detect
        )

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_sensitive_info_locally(ctx, rule)

        assert result is not None
        assert result.conclusion == decide_pb2.CONCLUSION_DENY
        si = result.reason.sensitive_info
        assert len(si.denied) == 1
        assert si.denied[0].identified_type == "CUSTOM_PII"
