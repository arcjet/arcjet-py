"""Unit tests for rule builders and protobuf conversion.

Tests rule configuration, validation, and protobuf message generation.
"""

from __future__ import annotations

import pytest


def test_shield_to_proto_and_characteristics(mock_protobuf_modules):
    """Test shield rule converts to protobuf with mode and characteristics."""
    from arcjet.rules import Mode, shield

    r = shield(mode=Mode.LIVE, characteristics=("uid", "ip"))
    pb = r.to_proto()
    assert pb.shield is not None
    assert pb.shield.mode == mock_protobuf_modules["pb2"].MODE_LIVE
    assert pb.shield.characteristics == ["uid", "ip"]


def test_detect_bot_allows_categories_and_names(mock_protobuf_modules):
    """Test detect_bot rule accepts both categories and string names."""
    from arcjet.rules import BotCategory, detect_bot

    r = detect_bot(allow=(BotCategory.GOOGLE, "OPENAI_CRAWLER_SEARCH"))
    pb = r.to_proto()
    assert pb.bot_v2.allow == [BotCategory.GOOGLE.value, "OPENAI_CRAWLER_SEARCH"]


def test_rate_limit_builders_validation_and_proto(mock_protobuf_modules):
    """Test rate limit rules validate parameters and convert to protobuf."""
    from arcjet.rules import Mode, fixed_window, sliding_window, token_bucket

    tb = token_bucket(mode=Mode.DRY_RUN, refill_rate=10, interval=60, capacity=20)
    pb = tb.to_proto()
    assert (
        pb.rate_limit.algorithm
        == mock_protobuf_modules["pb2"].RATE_LIMIT_ALGORITHM_TOKEN_BUCKET
    )
    assert pb.rate_limit.interval == 60

    fw = fixed_window(max=100, window=60)
    pb2 = fw.to_proto()
    assert pb2.rate_limit.max == 100

    sw = sliding_window(max=77, interval=30)
    pb3 = sw.to_proto()
    assert pb3.rate_limit.interval == 30

    with pytest.raises(ValueError):
        token_bucket(refill_rate=0, interval=1, capacity=1)

    with pytest.raises(ValueError):
        fixed_window(max=0, window=1)

    with pytest.raises(ValueError):
        sliding_window(max=1, interval=0)


def test_validate_email_coercion_and_proto(mock_protobuf_modules):
    """Test validate_email rule coerces string/enum types and converts to protobuf."""
    from arcjet.rules import EmailType, validate_email

    r = validate_email(deny=(EmailType.DISPOSABLE, "INVALID"))
    pb = r.to_proto()
    assert mock_protobuf_modules["pb2"].EMAIL_TYPE_DISPOSABLE in pb.email.deny
    assert mock_protobuf_modules["pb2"].EMAIL_TYPE_INVALID in pb.email.deny
    assert pb.email.allow == []

    r = validate_email(allow=(EmailType.NO_MX_RECORDS, "FREE"))
    pb = r.to_proto()
    assert mock_protobuf_modules["pb2"].EMAIL_TYPE_NO_MX_RECORDS in pb.email.allow
    assert mock_protobuf_modules["pb2"].EMAIL_TYPE_FREE in pb.email.allow
    assert pb.email.deny == []


def test_rule_spec_get_characteristics_with_non_tuple():
    """Test get_characteristics with non-tuple characteristics."""
    from arcjet.proto.decide.v1alpha1 import decide_pb2
    from arcjet.rules import Mode, RuleSpec

    # Create a mock RuleSpec subclass with non-tuple characteristics
    class TestRule(RuleSpec):
        def __init__(self):
            self.characteristics = ["user_id", "session_id"]  # List instead of tuple

        def to_proto(self) -> decide_pb2.Rule:
            return decide_pb2.Rule()

    rule = TestRule()
    chars = rule.get_characteristics()

    # Should convert to tuple
    assert isinstance(chars, tuple)
    assert chars == ("user_id", "session_id")


def test_rule_spec_get_characteristics_with_invalid_items():
    """Test get_characteristics filters out invalid items."""
    from arcjet.proto.decide.v1alpha1 import decide_pb2
    from arcjet.rules import RuleSpec

    class TestRule(RuleSpec):
        def __init__(self):
            self.characteristics = ("valid", 123, "", None, "another_valid")

        def to_proto(self) -> decide_pb2.Rule:
            return decide_pb2.Rule()

    rule = TestRule()
    chars = rule.get_characteristics()

    # Should only include valid strings
    assert chars == ("valid", "another_valid")


def test_rule_spec_get_characteristics_conversion_fails():
    """Test get_characteristics when conversion to tuple fails."""
    from arcjet.proto.decide.v1alpha1 import decide_pb2
    from arcjet.rules import RuleSpec

    class NonIterableCharacteristics:
        def __iter__(self):
            raise TypeError("Not iterable")

    class TestRule(RuleSpec):
        def __init__(self):
            self.characteristics = NonIterableCharacteristics()

        def to_proto(self) -> decide_pb2.Rule:
            return decide_pb2.Rule()

    rule = TestRule()
    chars = rule.get_characteristics()

    # Should return empty tuple on exception
    assert chars == ()


def test_detect_prompt_injection_to_proto(mock_protobuf_modules):
    """Test detect_prompt_injection rule converts to protobuf with mode and threshold."""
    from arcjet.rules import Mode, detect_prompt_injection

    r = detect_prompt_injection(mode=Mode.LIVE, threshold=0.9)
    pb = r.to_proto()
    assert pb.prompt_injection_detection is not None
    assert pb.prompt_injection_detection.mode == mock_protobuf_modules["pb2"].MODE_LIVE
    assert pb.prompt_injection_detection.threshold == 0.9


def test_detect_prompt_injection_default_threshold(mock_protobuf_modules):
    """Test detect_prompt_injection uses default threshold of 0.5."""
    from arcjet.rules import Mode, detect_prompt_injection

    r = detect_prompt_injection(mode=Mode.DRY_RUN)
    pb = r.to_proto()
    assert pb.prompt_injection_detection.threshold == 0.5


def test_detect_prompt_injection_validation(mock_protobuf_modules):
    """Test detect_prompt_injection validates threshold range."""
    from arcjet.rules import detect_prompt_injection

    with pytest.raises(ValueError, match="between 0.0 and 1.0"):
        detect_prompt_injection(threshold=1.5)

    with pytest.raises(ValueError, match="between 0.0 and 1.0"):
        detect_prompt_injection(threshold=-0.1)

    # Edge cases should work
    r1 = detect_prompt_injection(threshold=0.0)
    assert r1.threshold == 0.0

    r2 = detect_prompt_injection(threshold=1.0)
    assert r2.threshold == 1.0
