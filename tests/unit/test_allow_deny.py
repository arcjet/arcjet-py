"""Tests for detect_bot / validate_email allow XOR deny exclusivity."""

from __future__ import annotations

import pytest


class TestAllowDenyExclusivity:
    def test_detect_bot_rejects_neither(self, mock_protobuf_modules):
        from arcjet._rules import Mode, detect_bot

        with pytest.raises(ValueError, match="either `allow` or `deny`"):
            detect_bot(mode=Mode.LIVE)

    def test_detect_bot_rejects_both(self, mock_protobuf_modules):
        from arcjet._rules import BotCategory, Mode, detect_bot

        with pytest.raises(ValueError, match="cannot be provided together"):
            detect_bot(mode=Mode.LIVE, allow=[BotCategory.GOOGLE], deny=["CURL"])

    def test_detect_bot_empty_allow_blocks_all_bots(self, mock_protobuf_modules):
        from arcjet._rules import Mode, detect_bot

        rule = detect_bot(mode=Mode.LIVE, allow=[])
        assert rule.allow == ()
        assert rule.deny is None

    def test_bot_detection_dataclass_rejects_neither(self, mock_protobuf_modules):
        from arcjet._rules import BotDetection, Mode

        with pytest.raises(ValueError, match="either `allow` or `deny`"):
            BotDetection(mode=Mode.LIVE)

    def test_validate_email_rejects_neither(self, mock_protobuf_modules):
        from arcjet._rules import Mode, validate_email

        with pytest.raises(ValueError, match="either `allow` or `deny`"):
            validate_email(mode=Mode.LIVE)

    def test_validate_email_rejects_both(self, mock_protobuf_modules):
        from arcjet._rules import EmailType, Mode, validate_email

        with pytest.raises(ValueError, match="cannot be provided together"):
            validate_email(
                mode=Mode.LIVE,
                allow=[EmailType.FREE],
                deny=[EmailType.DISPOSABLE],
            )

    def test_validate_email_empty_allow_is_valid(self, mock_protobuf_modules):
        from arcjet._rules import Mode, validate_email

        rule = validate_email(mode=Mode.LIVE, allow=[])
        assert rule.allow == ()
        assert rule.deny is None
