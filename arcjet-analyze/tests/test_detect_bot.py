"""Tests for detect-bot export."""

from __future__ import annotations

import json

from arcjet_analyze import (
    AllowedBotConfig,
    AnalyzeComponent,
    BotResult,
    DeniedBotConfig,
    Ok,
)

REQUEST = json.dumps(
    {
        "ip": "1.2.3.4",
        "method": "GET",
        "host": "example.com",
        "path": "/",
        "headers": {"user-agent": "curl/8.0"},
    }
)


class TestDetectBot:
    def test_allowed_bot_config(self, component: AnalyzeComponent) -> None:
        config = AllowedBotConfig(entities=[], skip_custom_detect=False)
        result = component.detect_bot(REQUEST, config)
        assert isinstance(result, Ok)
        assert isinstance(result.value, BotResult)

    def test_denied_bot_config(self, component: AnalyzeComponent) -> None:
        config = DeniedBotConfig(entities=[], skip_custom_detect=False)
        result = component.detect_bot(REQUEST, config)
        assert isinstance(result, Ok)
        assert isinstance(result.value, BotResult)

    def test_allowed_config_detects_curl(self, component: AnalyzeComponent) -> None:
        config = AllowedBotConfig(entities=[], skip_custom_detect=False)
        result = component.detect_bot(REQUEST, config)
        assert isinstance(result, Ok)
        # curl user-agent should be detected as a denied bot
        assert "CURL" in result.value.denied

    def test_denied_config_with_search_engine(
        self, component: AnalyzeComponent
    ) -> None:
        config = DeniedBotConfig(
            entities=["CATEGORY:SEARCH_ENGINE"], skip_custom_detect=False
        )
        result = component.detect_bot(REQUEST, config)
        assert isinstance(result, Ok)
        # curl is detected and moves to allowed since it's not in denied list
        assert isinstance(result.value.allowed, list)

    def test_verified_and_spoofed_fields(self, component: AnalyzeComponent) -> None:
        config = AllowedBotConfig(entities=[], skip_custom_detect=False)
        result = component.detect_bot(REQUEST, config)
        assert isinstance(result, Ok)
        assert isinstance(result.value.verified, bool)
        assert isinstance(result.value.spoofed, bool)

    def test_empty_entity_list(self, component: AnalyzeComponent) -> None:
        config = AllowedBotConfig(entities=[], skip_custom_detect=True)
        result = component.detect_bot(REQUEST, config)
        assert isinstance(result, Ok)
