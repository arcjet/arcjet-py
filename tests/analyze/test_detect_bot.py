"""Tests for detect-bot export."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from arcjet._analyze import (
    AllowedBotConfig,
    AnalyzeComponent,
    BotResult,
    DeniedBotConfig,
    Err,
    Ok,
)

from .conftest import BOT_REQUEST as CURL_REQUEST


def _request_with_ua(ua: str) -> str:
    return json.dumps(
        {
            "ip": "127.0.0.1",
            "headers": {"user-agent": ua},
        }
    )


class TestDetectBot:
    def test_allowed_bot_config(self, component: AnalyzeComponent) -> None:
        config = AllowedBotConfig(entities=[], skip_custom_detect=False)
        result = component.detect_bot(CURL_REQUEST, config)
        assert isinstance(result, Ok)
        assert isinstance(result.value, BotResult)

    def test_denied_bot_config(self, component: AnalyzeComponent) -> None:
        config = DeniedBotConfig(entities=[], skip_custom_detect=False)
        result = component.detect_bot(CURL_REQUEST, config)
        assert isinstance(result, Ok)
        assert isinstance(result.value, BotResult)

    def test_allowed_config_detects_curl(self, component: AnalyzeComponent) -> None:
        config = AllowedBotConfig(entities=[], skip_custom_detect=False)
        result = component.detect_bot(CURL_REQUEST, config)
        assert isinstance(result, Ok)
        assert result.value == BotResult(
            allowed=[], denied=["CURL"], verified=False, spoofed=False
        )

    def test_non_bot_user_agent(self, component: AnalyzeComponent) -> None:
        """A normal browser user-agent should not be detected as a bot."""
        config = AllowedBotConfig(entities=[], skip_custom_detect=False)
        result = component.detect_bot(_request_with_ua("Mozilla/5.0"), config)
        assert isinstance(result, Ok)
        assert result.value == BotResult(
            allowed=[], denied=[], verified=False, spoofed=False
        )

    def test_chrome_user_agent(self, component: AnalyzeComponent) -> None:
        """A Chrome user-agent should not be detected as a bot."""
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/58.0.3029.110 Safari/537.3"
        )
        config = AllowedBotConfig(entities=[], skip_custom_detect=False)
        result = component.detect_bot(_request_with_ua(ua), config)
        assert isinstance(result, Ok)
        assert result.value.allowed == []
        assert result.value.denied == []

    def test_fail_without_user_agent(self, component: AnalyzeComponent) -> None:
        """Missing user-agent header returns Err."""
        request = json.dumps({"ip": "127.0.0.1"})
        config = AllowedBotConfig(entities=[], skip_custom_detect=False)
        result = component.detect_bot(request, config)
        assert isinstance(result, Err)
        assert "user-agent" in result.value.lower()

    def test_detect_googlebot(self, component: AnalyzeComponent) -> None:
        config = AllowedBotConfig(entities=[], skip_custom_detect=False)
        result = component.detect_bot(_request_with_ua("Googlebot/2.0"), config)
        assert isinstance(result, Ok)
        assert "GOOGLE_CRAWLER" in result.value.denied
        assert result.value.allowed == []

    def test_allow_curl_by_entity(self, component: AnalyzeComponent) -> None:
        """Adding CURL to entities in allowed-bot-config moves it to allowed."""
        config = AllowedBotConfig(entities=["CURL"], skip_custom_detect=False)
        result = component.detect_bot(_request_with_ua("curl/7.64.1"), config)
        assert isinstance(result, Ok)
        assert result.value == BotResult(
            allowed=["CURL"], denied=[], verified=False, spoofed=False
        )

    def test_denied_config_with_search_engine(
        self, component: AnalyzeComponent
    ) -> None:
        config = DeniedBotConfig(
            entities=["CATEGORY:SEARCH_ENGINE"], skip_custom_detect=False
        )
        result = component.detect_bot(CURL_REQUEST, config)
        assert isinstance(result, Ok)
        assert isinstance(result.value.allowed, list)

    def test_verified_and_spoofed_fields(self, component: AnalyzeComponent) -> None:
        config = AllowedBotConfig(entities=[], skip_custom_detect=False)
        result = component.detect_bot(CURL_REQUEST, config)
        assert isinstance(result, Ok)
        assert isinstance(result.value.verified, bool)
        assert isinstance(result.value.spoofed, bool)

    def test_empty_entity_list(self, component: AnalyzeComponent) -> None:
        config = AllowedBotConfig(entities=[], skip_custom_detect=True)
        result = component.detect_bot(CURL_REQUEST, config)
        assert isinstance(result, Ok)


class TestDetectBotThreadSafety:
    """Verify the AnalyzeComponent lock prevents concurrent-access crashes."""

    def test_concurrent_detect_bot(self, component: AnalyzeComponent) -> None:
        """Call detect_bot from many threads sharing one component instance."""
        config = AllowedBotConfig(entities=[], skip_custom_detect=False)
        num_calls = 20
        errors: list[Exception] = []

        def _call(_i: int) -> Ok[BotResult]:
            result = component.detect_bot(CURL_REQUEST, config)
            assert isinstance(result, Ok)
            return result

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(_call, i) for i in range(num_calls)]
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as exc:
                    errors.append(exc)

        assert errors == [], f"Concurrent detect_bot raised: {errors}"
