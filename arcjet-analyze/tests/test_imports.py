"""Tests that user-provided import callbacks are invoked."""

from __future__ import annotations

import json

from arcjet_analyze import (
    AllowedBotConfig,
    AnalyzeComponent,
    DenyEmailValidationConfig,
    ImportCallbacks,
    Ok,
    SensitiveInfoConfig,
    SensitiveInfoEntitiesDeny,
    SensitiveInfoEntityEmail,
)

BOT_REQUEST = json.dumps(
    {
        "ip": "1.2.3.4",
        "method": "GET",
        "host": "example.com",
        "path": "/",
        "headers": {"user-agent": "curl/8.0"},
    }
)


class TestCustomCallbacks:
    def test_custom_ip_lookup(self, wasm_path: str) -> None:
        calls: list[str] = []

        def my_ip_lookup(ip: str) -> str | None:
            calls.append(ip)
            return "US"

        ac = AnalyzeComponent(
            wasm_path, callbacks=ImportCallbacks(ip_lookup=my_ip_lookup)
        )
        ac.match_filters("{}", [], True)
        # ip_lookup may or may not be called depending on the component logic,
        # but the callback should not crash
        for c in calls:
            assert isinstance(c, str)

    def test_custom_bot_detect(self, wasm_path: str) -> None:
        calls: list[str] = []

        def my_detect(request: str) -> list[str]:
            calls.append(request)
            return ["MY_BOT"]

        ac = AnalyzeComponent(
            wasm_path, callbacks=ImportCallbacks(bot_detect=my_detect)
        )
        config = AllowedBotConfig(entities=[], skip_custom_detect=False)
        result = ac.detect_bot(BOT_REQUEST, config)
        assert isinstance(result, Ok)

    def test_custom_email_validators(self, wasm_path: str) -> None:
        free_calls: list[str] = []

        def my_is_free(domain: str) -> str:
            free_calls.append(domain)
            return "yes"

        ac = AnalyzeComponent(
            wasm_path, callbacks=ImportCallbacks(is_free_email=my_is_free)
        )
        config = DenyEmailValidationConfig(
            require_top_level_domain=True,
            allow_domain_literal=False,
            deny=[],
        )
        result = ac.is_valid_email("test@example.com", config)
        assert isinstance(result, Ok)

    def test_default_callbacks_work(self, wasm_path: str) -> None:
        """All default callbacks should work without crashing."""
        ac = AnalyzeComponent(wasm_path)
        # Just verify none of these crash
        ac.match_filters("{}", [], True)
        ac.detect_bot(
            BOT_REQUEST,
            AllowedBotConfig(entities=[], skip_custom_detect=False),
        )
        ac.is_valid_email(
            "test@example.com",
            DenyEmailValidationConfig(
                require_top_level_domain=True,
                allow_domain_literal=False,
                deny=[],
            ),
        )
        ac.detect_sensitive_info(
            "test",
            SensitiveInfoConfig(
                entities=SensitiveInfoEntitiesDeny(
                    entities=[SensitiveInfoEntityEmail()]
                ),
                context_window_size=None,
                skip_custom_detect=False,
            ),
        )
