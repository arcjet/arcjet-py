"""Tests that user-provided import callbacks are invoked."""

from __future__ import annotations

import json

import pytest

from arcjet._analyze import (
    AllowedBotConfig,
    AllowEmailValidationConfig,
    AnalyzeComponent,
    DenyEmailValidationConfig,
    ImportCallbacks,
    Ok,
    SensitiveInfoConfig,
    SensitiveInfoEntitiesAllow,
    SensitiveInfoEntitiesDeny,
    SensitiveInfoEntity,
    SensitiveInfoEntityCustom,
    SensitiveInfoEntityEmail,
    SensitiveInfoEntityPhoneNumber,
)

from .conftest import BOT_REQUEST

FILTER_REQUEST = json.dumps({"ip": "1.2.3.4"})


class TestDefaultCallbacks:
    """Verify the built-in default callbacks behave correctly."""

    def test_default_callbacks_work(self, wasm_path: str) -> None:
        """All default callbacks should work without crashing."""
        ac = AnalyzeComponent(wasm_path)
        ac.match_filters("{}", "{}", [], True)
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

    def test_default_bot_verify_directly(self) -> None:
        """Default bot_verify returns 'unverifiable' for any input."""
        from arcjet._analyze._import_defaults import _default_bot_verify

        assert _default_bot_verify("googlebot", "66.249.66.1") == "unverifiable"

    def test_default_is_free_email_gmail(self, component: AnalyzeComponent) -> None:
        """Default is_free_email blocks gmail.com."""
        config = AllowEmailValidationConfig(
            require_top_level_domain=True,
            allow_domain_literal=False,
            allow=[],
        )
        result = component.is_valid_email("alice@gmail.com", config)
        assert isinstance(result, Ok)
        assert "FREE" in result.value.blocked

    def test_default_is_free_email_yahoo(self, component: AnalyzeComponent) -> None:
        """Default is_free_email blocks yahoo.com."""
        config = AllowEmailValidationConfig(
            require_top_level_domain=True,
            allow_domain_literal=False,
            allow=[],
        )
        result = component.is_valid_email("alice@yahoo.com", config)
        assert isinstance(result, Ok)
        assert "FREE" in result.value.blocked

    def test_default_is_free_email_hotmail(self, component: AnalyzeComponent) -> None:
        """Default is_free_email blocks hotmail.com."""
        config = AllowEmailValidationConfig(
            require_top_level_domain=True,
            allow_domain_literal=False,
            allow=[],
        )
        result = component.is_valid_email("alice@hotmail.com", config)
        assert isinstance(result, Ok)
        assert "FREE" in result.value.blocked

    def test_default_is_free_email_non_free(self, component: AnalyzeComponent) -> None:
        """Default is_free_email does not block custom domains."""
        config = AllowEmailValidationConfig(
            require_top_level_domain=True,
            allow_domain_literal=False,
            allow=[],
        )
        result = component.is_valid_email("alice@arcjet.com", config)
        assert isinstance(result, Ok)
        assert "FREE" not in result.value.blocked
        assert result.value.validity == "valid"

    def test_default_bot_detect_returns_empty(
        self, component: AnalyzeComponent
    ) -> None:
        """Default bot_detect returns [] — WASM handles detection natively."""
        config = AllowedBotConfig(entities=[], skip_custom_detect=False)
        result = component.detect_bot(BOT_REQUEST, config)
        assert isinstance(result, Ok)
        # curl is detected by the WASM component, not by the import callback
        assert "CURL" in result.value.denied

    def test_default_bot_verify_returns_unverifiable(
        self, component: AnalyzeComponent
    ) -> None:
        """Default bot_verify returns 'unverifiable' — bots are not verified."""
        config = AllowedBotConfig(entities=[], skip_custom_detect=False)
        result = component.detect_bot(BOT_REQUEST, config)
        assert isinstance(result, Ok)
        assert result.value.verified is False

    def test_default_sensitive_info_detect_no_custom(
        self, component: AnalyzeComponent
    ) -> None:
        """Default sensitive_info_detect returns no custom detections."""
        config = SensitiveInfoConfig(
            entities=SensitiveInfoEntitiesDeny(entities=[]),
            context_window_size=1,
            skip_custom_detect=False,
        )
        result = component.detect_sensitive_info("hello world", config)
        assert result.allowed == []
        assert result.denied == []


class TestCustomIpLookup:
    def test_custom_ip_lookup_called(self, wasm_path: str) -> None:
        calls: list[str] = []

        def my_ip_lookup(ip: str) -> str | None:
            calls.append(ip)
            return json.dumps({"country": "US"})

        ac = AnalyzeComponent(
            wasm_path, callbacks=ImportCallbacks(ip_lookup=my_ip_lookup)
        )
        ac.match_filters(FILTER_REQUEST, "{}", [], True)
        assert len(calls) >= 1
        for c in calls:
            assert isinstance(c, str)

    def test_ip_lookup_returns_none(self, wasm_path: str) -> None:
        """ip_lookup returning None works (no enrichment)."""
        ac = AnalyzeComponent(
            wasm_path, callbacks=ImportCallbacks(ip_lookup=lambda _ip: None)
        )
        result = ac.match_filters(FILTER_REQUEST, "{}", [], True)
        assert isinstance(result, Ok)


class TestCustomBotDetect:
    def test_custom_bot_detect_called(self, wasm_path: str) -> None:
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
        assert len(calls) == 1

    def test_custom_bot_detect_result_used(self, wasm_path: str) -> None:
        """Custom bot detect results appear in the final result."""
        ac = AnalyzeComponent(
            wasm_path,
            callbacks=ImportCallbacks(bot_detect=lambda _req: ["CUSTOM_BOT"]),
        )
        config = AllowedBotConfig(entities=[], skip_custom_detect=False)
        result = ac.detect_bot(BOT_REQUEST, config)
        assert isinstance(result, Ok)
        assert "CUSTOM_BOT" in result.value.denied

    def test_custom_bot_detect_skip(self, wasm_path: str) -> None:
        """skip_custom_detect=True skips the custom callback."""
        calls: list[str] = []

        def tracking_detect(req: str) -> list[str]:
            calls.append(req)
            return ["CUSTOM_BOT"]

        ac = AnalyzeComponent(
            wasm_path,
            callbacks=ImportCallbacks(bot_detect=tracking_detect),
        )
        config = AllowedBotConfig(entities=[], skip_custom_detect=True)
        result = ac.detect_bot(BOT_REQUEST, config)
        assert isinstance(result, Ok)
        assert len(calls) == 0
        assert "CUSTOM_BOT" not in result.value.denied
        assert "CUSTOM_BOT" not in result.value.allowed


class TestCustomBotVerify:
    def test_custom_bot_verify_wired(self, wasm_path: str) -> None:
        """Custom bot_verify callback does not crash."""
        ac = AnalyzeComponent(
            wasm_path,
            callbacks=ImportCallbacks(bot_verify=lambda _bot_id, _ip: "verified"),
        )
        config = AllowedBotConfig(entities=[], skip_custom_detect=False)
        result = ac.detect_bot(BOT_REQUEST, config)
        assert isinstance(result, Ok)

    def test_bot_verify_unverifiable_default(self, wasm_path: str) -> None:
        """Default bot_verify returns 'unverifiable' — bots stay unverified.

        Note: verify is only invoked by the WASM component when it determines
        a bot is potentially verifiable (based on IP ranges).  With test IPs
        the callback is not reached, so verified/spoofed stay False.
        """
        ac = AnalyzeComponent(wasm_path)
        config = AllowedBotConfig(entities=[], skip_custom_detect=False)
        result = ac.detect_bot(BOT_REQUEST, config)
        assert isinstance(result, Ok)
        assert result.value.verified is False
        assert result.value.spoofed is False


class TestCustomEmailValidators:
    def test_custom_is_free_email(self, wasm_path: str) -> None:
        """Custom is_free_email callback is invoked."""
        calls: list[str] = []

        def my_is_free(domain: str) -> str:
            calls.append(domain)
            return "yes"

        ac = AnalyzeComponent(
            wasm_path, callbacks=ImportCallbacks(is_free_email=my_is_free)
        )
        config = AllowEmailValidationConfig(
            require_top_level_domain=True,
            allow_domain_literal=False,
            allow=[],
        )
        result = ac.is_valid_email("test@example.com", config)
        assert isinstance(result, Ok)
        assert len(calls) >= 1
        assert "example.com" in calls

    def test_custom_is_disposable_email(self, wasm_path: str) -> None:
        """Custom is_disposable_email that returns 'yes' blocks the email."""
        ac = AnalyzeComponent(
            wasm_path,
            callbacks=ImportCallbacks(is_disposable_email=lambda _domain: "yes"),
        )
        config = AllowEmailValidationConfig(
            require_top_level_domain=True,
            allow_domain_literal=False,
            allow=[],
        )
        result = ac.is_valid_email("test@example.com", config)
        assert isinstance(result, Ok)
        assert "DISPOSABLE" in result.value.blocked

    def test_custom_has_mx_records_no(self, wasm_path: str) -> None:
        """Custom has_mx_records returning 'no' blocks the email."""
        ac = AnalyzeComponent(
            wasm_path,
            callbacks=ImportCallbacks(has_mx_records=lambda _domain: "no"),
        )
        config = AllowEmailValidationConfig(
            require_top_level_domain=True,
            allow_domain_literal=False,
            allow=[],
        )
        result = ac.is_valid_email("test@example.com", config)
        assert isinstance(result, Ok)
        assert "NO_MX_RECORDS" in result.value.blocked

    def test_custom_has_gravatar_yes(self, wasm_path: str) -> None:
        """Custom has_gravatar callback doesn't crash and is wired correctly."""
        calls: list[str] = []

        def tracking_gravatar(email: str) -> str:
            calls.append(email)
            return "yes"

        ac = AnalyzeComponent(
            wasm_path,
            callbacks=ImportCallbacks(has_gravatar=tracking_gravatar),
        )
        config = AllowEmailValidationConfig(
            require_top_level_domain=True,
            allow_domain_literal=False,
            allow=[],
        )
        result = ac.is_valid_email("test@example.com", config)
        assert isinstance(result, Ok)
        # has_gravatar should be called with the email address
        assert len(calls) >= 1

    def test_all_email_validators_combined(self, wasm_path: str) -> None:
        """All four email validator callbacks can be set simultaneously."""
        ac = AnalyzeComponent(
            wasm_path,
            callbacks=ImportCallbacks(
                is_free_email=lambda _d: "unknown",
                is_disposable_email=lambda _d: "unknown",
                has_mx_records=lambda _d: "yes",
                has_gravatar=lambda _e: "unknown",
            ),
        )
        config = DenyEmailValidationConfig(
            require_top_level_domain=True,
            allow_domain_literal=False,
            deny=[],
        )
        result = ac.is_valid_email("test@example.com", config)
        assert isinstance(result, Ok)
        assert result.value.validity == "valid"


class TestCustomSensitiveInfoDetect:
    def test_custom_detect_called(self, wasm_path: str) -> None:
        """Custom sensitive_info_detect callback is invoked with tokens."""
        all_tokens: list[list[str]] = []

        def my_detect(tokens: list[str]) -> list[SensitiveInfoEntity | None]:
            all_tokens.append(tokens)
            return [None] * len(tokens)  # type: ignore[invalid-return-type]

        ac = AnalyzeComponent(
            wasm_path,
            callbacks=ImportCallbacks(sensitive_info_detect=my_detect),
        )
        config = SensitiveInfoConfig(
            entities=SensitiveInfoEntitiesAllow(entities=[]),
            context_window_size=1,
            skip_custom_detect=False,
        )
        ac.detect_sensitive_info("a b c d e", config)
        # Callback should have been invoked
        assert len(all_tokens) > 0
        for tokens in all_tokens:
            assert isinstance(tokens, list)
            for t in tokens:
                assert isinstance(t, str)

    def test_custom_detect_returns_entity(self, wasm_path: str) -> None:
        """Custom detect returning an entity causes it to appear in results."""

        def my_detect(
            tokens: list[str],
        ) -> list[SensitiveInfoEntity | None]:
            return [
                SensitiveInfoEntityCustom("secret") if t == "c" else None
                for t in tokens
            ]

        ac = AnalyzeComponent(
            wasm_path,
            callbacks=ImportCallbacks(sensitive_info_detect=my_detect),
        )
        config = SensitiveInfoConfig(
            entities=SensitiveInfoEntitiesAllow(entities=[]),
            context_window_size=1,
            skip_custom_detect=False,
        )
        result = ac.detect_sensitive_info("a b c d e", config)
        # The custom-detected "c" should appear in denied (not in allow list)
        custom_entities = [
            e
            for e in result.denied
            if isinstance(e.identified_type, SensitiveInfoEntityCustom)
        ]
        assert len(custom_entities) >= 1
        ident = custom_entities[0].identified_type
        assert isinstance(ident, SensitiveInfoEntityCustom)
        assert ident.value == "secret"

    def test_custom_detect_skip(self, wasm_path: str) -> None:
        """skip_custom_detect=True skips the custom callback."""
        calls = 0

        def my_detect(tokens: list[str]) -> list[SensitiveInfoEntity | None]:
            nonlocal calls
            calls += 1
            return [None] * len(tokens)  # type: ignore[invalid-return-type]

        ac = AnalyzeComponent(
            wasm_path,
            callbacks=ImportCallbacks(sensitive_info_detect=my_detect),
        )
        config = SensitiveInfoConfig(
            entities=SensitiveInfoEntitiesDeny(entities=[]),
            context_window_size=1,
            skip_custom_detect=True,
        )
        ac.detect_sensitive_info("hello world", config)
        assert calls == 0

    def test_custom_detect_with_phone_entity(self, wasm_path: str) -> None:
        """Custom detect can return built-in entity types."""

        def my_detect(
            tokens: list[str],
        ) -> list[SensitiveInfoEntity | None]:
            return [
                SensitiveInfoEntityPhoneNumber() if "555" in t else None for t in tokens
            ]

        ac = AnalyzeComponent(
            wasm_path,
            callbacks=ImportCallbacks(sensitive_info_detect=my_detect),
        )
        config = SensitiveInfoConfig(
            entities=SensitiveInfoEntitiesDeny(
                entities=[SensitiveInfoEntityPhoneNumber()]
            ),
            context_window_size=1,
            skip_custom_detect=False,
        )
        result = ac.detect_sensitive_info("call 555-1234 now", config)
        phone_entities = [
            e
            for e in result.denied
            if isinstance(e.identified_type, SensitiveInfoEntityPhoneNumber)
        ]
        assert len(phone_entities) >= 1


class TestCallbackErrorPropagation:
    """Verify that exceptions from callbacks propagate cleanly to the caller."""

    def test_bot_detect_exception_propagates(self, wasm_path: str) -> None:
        """An exception in bot_detect surfaces to the caller."""

        def bad_detect(_req: str) -> list[str]:
            raise ValueError("boom from bot_detect")

        ac = AnalyzeComponent(
            wasm_path, callbacks=ImportCallbacks(bot_detect=bad_detect)
        )
        config = AllowedBotConfig(entities=[], skip_custom_detect=False)
        with pytest.raises(ValueError, match="boom from bot_detect"):
            ac.detect_bot(BOT_REQUEST, config)

    def test_is_free_email_exception_propagates(self, wasm_path: str) -> None:
        """An exception in is_free_email surfaces to the caller."""

        def bad_is_free(_domain: str) -> str:
            raise RuntimeError("boom from is_free_email")

        ac = AnalyzeComponent(
            wasm_path, callbacks=ImportCallbacks(is_free_email=bad_is_free)
        )
        config = AllowEmailValidationConfig(
            require_top_level_domain=True,
            allow_domain_literal=False,
            allow=[],
        )
        with pytest.raises(RuntimeError, match="boom from is_free_email"):
            ac.is_valid_email("test@example.com", config)

    def test_sensitive_info_detect_exception_propagates(self, wasm_path: str) -> None:
        """An exception in sensitive_info_detect surfaces to the caller."""

        def bad_detect(_tokens: list[str]) -> list[SensitiveInfoEntity | None]:
            raise TypeError("boom from sensitive_info_detect")

        ac = AnalyzeComponent(
            wasm_path,
            callbacks=ImportCallbacks(sensitive_info_detect=bad_detect),
        )
        config = SensitiveInfoConfig(
            entities=SensitiveInfoEntitiesDeny(entities=[]),
            context_window_size=1,
            skip_custom_detect=False,
        )
        with pytest.raises(TypeError, match="boom from sensitive_info_detect"):
            ac.detect_sensitive_info("hello world", config)

    def test_sensitive_info_detect_length_mismatch(self, wasm_path: str) -> None:
        """sensitive_info_detect returning wrong length raises ValueError."""

        def wrong_length(tokens: list[str]) -> list[SensitiveInfoEntity | None]:
            # Return fewer results than tokens
            return [None]

        ac = AnalyzeComponent(
            wasm_path,
            callbacks=ImportCallbacks(sensitive_info_detect=wrong_length),
        )
        config = SensitiveInfoConfig(
            entities=SensitiveInfoEntitiesDeny(entities=[]),
            context_window_size=3,
            skip_custom_detect=False,
        )
        with pytest.raises(ValueError, match="results for .* tokens"):
            ac.detect_sensitive_info("a b c d e", config)

    def test_per_call_detect_exception_propagates(self, wasm_path: str) -> None:
        """An exception in a per-call detect override surfaces to the caller."""

        def bad_detect(_tokens: list[str]) -> list[SensitiveInfoEntity | None]:
            raise RuntimeError("boom from per-call detect")

        ac = AnalyzeComponent(wasm_path)
        config = SensitiveInfoConfig(
            entities=SensitiveInfoEntitiesDeny(entities=[]),
            context_window_size=1,
            skip_custom_detect=False,
        )
        with pytest.raises(RuntimeError, match="boom from per-call detect"):
            ac.detect_sensitive_info("hello world", config, detect=bad_detect)

    def test_per_call_detect_length_mismatch(self, wasm_path: str) -> None:
        """Per-call detect returning wrong length raises ValueError."""

        def wrong_length(tokens: list[str]) -> list[SensitiveInfoEntity | None]:
            return [None]

        ac = AnalyzeComponent(wasm_path)
        config = SensitiveInfoConfig(
            entities=SensitiveInfoEntitiesDeny(entities=[]),
            context_window_size=3,
            skip_custom_detect=False,
        )
        with pytest.raises(ValueError, match="results for .* tokens"):
            ac.detect_sensitive_info("a b c d e", config, detect=wrong_length)


class TestCloseAndContextManager:
    """Verify close() and context manager behavior."""

    def test_close_prevents_further_calls(self, wasm_path: str) -> None:
        """After close(), calling any export raises RuntimeError."""
        ac = AnalyzeComponent(wasm_path)
        # Sanity: works before close
        ac.match_filters("{}", "{}", [], True)
        ac.close()
        with pytest.raises(RuntimeError, match="closed"):
            ac.match_filters("{}", "{}", [], True)

    def test_context_manager_closes_on_exit(self, wasm_path: str) -> None:
        """Exiting a with-block closes the component."""
        with AnalyzeComponent(wasm_path) as ac:
            ac.match_filters("{}", "{}", [], True)
        with pytest.raises(RuntimeError, match="closed"):
            ac.match_filters("{}", "{}", [], True)

    def test_close_prevents_detect_sensitive_info_override(
        self, wasm_path: str
    ) -> None:
        """close() also blocks the per-call override path in detect_sensitive_info."""
        ac = AnalyzeComponent(wasm_path)
        ac.close()
        config = SensitiveInfoConfig(
            entities=SensitiveInfoEntitiesDeny(entities=[]),
            context_window_size=1,
            skip_custom_detect=False,
        )
        with pytest.raises(RuntimeError, match="closed"):
            ac.detect_sensitive_info(
                "hello",
                config,
                detect=lambda t: [None] * len(t),
            )

    def test_close_is_idempotent(self, wasm_path: str) -> None:
        """Calling close() multiple times does not raise."""
        ac = AnalyzeComponent(wasm_path)
        ac.close()
        ac.close()  # Should not raise
