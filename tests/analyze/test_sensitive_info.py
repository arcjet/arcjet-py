"""Tests for detect-sensitive-info export."""

from __future__ import annotations

import pytest

from arcjet._analyze import (
    AnalyzeComponent,
    DetectedSensitiveInfoEntity,
    SensitiveInfoConfig,
    SensitiveInfoEntitiesAllow,
    SensitiveInfoEntitiesDeny,
    SensitiveInfoEntity,
    SensitiveInfoEntityCreditCardNumber,
    SensitiveInfoEntityCustom,
    SensitiveInfoEntityEmail,
    SensitiveInfoEntityIpAddress,
    SensitiveInfoEntityPhoneNumber,
    SensitiveInfoResult,
)


def _deny_config(
    *entities: object,
    context_window_size: int | None = None,
) -> SensitiveInfoConfig:
    return SensitiveInfoConfig(
        entities=SensitiveInfoEntitiesDeny(entities=list(entities)),  # type: ignore[arg-type]
        context_window_size=context_window_size,
        skip_custom_detect=False,
    )


def _allow_config(
    *entities: object,
    context_window_size: int | None = None,
) -> SensitiveInfoConfig:
    return SensitiveInfoConfig(
        entities=SensitiveInfoEntitiesAllow(entities=list(entities)),  # type: ignore[arg-type]
        context_window_size=context_window_size,
        skip_custom_detect=False,
    )


class TestDetectSensitiveInfo:
    def test_deny_email(self, component: AnalyzeComponent) -> None:
        config = _deny_config(SensitiveInfoEntityEmail())
        result = component.detect_sensitive_info("my email is test@example.com", config)
        assert isinstance(result, SensitiveInfoResult)
        assert len(result.denied) >= 1
        assert len(result.allowed) == 0
        entity = result.denied[0]
        assert isinstance(entity, DetectedSensitiveInfoEntity)
        assert isinstance(entity.identified_type, SensitiveInfoEntityEmail)
        assert entity.start >= 0
        assert entity.end > entity.start

    def test_allow_email(self, component: AnalyzeComponent) -> None:
        config = _allow_config(SensitiveInfoEntityEmail())
        result = component.detect_sensitive_info("my email is test@example.com", config)
        assert isinstance(result, SensitiveInfoResult)
        assert len(result.allowed) >= 1
        assert len(result.denied) == 0

    def test_empty_content(self, component: AnalyzeComponent) -> None:
        config = _deny_config(SensitiveInfoEntityEmail())
        result = component.detect_sensitive_info("", config)
        assert isinstance(result, SensitiveInfoResult)
        assert len(result.allowed) == 0
        assert len(result.denied) == 0

    def test_custom_entity_type(self, component: AnalyzeComponent) -> None:
        config = _deny_config(SensitiveInfoEntityCustom(value="ssn"))
        result = component.detect_sensitive_info("some text 123-45-6789", config)
        assert isinstance(result, SensitiveInfoResult)

    def test_multiple_entity_types(self, component: AnalyzeComponent) -> None:
        config = _deny_config(
            SensitiveInfoEntityEmail(), SensitiveInfoEntityPhoneNumber()
        )
        result = component.detect_sensitive_info(
            "email test@example.com phone 555-123-4567", config
        )
        assert isinstance(result, SensitiveInfoResult)

    def test_context_window_size(self, component: AnalyzeComponent) -> None:
        config = _deny_config(SensitiveInfoEntityEmail(), context_window_size=1)
        result = component.detect_sensitive_info("my email is test@example.com", config)
        assert isinstance(result, SensitiveInfoResult)

    # --- Tests ported from JS analyze/test/analyze.test.ts ---

    def test_detect_email_exact_positions(self, component: AnalyzeComponent) -> None:
        """Detect email in 'a b@c.d e' at positions [2, 7]."""
        config = _allow_config(context_window_size=1)
        result = component.detect_sensitive_info("a b@c.d e", config)
        assert result.denied == [
            DetectedSensitiveInfoEntity(
                start=2,
                end=7,
                identified_type=SensitiveInfoEntityEmail(),
            )
        ]
        assert result.allowed == []

    def test_non_sensitive_returns_empty(self, component: AnalyzeComponent) -> None:
        config = _allow_config(context_window_size=1)
        result = component.detect_sensitive_info("a b c d e", config)
        assert result.allowed == []
        assert result.denied == []

    def test_detect_credit_card(self, component: AnalyzeComponent) -> None:
        config = _allow_config(context_window_size=1)
        result = component.detect_sensitive_info("a 4242424242424242 b", config)
        assert result.denied == [
            DetectedSensitiveInfoEntity(
                start=2,
                end=18,
                identified_type=SensitiveInfoEntityCreditCardNumber(),
            )
        ]

    def test_credit_card_in_allow(self, component: AnalyzeComponent) -> None:
        """Credit card in allow list -> appears in allowed, not denied."""
        config = _allow_config(
            SensitiveInfoEntityCreditCardNumber(), context_window_size=1
        )
        result = component.detect_sensitive_info("a 4242424242424242 b", config)
        assert result.allowed == [
            DetectedSensitiveInfoEntity(
                start=2,
                end=18,
                identified_type=SensitiveInfoEntityCreditCardNumber(),
            )
        ]
        assert result.denied == []

    def test_credit_card_with_dashes(self, component: AnalyzeComponent) -> None:
        config = _allow_config(
            SensitiveInfoEntityCreditCardNumber(), context_window_size=1
        )
        result = component.detect_sensitive_info("a 4242-4242-4242-4242 b", config)
        assert result.allowed == [
            DetectedSensitiveInfoEntity(
                start=2,
                end=21,
                identified_type=SensitiveInfoEntityCreditCardNumber(),
            )
        ]

    def test_credit_card_with_spaces(self, component: AnalyzeComponent) -> None:
        config = _allow_config(
            SensitiveInfoEntityCreditCardNumber(), context_window_size=1
        )
        result = component.detect_sensitive_info("a 4242 4242 4242 4242 b", config)
        assert result.allowed == [
            DetectedSensitiveInfoEntity(
                start=2,
                end=21,
                identified_type=SensitiveInfoEntityCreditCardNumber(),
            )
        ]

    def test_detect_email_alice(self, component: AnalyzeComponent) -> None:
        config = _allow_config(context_window_size=1)
        result = component.detect_sensitive_info("a alice@arcjet.com b", config)
        assert result.denied == [
            DetectedSensitiveInfoEntity(
                start=2,
                end=18,
                identified_type=SensitiveInfoEntityEmail(),
            )
        ]

    def test_detect_ip_address(self, component: AnalyzeComponent) -> None:
        config = _allow_config(context_window_size=1)
        result = component.detect_sensitive_info("a 127.0.0.1 b", config)
        assert result.denied == [
            DetectedSensitiveInfoEntity(
                start=2,
                end=11,
                identified_type=SensitiveInfoEntityIpAddress(),
            )
        ]

    def test_detect_phone_number(self, component: AnalyzeComponent) -> None:
        config = _allow_config(context_window_size=1)
        result = component.detect_sensitive_info("a 555-555-5555 b", config)
        assert result.denied == [
            DetectedSensitiveInfoEntity(
                start=2,
                end=14,
                identified_type=SensitiveInfoEntityPhoneNumber(),
            )
        ]

    # --- Per-call detect= override tests ---

    def test_per_call_detect_override(self, component: AnalyzeComponent) -> None:
        """Per-call detect= callback overrides the default for one invocation."""
        called_tokens: list[list[str]] = []

        def my_detect(tokens: list[str]) -> list[SensitiveInfoEntity | None]:
            called_tokens.append(tokens)
            return [  # type: ignore[invalid-return-type]
                SensitiveInfoEntityCustom(value="SECRET")
            ] * len(tokens)

        config = _deny_config(SensitiveInfoEntityCustom(value="SECRET"))
        result = component.detect_sensitive_info(
            "hello world", config, detect=my_detect
        )
        assert isinstance(result, SensitiveInfoResult)
        assert len(called_tokens) > 0

    def test_per_call_detect_does_not_persist(
        self, component: AnalyzeComponent
    ) -> None:
        """Per-call detect= does not affect subsequent calls."""
        call_count = 0

        def counting_detect(tokens: list[str]) -> list[SensitiveInfoEntity | None]:
            nonlocal call_count
            call_count += 1
            return [None] * len(tokens)

        config = _deny_config(SensitiveInfoEntityEmail())
        # First call with override
        component.detect_sensitive_info(
            "test@example.com", config, detect=counting_detect
        )
        assert call_count > 0

        # Second call without override — should use default, not the override
        prev_count = call_count
        component.detect_sensitive_info("test@example.com", config)
        assert call_count == prev_count  # override was not called again


class TestCardDefinition:
    """Pin the card definition the bundled component ships, so an old
    component is caught: these cases differ between the previous issuer table
    and the shared one."""

    @pytest.mark.parametrize(
        ("text", "card"),
        [
            ("card 5500000000000004 ok", "5500000000000004"),
            ("card 22040000000000006 ok", "22040000000000006"),
            ("card 5500 0000-0000 0004 ok", "5500 0000-0000 0004"),
        ],
    )
    def test_detects_card(
        self, component: AnalyzeComponent, text: str, card: str
    ) -> None:
        config = _deny_config(SensitiveInfoEntityCreditCardNumber())
        result = component.detect_sensitive_info(text, config)
        start = text.index(card)
        assert result.denied == [
            DetectedSensitiveInfoEntity(
                start=start,
                end=start + len(card),
                identified_type=SensitiveInfoEntityCreditCardNumber(),
            )
        ]

    def test_no_longer_detects_18_digit_visa(self, component: AnalyzeComponent) -> None:
        config = _deny_config(SensitiveInfoEntityCreditCardNumber())
        result = component.detect_sensitive_info("card 400000000000000002 ok", config)
        assert result.denied == []


class TestEmailDefinition:
    """Pin email changes in the bundled component, so the previous component
    is caught."""

    def test_single_label_domain_is_not_an_email(
        self, component: AnalyzeComponent
    ) -> None:
        config = _deny_config(SensitiveInfoEntityEmail())
        result = component.detect_sensitive_info("write to user@localhost", config)
        assert result.denied == []

    def test_mailto_scheme_is_not_part_of_the_email(
        self, component: AnalyzeComponent
    ) -> None:
        config = _deny_config(SensitiveInfoEntityEmail())
        text = "mailto:alice@example.com"
        result = component.detect_sensitive_info(text, config)
        start = text.index("alice@")
        assert result.denied == [
            DetectedSensitiveInfoEntity(
                start=start,
                end=len(text),
                identified_type=SensitiveInfoEntityEmail(),
            )
        ]
