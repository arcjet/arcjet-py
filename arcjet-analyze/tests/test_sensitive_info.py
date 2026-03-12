"""Tests for detect-sensitive-info export."""

from __future__ import annotations

from arcjet_analyze import (
    AnalyzeComponent,
    DetectedSensitiveInfoEntity,
    SensitiveInfoConfig,
    SensitiveInfoEntitiesAllow,
    SensitiveInfoEntitiesDeny,
    SensitiveInfoEntityCustom,
    SensitiveInfoEntityEmail,
    SensitiveInfoEntityPhoneNumber,
    SensitiveInfoResult,
)


class TestDetectSensitiveInfo:
    def test_deny_email(self, component: AnalyzeComponent) -> None:
        config = SensitiveInfoConfig(
            entities=SensitiveInfoEntitiesDeny(entities=[SensitiveInfoEntityEmail()]),
            context_window_size=None,
            skip_custom_detect=False,
        )
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
        config = SensitiveInfoConfig(
            entities=SensitiveInfoEntitiesAllow(entities=[SensitiveInfoEntityEmail()]),
            context_window_size=None,
            skip_custom_detect=False,
        )
        result = component.detect_sensitive_info("my email is test@example.com", config)
        assert isinstance(result, SensitiveInfoResult)
        assert len(result.allowed) >= 1
        assert len(result.denied) == 0

    def test_empty_content(self, component: AnalyzeComponent) -> None:
        config = SensitiveInfoConfig(
            entities=SensitiveInfoEntitiesDeny(entities=[SensitiveInfoEntityEmail()]),
            context_window_size=None,
            skip_custom_detect=False,
        )
        result = component.detect_sensitive_info("", config)
        assert isinstance(result, SensitiveInfoResult)
        assert len(result.allowed) == 0
        assert len(result.denied) == 0

    def test_custom_entity_type(self, component: AnalyzeComponent) -> None:
        config = SensitiveInfoConfig(
            entities=SensitiveInfoEntitiesDeny(
                entities=[SensitiveInfoEntityCustom(value="ssn")]
            ),
            context_window_size=None,
            skip_custom_detect=False,
        )
        result = component.detect_sensitive_info("some text 123-45-6789", config)
        assert isinstance(result, SensitiveInfoResult)

    def test_multiple_entity_types(self, component: AnalyzeComponent) -> None:
        config = SensitiveInfoConfig(
            entities=SensitiveInfoEntitiesDeny(
                entities=[
                    SensitiveInfoEntityEmail(),
                    SensitiveInfoEntityPhoneNumber(),
                ]
            ),
            context_window_size=None,
            skip_custom_detect=False,
        )
        result = component.detect_sensitive_info(
            "email test@example.com phone 555-123-4567", config
        )
        assert isinstance(result, SensitiveInfoResult)

    def test_context_window_size(self, component: AnalyzeComponent) -> None:
        config = SensitiveInfoConfig(
            entities=SensitiveInfoEntitiesDeny(entities=[SensitiveInfoEntityEmail()]),
            context_window_size=1,
            skip_custom_detect=False,
        )
        result = component.detect_sensitive_info("my email is test@example.com", config)
        assert isinstance(result, SensitiveInfoResult)
