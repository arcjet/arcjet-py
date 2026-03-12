"""Tests for is-valid-email export."""

from __future__ import annotations

from arcjet_analyze import (
    AllowEmailValidationConfig,
    AnalyzeComponent,
    DenyEmailValidationConfig,
    EmailValidationResult,
    Ok,
)


class TestValidateEmail:
    def test_valid_email_deny_config(self, component: AnalyzeComponent) -> None:
        config = DenyEmailValidationConfig(
            require_top_level_domain=True,
            allow_domain_literal=False,
            deny=[],
        )
        result = component.is_valid_email("test@example.com", config)
        assert isinstance(result, Ok)
        assert isinstance(result.value, EmailValidationResult)
        assert result.value.validity == "valid"

    def test_invalid_email(self, component: AnalyzeComponent) -> None:
        config = DenyEmailValidationConfig(
            require_top_level_domain=True,
            allow_domain_literal=False,
            deny=[],
        )
        result = component.is_valid_email("not-an-email", config)
        assert isinstance(result, Ok)
        assert result.value.validity == "invalid"

    def test_allow_config(self, component: AnalyzeComponent) -> None:
        config = AllowEmailValidationConfig(
            require_top_level_domain=True,
            allow_domain_literal=False,
            allow=[],
        )
        result = component.is_valid_email("test@example.com", config)
        assert isinstance(result, Ok)
        assert isinstance(result.value, EmailValidationResult)

    def test_blocked_field_is_list(self, component: AnalyzeComponent) -> None:
        config = DenyEmailValidationConfig(
            require_top_level_domain=True,
            allow_domain_literal=False,
            deny=[],
        )
        result = component.is_valid_email("test@example.com", config)
        assert isinstance(result, Ok)
        assert isinstance(result.value.blocked, list)
