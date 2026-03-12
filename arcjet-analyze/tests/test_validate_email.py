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

    def test_valid_email_allow_config(self, component: AnalyzeComponent) -> None:
        """Allow config with a@b.c -> valid, no blocked."""
        config = AllowEmailValidationConfig(
            require_top_level_domain=True,
            allow_domain_literal=False,
            allow=[],
        )
        result = component.is_valid_email("a@b.c", config)
        assert isinstance(result, Ok)
        assert result.value.validity == "valid"
        assert result.value.blocked == []

    def test_invalid_blocked_value(self, component: AnalyzeComponent) -> None:
        """Invalid email has INVALID in blocked list."""
        config = AllowEmailValidationConfig(
            require_top_level_domain=True,
            allow_domain_literal=False,
            allow=[],
        )
        result = component.is_valid_email("example", config)
        assert isinstance(result, Ok)
        assert result.value.validity == "invalid"
        assert "INVALID" in result.value.blocked

    def test_free_email_blocked(self, component: AnalyzeComponent) -> None:
        """Free email providers (gmail) are blocked by default with allow config."""
        config = AllowEmailValidationConfig(
            require_top_level_domain=True,
            allow_domain_literal=False,
            allow=[],
        )
        result = component.is_valid_email("example@gmail.com", config)
        assert isinstance(result, Ok)
        assert result.value.validity == "invalid"
        assert "FREE" in result.value.blocked

    def test_missing_tld_blocked(self, component: AnalyzeComponent) -> None:
        """Missing TLD is blocked when requireTopLevelDomain is True."""
        config = AllowEmailValidationConfig(
            require_top_level_domain=True,
            allow_domain_literal=False,
            allow=[],
        )
        result = component.is_valid_email("a@b", config)
        assert isinstance(result, Ok)
        assert result.value.validity == "invalid"
        assert "INVALID" in result.value.blocked

    def test_missing_tld_allowed(self, component: AnalyzeComponent) -> None:
        """Missing TLD is allowed when requireTopLevelDomain is False."""
        config = AllowEmailValidationConfig(
            require_top_level_domain=False,
            allow_domain_literal=False,
            allow=[],
        )
        result = component.is_valid_email("a@b", config)
        assert isinstance(result, Ok)
        assert result.value.validity == "valid"
        assert result.value.blocked == []

    def test_domain_literal_blocked(self, component: AnalyzeComponent) -> None:
        """Domain literal is blocked when allowDomainLiteral is False."""
        config = AllowEmailValidationConfig(
            require_top_level_domain=True,
            allow_domain_literal=False,
            allow=[],
        )
        result = component.is_valid_email("a@[127.0.0.1]", config)
        assert isinstance(result, Ok)
        assert result.value.validity == "invalid"
        assert "INVALID" in result.value.blocked

    def test_domain_literal_allowed(self, component: AnalyzeComponent) -> None:
        """Domain literal is allowed when allowDomainLiteral is True."""
        config = AllowEmailValidationConfig(
            require_top_level_domain=True,
            allow_domain_literal=True,
            allow=[],
        )
        result = component.is_valid_email("a@[127.0.0.1]", config)
        assert isinstance(result, Ok)
        assert result.value.validity == "valid"
        assert result.value.blocked == []

    def test_require_tld_true_localhost(self, component: AnalyzeComponent) -> None:
        """alice@localhost is invalid when requireTopLevelDomain is True."""
        config = AllowEmailValidationConfig(
            require_top_level_domain=True,
            allow_domain_literal=False,
            allow=[],
        )
        result = component.is_valid_email("alice@localhost", config)
        assert isinstance(result, Ok)
        assert result.value.validity == "invalid"

    def test_require_tld_false_localhost(self, component: AnalyzeComponent) -> None:
        """alice@localhost is valid when requireTopLevelDomain is False."""
        config = AllowEmailValidationConfig(
            require_top_level_domain=False,
            allow_domain_literal=False,
            allow=[],
        )
        result = component.is_valid_email("alice@localhost", config)
        assert isinstance(result, Ok)
        assert result.value.validity == "valid"
        assert result.value.blocked == []
