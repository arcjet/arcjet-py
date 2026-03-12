"""Per-call WASM benchmarks — hot path with warm AnalyzeComponent.

These isolate the cost of Store allocation + component instantiation + invoke
for each WASM export. The session-scoped analyze_component fixture means
Engine/Component/Linker creation is NOT included.
"""

from __future__ import annotations

from arcjet_analyze import (
    AllowedBotConfig,
    AnalyzeComponent,
    DeniedBotConfig,
    DenyEmailValidationConfig,
)


def test_bench_detect_bot_deny(
    benchmark,
    analyze_component: AnalyzeComponent,
    bot_request_json: str,
    denied_bot_config: DeniedBotConfig,
):
    """detect_bot with curl UA — bot detected, DENY path."""
    benchmark(analyze_component.detect_bot, bot_request_json, denied_bot_config)


def test_bench_detect_bot_allow(
    benchmark,
    analyze_component: AnalyzeComponent,
    browser_request_json: str,
    allowed_bot_config: AllowedBotConfig,
):
    """detect_bot with browser UA — no bot, ALLOW path."""
    benchmark(analyze_component.detect_bot, browser_request_json, allowed_bot_config)


def test_bench_is_valid_email_valid(
    benchmark,
    analyze_component: AnalyzeComponent,
    deny_email_config: DenyEmailValidationConfig,
):
    """is_valid_email with a valid email address."""
    benchmark(analyze_component.is_valid_email, "user@example.com", deny_email_config)


def test_bench_is_valid_email_invalid(
    benchmark,
    analyze_component: AnalyzeComponent,
    deny_email_config: DenyEmailValidationConfig,
):
    """is_valid_email with an invalid email address."""
    benchmark(analyze_component.is_valid_email, "not-an-email", deny_email_config)


def test_bench_match_filters(
    benchmark, analyze_component: AnalyzeComponent, bot_request_json: str
):
    """match_filters — simplest export, baseline."""
    benchmark(analyze_component.match_filters, bot_request_json, ["true"], True)


def test_bench_generate_fingerprint(
    benchmark, analyze_component: AnalyzeComponent, bot_request_json: str
):
    """generate_fingerprint — fingerprint generation."""
    benchmark(analyze_component.generate_fingerprint, bot_request_json, ["ip.src"])


def test_bench_validate_characteristics(
    benchmark, analyze_component: AnalyzeComponent, bot_request_json: str
):
    """validate_characteristics — cheapest export, baseline for overhead measurement."""
    benchmark(analyze_component.validate_characteristics, bot_request_json, ["ip.src"])
