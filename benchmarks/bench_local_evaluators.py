"""Full local evaluator pipeline benchmarks.

Uses real WASM via _get_component() singleton (pre-warmed by conftest).
Measures the complete path: JSON serialisation → WASM call → proto RuleResult.
"""

from __future__ import annotations

from arcjet._local import evaluate_bot_locally, evaluate_email_locally
from arcjet.context import RequestContext
from arcjet.rules import BotDetection, EmailValidation


def test_bench_evaluate_bot_locally_deny(
    benchmark, bot_ctx: RequestContext, deny_bot_rule: BotDetection
):
    """Full bot evaluation path: curl UA → WASM → DENY RuleResult."""
    benchmark(evaluate_bot_locally, bot_ctx, deny_bot_rule)


def test_bench_evaluate_bot_locally_allow(
    benchmark, browser_ctx: RequestContext, allow_bot_rule: BotDetection
):
    """Full bot evaluation path: browser UA → WASM → ALLOW RuleResult."""
    benchmark(evaluate_bot_locally, browser_ctx, allow_bot_rule)


def test_bench_evaluate_email_locally_valid(
    benchmark, email_ctx: RequestContext, deny_email_rule: EmailValidation
):
    """Full email evaluation path: valid email → WASM → ALLOW RuleResult."""
    benchmark(evaluate_email_locally, email_ctx, deny_email_rule)


def test_bench_evaluate_email_locally_invalid(
    benchmark, bad_email_ctx: RequestContext, deny_email_rule: EmailValidation
):
    """Full email evaluation path: invalid email → WASM → DENY RuleResult."""
    benchmark(evaluate_email_locally, bad_email_ctx, deny_email_rule)
