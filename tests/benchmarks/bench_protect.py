"""Full protect() benchmarks — macro-level comparison of code paths.

Constructs ArcjetSync directly with a mocked _client.decide() returning a
canned ALLOW decision. Compares: no-WASM baseline, WASM-allow-then-remote,
WASM-deny-short-circuit, email, and combined rules.

The key metric: bench_protect_bot_allow_then_remote mean minus
bench_protect_no_local_rules mean = WASM overhead added to the hot path.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from arcjet._enums import Mode
from arcjet.client import ArcjetSync
from arcjet.context import RequestContext
from arcjet.rules import (
    BotDetection,
    EmailType,
    EmailValidation,
    Shield,
)


def _make_aj(mock_client: MagicMock, *rules) -> ArcjetSync:
    """Construct an ArcjetSync with mocked remote client."""
    needs_email = any(isinstance(r, EmailValidation) for r in rules)
    return ArcjetSync(
        _key="ajkey_test_benchmark_000000000000",
        _rules=tuple(rules),
        _client=mock_client,
        _sdk_stack=None,
        _sdk_version="0.0.0-bench",
        _timeout_ms=1000,
        _fail_open=True,
        _needs_email=needs_email,
    )


def test_bench_protect_no_local_rules(
    benchmark, mock_decide_client: MagicMock, bot_ctx: RequestContext
):
    """Baseline: shield() only, no WASM, mocked remote."""
    aj = _make_aj(mock_decide_client, Shield(mode=Mode.LIVE))
    benchmark(aj.protect, bot_ctx)


def test_bench_protect_bot_allow_then_remote(
    benchmark, mock_decide_client: MagicMock, browser_ctx: RequestContext
):
    """WASM runs (allow for browser UA), then mocked remote."""
    rule = BotDetection(mode=Mode.LIVE, deny=("CURL",))
    aj = _make_aj(mock_decide_client, rule)
    benchmark(aj.protect, browser_ctx)


def test_bench_protect_bot_deny_short_circuit(
    benchmark, mock_decide_client: MagicMock, bot_ctx: RequestContext
):
    """WASM DENY (curl UA), remote never called."""
    rule = BotDetection(mode=Mode.LIVE, deny=("CURL",))
    aj = _make_aj(mock_decide_client, rule)
    benchmark(aj.protect, bot_ctx)


def test_bench_protect_email_allow_then_remote(
    benchmark, mock_decide_client: MagicMock, email_ctx: RequestContext
):
    """WASM email validation (allow), then mocked remote."""
    rule = EmailValidation(mode=Mode.LIVE, deny=(EmailType.DISPOSABLE,))
    aj = _make_aj(mock_decide_client, rule)
    benchmark(aj.protect, email_ctx, email="user@example.com")


def test_bench_protect_bot_plus_email(benchmark, mock_decide_client: MagicMock):
    """Two WASM calls (bot + email), then mocked remote."""
    bot_rule = BotDetection(mode=Mode.LIVE, deny=("CURL",))
    email_rule = EmailValidation(mode=Mode.LIVE, deny=(EmailType.DISPOSABLE,))
    aj = _make_aj(mock_decide_client, bot_rule, email_rule)
    ctx = RequestContext(
        ip="1.2.3.4",
        method="POST",
        host="example.com",
        path="/signup",
        headers={
            "user-agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "content-type": "application/json",
        },
        email="user@example.com",
    )
    benchmark(aj.protect, ctx, email="user@example.com")
