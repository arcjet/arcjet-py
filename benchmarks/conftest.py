"""Shared fixtures for WASM benchmarks.

All heavy fixtures are session-scoped to avoid re-paying init costs between
benchmark functions.
"""

from __future__ import annotations

import importlib.resources as _res
import json
from unittest.mock import MagicMock

import pytest
from arcjet_analyze import (
    AllowedBotConfig,
    AllowEmailValidationConfig,
    AnalyzeComponent,
    DeniedBotConfig,
    DenyEmailValidationConfig,
)

from arcjet._enums import Mode
from arcjet._local import _get_component
from arcjet.context import RequestContext
from arcjet.rules import BotDetection, EmailType, EmailValidation, Shield

# ---------------------------------------------------------------------------
# WASM component fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def wasm_path() -> str:
    """Resolve the WASM binary via importlib.resources."""
    ref = _res.files("arcjet_analyze") / "wasm" / "arcjet_analyze_js_req.component.wasm"
    return str(ref)


@pytest.fixture(scope="session")
def analyze_component(wasm_path: str) -> AnalyzeComponent:
    """Warm AnalyzeComponent — Engine/Component/Linker already initialised."""
    return AnalyzeComponent(wasm_path)


@pytest.fixture(autouse=True, scope="session")
def prewarm_wasm_component() -> None:
    """Ensure the _get_component() singleton is initialised before benchmarks."""
    _get_component()


# ---------------------------------------------------------------------------
# Pre-built JSON request strings
# ---------------------------------------------------------------------------

_BOT_REQUEST = {
    "ip": "1.2.3.4",
    "method": "GET",
    "host": "example.com",
    "path": "/",
    "headers": {"user-agent": "curl/7.64.1"},
}

_BROWSER_REQUEST = {
    "ip": "1.2.3.4",
    "method": "GET",
    "host": "example.com",
    "path": "/",
    "headers": {
        "user-agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.5",
    },
}


@pytest.fixture(scope="session")
def bot_request_json() -> str:
    return json.dumps(_BOT_REQUEST)


@pytest.fixture(scope="session")
def browser_request_json() -> str:
    return json.dumps(_BROWSER_REQUEST)


# ---------------------------------------------------------------------------
# Pre-built RequestContext instances
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def bot_ctx() -> RequestContext:
    return RequestContext(
        ip="1.2.3.4",
        method="GET",
        host="example.com",
        path="/",
        headers={"user-agent": "curl/7.64.1"},
    )


@pytest.fixture(scope="session")
def browser_ctx() -> RequestContext:
    return RequestContext(
        ip="1.2.3.4",
        method="GET",
        host="example.com",
        path="/",
        headers={
            "user-agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.5",
        },
    )


@pytest.fixture(scope="session")
def email_ctx() -> RequestContext:
    return RequestContext(
        ip="1.2.3.4",
        method="POST",
        host="example.com",
        path="/signup",
        headers={"content-type": "application/json"},
        email="user@example.com",
    )


@pytest.fixture(scope="session")
def bad_email_ctx() -> RequestContext:
    return RequestContext(
        ip="1.2.3.4",
        method="POST",
        host="example.com",
        path="/signup",
        headers={"content-type": "application/json"},
        email="not-an-email",
    )


@pytest.fixture(scope="session")
def many_headers_ctx() -> RequestContext:
    """RequestContext with 20 headers for worst-case serialization benchmarks."""
    headers = {f"x-custom-header-{i}": f"value-{i}" for i in range(20)}
    headers["user-agent"] = "curl/7.64.1"
    return RequestContext(
        ip="1.2.3.4",
        method="GET",
        host="example.com",
        path="/",
        headers=headers,
    )


# ---------------------------------------------------------------------------
# WASM config fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def denied_bot_config() -> DeniedBotConfig:
    return DeniedBotConfig(entities=["CURL"], skip_custom_detect=False)


@pytest.fixture(scope="session")
def allowed_bot_config() -> AllowedBotConfig:
    return AllowedBotConfig(
        entities=["CATEGORY:SEARCH_ENGINE"], skip_custom_detect=False
    )


@pytest.fixture(scope="session")
def deny_email_config() -> DenyEmailValidationConfig:
    return DenyEmailValidationConfig(
        require_top_level_domain=True,
        allow_domain_literal=False,
        deny=["DISPOSABLE"],
    )


@pytest.fixture(scope="session")
def allow_email_config() -> AllowEmailValidationConfig:
    return AllowEmailValidationConfig(
        require_top_level_domain=True,
        allow_domain_literal=False,
        allow=[],
    )


# ---------------------------------------------------------------------------
# Rule fixtures (for local evaluator benchmarks)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def deny_bot_rule() -> BotDetection:
    return BotDetection(mode=Mode.LIVE, deny=("CURL",))


@pytest.fixture(scope="session")
def allow_bot_rule() -> BotDetection:
    return BotDetection(mode=Mode.LIVE, allow=("CATEGORY:SEARCH_ENGINE",))


@pytest.fixture(scope="session")
def deny_email_rule() -> EmailValidation:
    return EmailValidation(mode=Mode.LIVE, deny=(EmailType.DISPOSABLE,))


# ---------------------------------------------------------------------------
# Macro benchmark helpers (bench_protect.py)
# ---------------------------------------------------------------------------


def _make_canned_allow_decision():
    """Build a canned ALLOW Decision proto for mocked remote calls."""
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    return decide_pb2.DecideResponse(
        decision=decide_pb2.Decision(
            id="test_bench_decision",
            conclusion=decide_pb2.CONCLUSION_ALLOW,
            reason=decide_pb2.Reason(),
            rule_results=[],
        )
    )


@pytest.fixture(scope="session")
def mock_decide_client() -> MagicMock:
    """A MagicMock that mimics DecideServiceClientSync.decide()."""
    client = MagicMock()
    client.decide.return_value = _make_canned_allow_decision()
    # report() is fire-and-forget, just make it a no-op
    client.report.return_value = None
    return client


@pytest.fixture(scope="session")
def shield_rule() -> Shield:
    return Shield(mode=Mode.LIVE)
