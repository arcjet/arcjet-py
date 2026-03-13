"""Shared fixtures for WASM benchmarks.

All heavy fixtures are session-scoped to avoid re-paying init costs between
benchmark functions.
"""

from __future__ import annotations

import importlib.resources as _res
import json

import pytest
from arcjet_analyze import (
    AllowedBotConfig,
    AllowEmailValidationConfig,
    AnalyzeComponent,
    DeniedBotConfig,
    DenyEmailValidationConfig,
)

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
