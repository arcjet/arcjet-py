"""Shared fixtures for arcjet_analyze tests."""

from __future__ import annotations

import json
import os
import sys

import pytest

# Ensure the package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from arcjet_analyze import AnalyzeComponent

WASM_PATH = os.path.join(
    os.path.dirname(__file__), "..", "arcjet_analyze_js_req.component.wasm"
)

# Shared request payloads used across test files
BOT_REQUEST = json.dumps(
    {
        "ip": "1.2.3.4",
        "method": "GET",
        "host": "example.com",
        "path": "/",
        "headers": {"user-agent": "curl/8.0"},
    }
)


@pytest.fixture()
def wasm_path() -> str:
    """Path to the full composite WASM component."""
    assert os.path.exists(WASM_PATH), f"WASM not found: {WASM_PATH}"
    return WASM_PATH


@pytest.fixture()
def component(wasm_path: str) -> AnalyzeComponent:
    """Default AnalyzeComponent with no custom callbacks."""
    return AnalyzeComponent(wasm_path)
