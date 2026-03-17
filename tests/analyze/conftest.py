"""Shared fixtures for arcjet._analyze tests."""

from __future__ import annotations

import importlib.resources as _res
import json
import os

import pytest

from arcjet._analyze import AnalyzeComponent

WASM_PATH = str(
    _res.files("arcjet._analyze") / "wasm" / "arcjet_analyze_js_req.component.wasm"
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


@pytest.fixture(scope="session")
def wasm_path() -> str:
    """Path to the full composite WASM component."""
    assert os.path.exists(WASM_PATH), f"WASM not found: {WASM_PATH}"
    return WASM_PATH


@pytest.fixture(scope="session")
def component(wasm_path: str) -> AnalyzeComponent:
    """Default AnalyzeComponent with no custom callbacks."""
    return AnalyzeComponent(wasm_path)
