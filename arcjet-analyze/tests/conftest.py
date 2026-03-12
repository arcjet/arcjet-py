"""Shared fixtures for arcjet_analyze tests."""

from __future__ import annotations

import os
import sys

import pytest

# Ensure the package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from arcjet_analyze import AnalyzeComponent, ImportCallbacks

WASM_PATH = os.path.join(
    os.path.dirname(__file__), "..", "arcjet_analyze_js_req.component.wasm"
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
