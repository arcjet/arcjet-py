"""Shared fixtures for arcjet._analyze tests."""

from __future__ import annotations

import importlib.resources as _res
import json
import os
from collections.abc import Iterator

import pytest

from arcjet._analyze import AnalyzeComponent
from arcjet._analyze._safety import collect_wasmtime_finalizers

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


@pytest.fixture(autouse=True)
def _drain_wasmtime_finalizers() -> Iterator[None]:
    """Drain wasmtime cyclic finalizers between tests.

    pytest 9.1 runs one ``gc.collect()`` pass on CPython between tests
    (pytest#14441). wasmtime-py handle slabs need several cyclic passes
    or a deferred ``__del__`` can corrupt ``Slab.allocate`` in the next
    test (arcjet-py#154).
    """
    yield
    collect_wasmtime_finalizers()


@pytest.fixture(scope="session")
def component(wasm_path: str) -> Iterator[AnalyzeComponent]:
    """Default AnalyzeComponent with no custom callbacks."""
    ac = AnalyzeComponent(wasm_path)
    yield ac
    ac.close()
    collect_wasmtime_finalizers()
