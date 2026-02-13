"""Shared pytest configuration and fixtures for all tests.

This conftest.py provides common fixtures and configuration for both
unit tests (formerly in tests/mocked) and integration tests.
"""

from __future__ import annotations

import pytest

# Import fixtures from fixture modules to make them available
from fixtures.protobuf_stubs import (
    make_allow_decision,
    make_deny_decision,
    make_error_decision,
    mock_protobuf_modules,
)

__all__ = [
    "make_allow_decision",
    "make_deny_decision",
    "make_error_decision",
    "mock_protobuf_modules",
]


@pytest.fixture
def dev_environment(monkeypatch: pytest.MonkeyPatch):
    """Set up development environment for tests.
    
    This fixture sets ARCJET_ENV=development which provides
    sensible defaults for testing (e.g., 127.0.0.1 for missing IPs).
    """
    monkeypatch.setenv("ARCJET_ENV", "development")
    yield
