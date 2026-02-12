"""Shared pytest fixtures and configuration for all tests.

This conftest provides fixtures that are available to all test modules,
promoting code reuse and consistency across the test suite.

Note: The mocked tests have their own conftest.py that stubs dependencies,
so they should be run separately as documented in tests/README.md.
"""

from __future__ import annotations

import pytest

# Note: These imports may fail for mocked tests which have their own conftest
# The mocked tests should be run separately: pytest tests/mocked/
try:
    from arcjet import arcjet
    from arcjet.rules import token_bucket

    _ARCJET_AVAILABLE = True
except ImportError:
    _ARCJET_AVAILABLE = False


@pytest.fixture
def simple_http_context():
    """A minimal HTTP context for basic testing."""
    return {"type": "http", "headers": []}


if _ARCJET_AVAILABLE:

    @pytest.fixture
    def arcjet_instance():
        """Create a basic arcjet instance with a single token bucket rule.
        
        This fixture provides a common arcjet configuration for tests that
        don't need special rule setups.
        """
        return arcjet(
            key="ajkey_test",
            rules=[token_bucket(refill_rate=1, interval=1, capacity=1)],
        )

    @pytest.fixture
    def arcjet_with_fail_open():
        """Create an arcjet instance configured to fail open on errors."""
        return arcjet(
            key="ajkey_test",
            rules=[token_bucket(refill_rate=1, interval=1, capacity=1)],
            fail_open=True,
        )

    @pytest.fixture
    def arcjet_with_fail_closed():
        """Create an arcjet instance configured to fail closed (raise) on errors."""
        return arcjet(
            key="ajkey_test",
            rules=[token_bucket(refill_rate=1, interval=1, capacity=1)],
            fail_open=False,
        )
