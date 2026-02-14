"""Conftest for unit tests directory.

This makes mock_protobuf_modules autouse for all unit tests to prevent
cross-contamination when tests are run in different orders.
"""

from __future__ import annotations

import pytest

# Import fixtures directly
from fixtures.protobuf_stubs import mock_protobuf_modules


@pytest.fixture(autouse=True)
def _ensure_protobuf_mocked(mock_protobuf_modules):
    """Automatically use mocked protobuf modules for all unit tests.

    This prevents cross-contamination issues when unit tests are run
    after tests that import real protobuf modules.
    """
    # The mock_protobuf_modules fixture does all the work
    # This just makes it autouse for this directory
    pass
