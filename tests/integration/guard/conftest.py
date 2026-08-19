"""Shared test helpers for arcjet.guard integration tests."""

from __future__ import annotations

import pytest
from guard_doubles import reset_sequence_context  # noqa: F401  (fixture)


@pytest.fixture(autouse=True)
def _reset_sequence_context(reset_sequence_context):
    """Apply sequence isolation to every guard test in this directory."""
