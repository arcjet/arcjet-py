"""Shared test doubles and fixtures for the Arcjet guard surfaces.

Imported flat (``from guard_doubles import ...``) because ``tests/`` is on
sys.path for the suite, the same way ``helpers`` and ``fixtures`` already are.
"""

from __future__ import annotations

import pytest

from arcjet.guard._context import _correlation_id, _sequence_metadata


@pytest.fixture
def reset_sequence_context():
    """Guarantee a test starts and ends outside any sequence.

    ``arcjet_sequence`` restores on exit, so a well-behaved test cannot leak.
    A test that sets the ContextVar directly can — and a leaked correlation ID
    surfaces as an unrelated test failing somewhere else entirely.
    """
    id_token = _correlation_id.set(None)
    metadata_token = _sequence_metadata.set(None)
    try:
        yield
    finally:
        _sequence_metadata.reset(metadata_token)
        _correlation_id.reset(id_token)
