"""Tests for enum types and mode conversion."""

from __future__ import annotations

import pytest

from arcjet._enums import Mode, _mode_to_proto
from arcjet.proto.decide.v1alpha1 import decide_pb2


def test_mode_enum_to_proto():
    """Test that Mode enum values convert to protobuf constants correctly."""
    assert Mode.DRY_RUN.to_proto() == decide_pb2.MODE_DRY_RUN
    assert Mode.LIVE.to_proto() == decide_pb2.MODE_LIVE


def test_mode_coercion_variants():
    """Test that various string formats are coerced to the correct mode."""
    assert _mode_to_proto("dry_run") == decide_pb2.MODE_DRY_RUN
    assert _mode_to_proto("DRYRUN") == decide_pb2.MODE_DRY_RUN
    assert _mode_to_proto("dry-run") == decide_pb2.MODE_DRY_RUN
    assert _mode_to_proto("live") == decide_pb2.MODE_LIVE


def test_mode_invalid():
    """Test that invalid mode strings raise ValueError."""
    with pytest.raises(ValueError):
        _mode_to_proto("staging")
