"""Unit tests for enum conversions and helpers.

Tests the Mode enum and conversion utilities without requiring
real protobuf dependencies.
"""

from __future__ import annotations

import pytest

from arcjet._enums import Mode, _mode_to_proto


def test_mode_enum_to_proto(mock_protobuf_modules):
    """Test that Mode enum values convert to correct protobuf constants."""
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    assert Mode.DRY_RUN.to_proto() == decide_pb2.MODE_DRY_RUN
    assert Mode.LIVE.to_proto() == decide_pb2.MODE_LIVE


def test_mode_coercion_variants(mock_protobuf_modules):
    """Test that various string representations of modes are normalized correctly."""
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    # Test DRY_RUN variants
    assert _mode_to_proto("dry_run") == decide_pb2.MODE_DRY_RUN
    assert _mode_to_proto("DRYRUN") == decide_pb2.MODE_DRY_RUN
    assert _mode_to_proto("dry-run") == decide_pb2.MODE_DRY_RUN

    # Test LIVE
    assert _mode_to_proto("live") == decide_pb2.MODE_LIVE


def test_mode_invalid(mock_protobuf_modules):
    """Test that invalid mode strings raise ValueError."""
    with pytest.raises(ValueError):
        _mode_to_proto("staging")
