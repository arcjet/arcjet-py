"""Additional context tests for edge cases."""

from __future__ import annotations


def test_context_with_various_extra_values():
    """Test RequestContext with different extra value types."""
    from arcjet.context import RequestContext

    # Test with None extra
    ctx1 = RequestContext(ip="1.2.3.4", extra=None)
    assert ctx1.extra is None

    # Test with empty dict
    ctx2 = RequestContext(ip="1.2.3.4", extra={})
    assert ctx2.extra == {}

    # Test with populated dict
    ctx3 = RequestContext(ip="1.2.3.4", extra={"user_id": "123"})
    assert ctx3.extra == {"user_id": "123"}
