"""Shared test helpers for arcjet.guard unit tests.

Guard tests use real protobuf imports (``arcjet.guard.proto.decide.v2``),
so we override the parent ``_ensure_protobuf_mocked`` autouse fixture to
prevent the v1alpha1 stubs from interfering.
"""

from __future__ import annotations

import pytest

from arcjet.guard.proto.decide.v2 import decide_pb2 as pb


@pytest.fixture(autouse=True)
def _ensure_protobuf_mocked():
    """No-op override — guard tests use real protobuf modules."""
    yield


def make_response(
    conclusion: int,
    results: list[pb.GuardRuleResult],
    *,
    decision_id: str = "gdec_test123",
) -> pb.GuardResponse:
    """Build a proto GuardResponse for testing."""
    return pb.GuardResponse(
        decision=pb.GuardDecision(
            id=decision_id,
            conclusion=conclusion,  # type: ignore[arg-type]  # proto enum int
            rule_results=results,
        ),
    )
