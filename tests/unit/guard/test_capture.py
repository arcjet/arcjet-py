"""Unit tests for capture event normalization.

Normalization is the part of capture with no concurrency in it, so these tests
are plain and deterministic. Delivery is covered in ``test_delivery.py``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from arcjet.guard._capture import (
    CAPTURE_OPTION_DROPPED_CODE,
    CAPTURE_SOURCE_SDK,
    build_capture_request,
    normalize_capture_event,
)
from arcjet.guard._diagnostics import CAPTURE_INPUT_INVALID


class _Diagnostics:
    """Records diagnostic codes instead of logging them."""

    def __init__(self) -> None:
        self.codes: list[tuple[str, int]] = []

    def __call__(self, code: str, count: int = 1) -> None:
        self.codes.append((code, count))

    @property
    def just_codes(self) -> list[str]:
        return [code for code, _ in self.codes]


def _normalize(**kwargs: object):
    diag = _Diagnostics()
    event = normalize_capture_event(diagnose=diag, **kwargs)
    return event, diag


class TestAction:
    def test_minimal_event(self) -> None:
        event, diag = _normalize(action="refund.issued")

        assert event is not None
        assert event.action == "refund.issued"
        assert event.correlation_id == ""
        assert event.decision_id == ""
        assert list(event.local_warnings) == []
        assert diag.codes == []

    def test_source_is_always_sdk(self) -> None:
        """The producer sets source; the server never defaults it."""
        event, _ = _normalize(action="refund.issued")

        assert event is not None
        assert event.source == CAPTURE_SOURCE_SDK == "sdk"

    def test_occurred_at_defaults_to_now(self) -> None:
        before = int(datetime.now(tz=timezone.utc).timestamp() * 1000)
        event, _ = _normalize(action="refund.issued")
        after = int(datetime.now(tz=timezone.utc).timestamp() * 1000)

        assert event is not None
        assert before <= event.occurred_at_unix_ms <= after

    def test_missing_action_drops_the_event(self) -> None:
        event, diag = _normalize(action=None)

        assert event is None
        assert diag.just_codes == [CAPTURE_INPUT_INVALID]

    def test_empty_action_drops_the_event(self) -> None:
        event, diag = _normalize(action="")

        assert event is None
        assert diag.just_codes == [CAPTURE_INPUT_INVALID]

    def test_non_string_action_drops_the_event(self) -> None:
        event, diag = _normalize(action=42)

        assert event is None
        assert diag.just_codes == [CAPTURE_INPUT_INVALID]


class TestOptionalFields:
    def test_all_fields_survive(self) -> None:
        occurred = datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)
        event, diag = _normalize(
            action="refund.issued",
            correlation_id="workflow_123",
            decision_id="gdec_abc",
            occurred_at=occurred,
            metadata={"invoice": {"id": "inv_123"}, "refunded": True},
        )

        assert event is not None
        assert event.correlation_id == "workflow_123"
        assert event.decision_id == "gdec_abc"
        assert event.occurred_at_unix_ms == int(occurred.timestamp() * 1000)
        assert dict(event.metadata_json) == {
            "invoice": '{"id":"inv_123"}',
            "refunded": "true",
        }
        assert diag.codes == []

    def test_none_is_not_a_dropped_field(self) -> None:
        """Absent means unset, so it earns no warning."""
        event, diag = _normalize(
            action="refund.issued",
            correlation_id=None,
            decision_id=None,
            occurred_at=None,
            metadata=None,
        )

        assert event is not None
        assert list(event.local_warnings) == []
        assert diag.codes == []

    def test_bad_optional_field_drops_only_itself(self) -> None:
        event, diag = _normalize(
            action="refund.issued",
            correlation_id=123,
            decision_id="gdec_abc",
        )

        assert event is not None
        # The event survives, and the good sibling field is untouched.
        assert event.action == "refund.issued"
        assert event.decision_id == "gdec_abc"
        assert event.correlation_id == ""
        codes = [w.code for w in event.local_warnings]
        assert codes == [CAPTURE_OPTION_DROPPED_CODE]
        assert "correlation_id" in event.local_warnings[0].message
        assert diag.just_codes == [CAPTURE_OPTION_DROPPED_CODE]

    def test_several_bad_fields_each_warn(self) -> None:
        event, _ = _normalize(
            action="refund.issued",
            correlation_id=123,
            decision_id=[],
            occurred_at="yesterday",
            metadata=7,
        )

        assert event is not None
        messages = " ".join(w.message for w in event.local_warnings)
        for name in ("correlation_id", "decision_id", "occurred_at", "metadata"):
            assert name in messages

    def test_non_mapping_metadata_is_dropped(self) -> None:
        event, _ = _normalize(action="refund.issued", metadata=["not", "a", "map"])

        assert event is not None
        assert dict(event.metadata_json) == {}
        assert [w.code for w in event.local_warnings] == [CAPTURE_OPTION_DROPPED_CODE]

    def test_unencodable_metadata_value_drops_one_key(self) -> None:
        event, _ = _normalize(
            action="refund.issued",
            metadata={"good": 1, "bad": {1, 2, 3}},
        )

        assert event is not None
        assert dict(event.metadata_json) == {"good": "1"}
        assert any("bad" in w.message for w in event.local_warnings)


class TestOccurredAt:
    def test_naive_datetime_is_local_time(self) -> None:
        naive = datetime(2026, 7, 27, 12, 0)
        event, diag = _normalize(action="refund.issued", occurred_at=naive)

        assert event is not None
        assert event.occurred_at_unix_ms == int(naive.timestamp() * 1000)
        assert diag.codes == []

    def test_pre_epoch_is_rejected(self) -> None:
        """The wire field is unsigned, so a negative value would wrap."""
        event, diag = _normalize(
            action="refund.issued",
            occurred_at=datetime(1969, 7, 20, tzinfo=timezone.utc),
        )

        assert event is not None
        # Falls back to now rather than sending a wrapped timestamp.
        assert event.occurred_at_unix_ms > 0
        assert [w.code for w in event.local_warnings] == [CAPTURE_OPTION_DROPPED_CODE]
        assert "occurred_at" in event.local_warnings[0].message
        assert diag.just_codes == [CAPTURE_OPTION_DROPPED_CODE]

    def test_epoch_itself_is_allowed(self) -> None:
        event, diag = _normalize(
            action="refund.issued",
            occurred_at=datetime(1970, 1, 1, tzinfo=timezone.utc),
        )

        assert event is not None
        assert event.occurred_at_unix_ms == 0
        assert diag.codes == []

    def test_far_future_is_allowed(self) -> None:
        """Clock skew is the server's problem; the SDK only guards the sign."""
        future = datetime.now(tz=timezone.utc) + timedelta(days=365 * 20)
        event, diag = _normalize(action="refund.issued", occurred_at=future)

        assert event is not None
        assert event.occurred_at_unix_ms == int(future.timestamp() * 1000)
        assert diag.codes == []


class TestHostileInput:
    def test_throwing_mapping_does_not_raise(self) -> None:
        class Hostile(dict):
            def items(self):
                raise RuntimeError("boom")

        event, _ = _normalize(action="refund.issued", metadata=Hostile())

        # encode_metadata swallows the failure, so the event still goes out.
        assert event is not None
        assert dict(event.metadata_json) == {}

    def test_throwing_datetime_subclass_does_not_raise(self) -> None:
        class Hostile(datetime):
            def timestamp(self) -> float:
                raise ValueError("boom")

        event, diag = _normalize(
            action="refund.issued",
            occurred_at=Hostile(2026, 7, 27, tzinfo=timezone.utc),
        )

        assert event is not None
        assert event.occurred_at_unix_ms > 0
        assert diag.just_codes == [CAPTURE_OPTION_DROPPED_CODE]

    def test_action_with_lone_surrogate_does_not_raise(self) -> None:
        """protobuf cannot encode a lone surrogate; it must not escape.

        Either outcome is acceptable — dropped with a diagnostic, or carried
        through — so this asserts each branch is internally consistent rather
        than picking one. `event.action` is checked for truthiness, not for
        `is not None`: a protobuf string field defaults to `""`, so the
        not-None form was always true and asserted nothing.
        """
        event, diag = _normalize(action="refund\ud800.issued")

        if event is None:
            assert diag.just_codes == [CAPTURE_INPUT_INVALID]
        else:
            assert event.action, "a surviving event must carry its action"
            assert event.source == CAPTURE_SOURCE_SDK


class TestCaptureRequest:
    def test_wraps_events_with_user_agent(self) -> None:
        event, _ = _normalize(action="refund.issued")
        assert event is not None

        request = build_capture_request([event], user_agent="arcjet-py/test")

        assert request.user_agent == "arcjet-py/test"
        assert len(request.events) == 1
        assert request.events[0].action == "refund.issued"
        assert request.sent_at_unix_ms > 0
