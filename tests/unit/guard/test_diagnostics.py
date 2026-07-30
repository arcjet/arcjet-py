"""Unit tests for the local capture diagnostics channel.

The clock is injected so coalescing can be tested without sleeping.
"""

from __future__ import annotations

import logging

from arcjet.guard._diagnostics import (
    CAPTURE_QUEUE_FULL,
    CAPTURE_SEND_FAILED,
    create_diagnose,
)


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class TestDiagnostics:
    def test_logs_a_warning(self, caplog) -> None:
        diagnose = create_diagnose()

        with caplog.at_level(logging.WARNING, logger="arcjet"):
            diagnose(CAPTURE_QUEUE_FULL, 3)

        assert len(caplog.records) == 1
        record = caplog.records[0]
        assert record.levelno == logging.WARNING
        assert CAPTURE_QUEUE_FULL in record.getMessage()
        assert "3 event(s)" in record.getMessage()
        # Structured fields, so a handler can route on them.
        assert record.code == CAPTURE_QUEUE_FULL
        assert record.count == 3

    def test_defaults_to_a_count_of_one(self, caplog) -> None:
        diagnose = create_diagnose()

        with caplog.at_level(logging.WARNING, logger="arcjet"):
            diagnose(CAPTURE_QUEUE_FULL)

        assert "1 event(s)" in caplog.records[0].getMessage()

    def test_repeats_are_coalesced(self, caplog) -> None:
        """A hot loop dropping events must not become a logging incident."""
        clock = FakeClock()
        diagnose = create_diagnose(monotonic=clock, coalesce_seconds=60)

        with caplog.at_level(logging.WARNING, logger="arcjet"):
            for _ in range(100):
                diagnose(CAPTURE_QUEUE_FULL, 1)

        assert len(caplog.records) == 1, "only the first should be logged"

    def test_suppressed_counts_are_reported_later(self, caplog) -> None:
        """Quiet does not mean lost: the next line carries the backlog."""
        clock = FakeClock()
        diagnose = create_diagnose(monotonic=clock, coalesce_seconds=60)

        with caplog.at_level(logging.WARNING, logger="arcjet"):
            diagnose(CAPTURE_QUEUE_FULL, 1)  # logged: 1
            for _ in range(9):
                diagnose(CAPTURE_QUEUE_FULL, 1)  # suppressed: 9 accumulate
            clock.advance(61)
            diagnose(CAPTURE_QUEUE_FULL, 1)  # logged: 9 + 1

        assert len(caplog.records) == 2
        assert "1 event(s)" in caplog.records[0].getMessage()
        assert "10 event(s)" in caplog.records[1].getMessage()

    def test_codes_are_coalesced_independently(self, caplog) -> None:
        clock = FakeClock()
        diagnose = create_diagnose(monotonic=clock, coalesce_seconds=60)

        with caplog.at_level(logging.WARNING, logger="arcjet"):
            diagnose(CAPTURE_QUEUE_FULL, 1)
            diagnose(CAPTURE_SEND_FAILED, 1)
            diagnose(CAPTURE_QUEUE_FULL, 1)

        codes = [r.code for r in caplog.records]
        assert codes == [CAPTURE_QUEUE_FULL, CAPTURE_SEND_FAILED]

    def test_zero_window_logs_everything(self, caplog) -> None:
        diagnose = create_diagnose(monotonic=FakeClock(), coalesce_seconds=0)

        with caplog.at_level(logging.WARNING, logger="arcjet"):
            for _ in range(3):
                diagnose(CAPTURE_QUEUE_FULL, 1)

        assert len(caplog.records) == 3

    def test_unknown_code_still_logs(self, caplog) -> None:
        diagnose = create_diagnose()

        with caplog.at_level(logging.WARNING, logger="arcjet"):
            diagnose("AJ9999", 1)

        assert len(caplog.records) == 1
        assert "AJ9999" in caplog.records[0].getMessage()

    def test_drain_reports_counts_held_back_by_coalescing(self, caplog) -> None:
        """Coalescing alone under-reports a burst that stops.

        This is the defect drain() exists for: 1000 drops inside one quiet window
        logged a single line reading "1 event(s)" and held the other 999 for a
        successor that never arrived — 0.1% of the real total.
        """
        clock = FakeClock()
        diagnose = create_diagnose(monotonic=clock, coalesce_seconds=60)

        with caplog.at_level(logging.WARNING, logger="arcjet"):
            for _ in range(1000):
                diagnose(CAPTURE_QUEUE_FULL, 1)
            # Before draining, only the first event has been reported.
            assert sum(r.count for r in caplog.records) == 1

            diagnose.drain()

        assert sum(r.count for r in caplog.records) == 1000, (
            "drain() must release the suppressed remainder"
        )

    def test_drain_with_nothing_held_back_is_silent(self, caplog) -> None:
        diagnose = create_diagnose(monotonic=FakeClock(), coalesce_seconds=60)

        with caplog.at_level(logging.WARNING, logger="arcjet"):
            diagnose(CAPTURE_QUEUE_FULL, 1)
            before = len(caplog.records)
            diagnose.drain()
            diagnose.drain()

        assert len(caplog.records) == before

    def test_drain_covers_every_code_independently(self, caplog) -> None:
        clock = FakeClock()
        diagnose = create_diagnose(monotonic=clock, coalesce_seconds=60)

        with caplog.at_level(logging.WARNING, logger="arcjet"):
            for _ in range(3):
                diagnose(CAPTURE_QUEUE_FULL, 1)
                diagnose(CAPTURE_SEND_FAILED, 2)
            diagnose.drain()

        totals: dict[str, int] = {}
        for record in caplog.records:
            totals[record.code] = totals.get(record.code, 0) + record.count
        assert totals == {CAPTURE_QUEUE_FULL: 3, CAPTURE_SEND_FAILED: 6}

    def test_drain_never_raises(self) -> None:
        def exploding_monotonic() -> float:
            raise RuntimeError("boom")

        diagnose = create_diagnose(monotonic=exploding_monotonic)

        diagnose(CAPTURE_QUEUE_FULL, 1)
        diagnose.drain()  # must not raise

    def test_never_raises_when_the_handler_fails(self) -> None:
        """A diagnostics sink is observational; it must not break delivery."""

        def exploding_monotonic() -> float:
            raise RuntimeError("boom")

        diagnose = create_diagnose(monotonic=exploding_monotonic)

        diagnose(CAPTURE_QUEUE_FULL, 1)  # must not raise
