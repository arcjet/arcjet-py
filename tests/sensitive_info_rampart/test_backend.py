"""Tests for the rampart() backend using a stubbed model runner.

Ported from arcjet-js/sensitive-info-rampart/test/index.test.ts (backend parts).
"""

from __future__ import annotations

import logging

from arcjet_sensitive_info_rampart import RampartOptions, merge_spans, rampart
from arcjet_sensitive_info_rampart._entities import (
    from_analyze_entity,
    to_analyze_entity,
)
from arcjet_sensitive_info_rampart._recognizers import DetectedSpan

from arcjet._analyze import SensitiveInfoEntitiesAllow, SensitiveInfoEntitiesDeny
from arcjet._sensitive_info_backend import (
    SensitiveInfoBackendContext,
    SensitiveInfoBackendOptions,
)

_CTX = SensitiveInfoBackendContext(log=logging.getLogger("test.rampart"))


def _model_returning(*spans):
    def run_model(value):
        return [DetectedSpan(start=s, end=e, type=t) for (s, e, t) in spans]

    return run_model


def _deny(*types):
    return SensitiveInfoEntitiesDeny(entities=[to_analyze_entity(t) for t in types])


def _allow(*types):
    return SensitiveInfoEntitiesAllow(entities=[to_analyze_entity(t) for t in types])


def _typenames(entities):
    return [from_analyze_entity(e.identified_type) for e in entities]


class TestMergeSpans:
    def test_longer_span_wins_within_group(self):
        # Both the CITY and STREET_NAME come from the model (one group); the
        # longer, distinct entity is kept rather than fragmented by the shorter.
        short = DetectedSpan(0, 4, "CITY")
        long = DetectedSpan(0, 10, "STREET_NAME")
        merged = merge_spans([[short, long]])
        assert len(merged) == 1
        assert merged[0].type == "STREET_NAME"

    def test_recognizer_wins_over_longer_model_span(self):
        # A higher-precedence recognizer span (group 0) must win over a longer
        # overlapping model span (group 1) so its type is not lost. Otherwise an
        # allow-listed EMAIL detected by the recognizer would be relabelled by the
        # model and then mis-bucketed as denied.
        recognizer = DetectedSpan(8, 18, "EMAIL")
        model = DetectedSpan(0, 18, "URL")
        merged = merge_spans([[recognizer], [model]])
        assert len(merged) == 1
        assert merged[0].type == "EMAIL"
        assert (merged[0].start, merged[0].end) == (8, 18)

    def test_equal_length_earlier_group_wins(self):
        recognizer = DetectedSpan(0, 5, "EMAIL")
        model = DetectedSpan(0, 5, "GIVEN_NAME")
        merged = merge_spans([[recognizer], [model]])
        assert len(merged) == 1
        assert merged[0].type == "EMAIL"

    def test_non_overlapping_kept_and_sorted(self):
        a = DetectedSpan(10, 15, "CITY")
        b = DetectedSpan(0, 5, "STATE")
        merged = merge_spans([[a, b]])
        assert [s.start for s in merged] == [0, 10]

    def test_many_spans_neighbour_overlap_resolution(self):
        # Exercises the bisect neighbour check: disjoint spans are all kept and
        # returned sorted by start; lower-precedence spans overlapping an
        # accepted one on either side are dropped, non-overlapping ones kept.
        group0 = [
            DetectedSpan(0, 5, "EMAIL"),
            DetectedSpan(20, 25, "EMAIL"),
            DetectedSpan(40, 45, "EMAIL"),
        ]
        group1 = [
            DetectedSpan(4, 8, "URL"),  # overlaps EMAIL[0,5] on the left
            DetectedSpan(24, 30, "URL"),  # overlaps EMAIL[20,25] on the left
            DetectedSpan(50, 55, "URL"),  # disjoint
        ]
        merged = merge_spans([group0, group1])
        starts = [s.start for s in merged]
        assert starts == sorted(starts)
        kept = {(s.start, s.end, s.type) for s in merged}
        assert kept == {
            (0, 5, "EMAIL"),
            (20, 25, "EMAIL"),
            (40, 45, "EMAIL"),
            (50, 55, "URL"),
        }


class TestRampartBackend:
    def test_deny_mode_denies_listed_types(self):
        backend = rampart(
            RampartOptions(
                recognizers=(),
                run_model=_model_returning(
                    (0, 4, "GIVEN_NAME"), (10, 20, "STREET_NAME")
                ),
            )
        )
        result = backend.detect(_CTX, "x" * 30, _deny("GIVEN_NAME"))
        assert _typenames(result.denied) == ["GIVEN_NAME"]
        assert _typenames(result.allowed) == ["STREET_NAME"]

    def test_allow_mode_denies_everything_else(self):
        backend = rampart(
            RampartOptions(
                recognizers=(),
                run_model=_model_returning(
                    (0, 4, "GIVEN_NAME"), (10, 20, "STREET_NAME")
                ),
            )
        )
        result = backend.detect(_CTX, "x" * 30, _allow("GIVEN_NAME"))
        assert _typenames(result.allowed) == ["GIVEN_NAME"]
        assert _typenames(result.denied) == ["STREET_NAME"]

    def test_recognizer_wins_over_model_on_overlap(self):
        # Model labels the email span as a name; the recognizer must win.
        value = "alice@example.com"
        backend = rampart(
            RampartOptions(run_model=_model_returning((0, len(value), "GIVEN_NAME")))
        )
        result = backend.detect(_CTX, value, _deny("EMAIL", "GIVEN_NAME"))
        denied = _typenames(result.denied)
        assert denied == ["EMAIL"]

    def test_allow_mode_keeps_recognizer_type_over_longer_model_span(self):
        # A recognizer detects the email; the model labels a *longer* overlapping
        # span a different type. The recognizer must still win so that, in allow
        # mode, an allow-listed EMAIL is not mis-bucketed as denied.
        value = "see: alice@example.com"  # model span is longer than the email
        backend = rampart(
            RampartOptions(run_model=_model_returning((0, len(value), "URL")))
        )
        result = backend.detect(_CTX, value, _allow("EMAIL"))
        assert _typenames(result.allowed) == ["EMAIL"]
        assert _typenames(result.denied) == []

    def test_maps_offsets_and_types(self):
        backend = rampart(
            RampartOptions(
                recognizers=(), run_model=_model_returning((3, 7, "SURNAME"))
            )
        )
        result = backend.detect(_CTX, "abc defg hij", _deny("SURNAME"))
        entity = result.denied[0]
        assert (entity.start, entity.end) == (3, 7)
        assert from_analyze_entity(entity.identified_type) == "SURNAME"

    def test_detect_callback_ignored_with_debug_log(self, caplog):
        backend = rampart(RampartOptions(recognizers=(), run_model=_model_returning()))
        options = SensitiveInfoBackendOptions(
            detect=lambda tokens: [None] * len(tokens)
        )
        with caplog.at_level(logging.DEBUG, logger="test.rampart"):
            backend.detect(_CTX, "nothing", _deny("EMAIL"), options)
        assert any(
            "ignored by the Rampart backend" in r.message for r in caplog.records
        )

    def test_no_detections_returns_empty(self):
        backend = rampart(RampartOptions(recognizers=(), run_model=_model_returning()))
        result = backend.detect(_CTX, "nothing here", _deny("EMAIL"))
        assert result.allowed == []
        assert result.denied == []


class TestMaxInputChars:
    def test_truncates_input_over_limit_and_warns(self, caplog):
        seen = {}

        def run_model(value):
            seen["value_len"] = len(value)
            return []

        backend = rampart(
            RampartOptions(recognizers=(), run_model=run_model, max_input_chars=10)
        )
        with caplog.at_level(logging.WARNING, logger="test.rampart"):
            result = backend.detect(_CTX, "x" * 50, _deny("EMAIL"))
        # The model only ever sees the truncated prefix.
        assert seen["value_len"] == 10
        assert any(
            "exceeds the Rampart backend limit" in r.message for r in caplog.records
        )
        assert result.denied == []

    def test_recognizers_only_scan_within_limit(self):
        # An email past the limit is not scanned (recognizers see the truncated
        # prefix), so no detection escapes the request-cost bound.
        value = ("x" * 40) + " alice@example.com"
        backend = rampart(
            RampartOptions(run_model=_model_returning(), max_input_chars=20)
        )
        result = backend.detect(_CTX, value, _deny("EMAIL"))
        assert _typenames(result.denied) == []

    def test_input_within_limit_not_truncated(self, caplog):
        seen = {}

        def run_model(value):
            seen["value_len"] = len(value)
            return []

        backend = rampart(
            RampartOptions(recognizers=(), run_model=run_model, max_input_chars=100)
        )
        with caplog.at_level(logging.WARNING, logger="test.rampart"):
            backend.detect(_CTX, "short text", _deny("EMAIL"))
        assert seen["value_len"] == len("short text")
        assert not any("exceeds" in r.message for r in caplog.records)

    def test_default_limit_applied_when_unset(self):
        from arcjet_sensitive_info_rampart import DEFAULT_MAX_INPUT_CHARS

        seen = {}

        def run_model(value):
            seen["value_len"] = len(value)
            return []

        backend = rampart(RampartOptions(recognizers=(), run_model=run_model))
        backend.detect(_CTX, "y" * (DEFAULT_MAX_INPUT_CHARS + 25), _deny("EMAIL"))
        assert seen["value_len"] == DEFAULT_MAX_INPUT_CHARS
