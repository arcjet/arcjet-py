"""Tests for the pure token-aggregation logic (no model load).

Ported from arcjet-js/sensitive-info-rampart/test/model.test.ts.
"""

from __future__ import annotations

from arcjet_sensitive_info_rampart._model import (
    RawToken,
    _merge_windowed_spans,
    aggregate_tokens,
)
from arcjet_sensitive_info_rampart._recognizers import DetectedSpan


def tok(entity, start, end, score=0.99):
    return RawToken(entity=entity, score=score, start=start, end=end)


class TestMergeWindowedSpans:
    def test_empty(self):
        assert _merge_windowed_spans([]) == []

    def test_unions_overlapping_same_type(self):
        # A boundary-straddling entity is detected as two overlapping partial
        # spans in adjacent windows; they union into the full span.
        merged = _merge_windowed_spans(
            [
                DetectedSpan(start=100, end=130, type="STREET_NAME"),
                DetectedSpan(start=116, end=170, type="STREET_NAME"),
            ]
        )
        assert [(s.start, s.end, s.type) for s in merged] == [(100, 170, "STREET_NAME")]

    def test_unions_long_straddle_starting_before_overlap(self):
        # An entity longer than the window overlap that starts before the overlap
        # region is still seen in both windows (both windows cover the overlap),
        # so the partials overlap and union into the full span rather than being
        # left truncated. Guards boundary reconstruction for long entities.
        merged = _merge_windowed_spans(
            [
                DetectedSpan(start=410, end=480, type="STREET_NAME"),
                DetectedSpan(start=416, end=560, type="STREET_NAME"),
            ]
        )
        assert [(s.start, s.end) for s in merged] == [(410, 560)]

    def test_unions_same_type_across_interleaving_other_type(self):
        # Two same-type fragments that overlap must still union even when a
        # different-type span starts between them in sort order (the running
        # span is tracked per type, not just as the last merged span).
        merged = _merge_windowed_spans(
            [
                DetectedSpan(start=100, end=130, type="STREET_NAME"),
                DetectedSpan(start=110, end=120, type="CITY"),
                DetectedSpan(start=116, end=170, type="STREET_NAME"),
            ]
        )
        spans = {(s.start, s.end, s.type) for s in merged}
        assert (100, 170, "STREET_NAME") in spans
        assert (110, 120, "CITY") in spans
        assert len(merged) == 2

    def test_drops_exact_duplicates(self):
        # The overlap region reports the same span from both windows.
        merged = _merge_windowed_spans(
            [
                DetectedSpan(start=10, end=20, type="EMAIL"),
                DetectedSpan(start=10, end=20, type="EMAIL"),
            ]
        )
        assert [(s.start, s.end) for s in merged] == [(10, 20)]

    def test_keeps_distinct_same_type_entities(self):
        # Two distinct same-type entities that do not overlap stay separate.
        merged = _merge_windowed_spans(
            [
                DetectedSpan(start=0, end=5, type="GIVEN_NAME"),
                DetectedSpan(start=10, end=15, type="GIVEN_NAME"),
            ]
        )
        assert [(s.start, s.end) for s in merged] == [(0, 5), (10, 15)]

    def test_does_not_merge_overlapping_different_types(self):
        merged = _merge_windowed_spans(
            [
                DetectedSpan(start=0, end=10, type="CITY"),
                DetectedSpan(start=5, end=15, type="STATE"),
            ]
        )
        assert len(merged) == 2


class TestAggregateTokens:
    def test_empty(self):
        assert aggregate_tokens("", []) == []

    def test_single_token_span(self):
        value = "Alex"
        spans = aggregate_tokens(value, [tok("B-GIVEN_NAME", 0, 4)])
        assert len(spans) == 1
        assert (spans[0].start, spans[0].end, spans[0].type) == (0, 4, "GIVEN_NAME")

    def test_merges_subword_tokens_across_whitespace(self):
        # "Alex Rivera" as two same-type tokens with a space between merges.
        value = "Alex Rivera"
        spans = aggregate_tokens(
            value,
            [tok("B-GIVEN_NAME", 0, 4), tok("I-GIVEN_NAME", 5, 11)],
        )
        assert len(spans) == 1
        assert (spans[0].start, spans[0].end) == (0, 11)

    def test_begin_token_starts_new_span(self):
        # Two B- tokens of the same type do not merge.
        value = "Alex Sam"
        spans = aggregate_tokens(
            value,
            [tok("B-GIVEN_NAME", 0, 4), tok("B-GIVEN_NAME", 5, 8)],
        )
        assert len(spans) == 2

    def test_different_types_do_not_merge(self):
        value = "Alex 123"
        spans = aggregate_tokens(
            value,
            [tok("B-GIVEN_NAME", 0, 4), tok("I-PHONE", 5, 8)],
        )
        assert len(spans) == 2
        assert spans[0].type == "GIVEN_NAME"
        assert spans[1].type == "PHONE_NUMBER"

    def test_outside_token_breaks_span(self):
        value = "Alex of Rivera"
        spans = aggregate_tokens(
            value,
            [
                tok("B-GIVEN_NAME", 0, 4),
                tok("O", 5, 7),
                tok("I-GIVEN_NAME", 8, 14),
            ],
        )
        assert len(spans) == 2

    def test_below_threshold_dropped(self):
        value = "Alex"
        spans = aggregate_tokens(value, [tok("B-GIVEN_NAME", 0, 4, score=0.2)])
        assert spans == []

    def test_non_whitespace_gap_does_not_merge(self):
        # A non-whitespace character between two same-type tokens breaks the run.
        value = "ab-cd"
        spans = aggregate_tokens(
            value,
            [tok("B-CITY", 0, 2), tok("I-CITY", 3, 5)],
        )
        assert len(spans) == 2

    def test_custom_threshold(self):
        value = "Alex"
        assert (
            aggregate_tokens(value, [tok("B-GIVEN_NAME", 0, 4, score=0.6)], 0.7) == []
        )
        spans = aggregate_tokens(value, [tok("B-GIVEN_NAME", 0, 4, score=0.6)], 0.5)
        assert len(spans) == 1
