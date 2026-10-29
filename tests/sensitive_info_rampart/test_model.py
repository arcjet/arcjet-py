"""Tests for the pure token-aggregation logic (no model load).

Ported from arcjet-js/sensitive-info-rampart/test/model.test.ts.
"""

from __future__ import annotations

from arcjet_sensitive_info_rampart._model import (
    RawToken,
    _merge_windowed_spans,
    _plan_windows,
    aggregate_tokens,
)
from arcjet_sensitive_info_rampart._recognizers import DetectedSpan
from hypothesis import given
from hypothesis import strategies as st


def tok(entity, start, end, score=0.99, *, is_subword=False):
    return RawToken(
        entity=entity,
        score=score,
        start=start,
        end=end,
        is_subword=is_subword,
    )


def _words(*lengths):
    """Word ids for consecutive words of the given token lengths."""
    return [word for word, length in enumerate(lengths) for _ in range(length)]


def _assert_valid_plan(word_ids, budget, overlap, windows):
    n = len(word_ids)
    assert windows[0][0] == 0
    assert windows[-1][1] == n
    for start, end in windows:
        assert 0 < end - start <= budget
    for (prev_start, prev_end), (start, end) in zip(windows, windows[1:]):
        # Strict progress, and every boundary is covered by both windows.
        assert prev_start < start
        assert prev_end < end
        assert prev_end - start >= min(overlap, prev_end - prev_start - 1)


class TestPlanWindows:
    def test_empty(self):
        assert _plan_windows([], budget=510, overlap=64) == []

    def test_exactly_budget_is_one_window(self):
        assert _plan_windows(list(range(510)), budget=510, overlap=64) == [(0, 510)]

    def test_one_over_budget_is_two_windows(self):
        windows = _plan_windows(list(range(511)), budget=510, overlap=64)
        assert windows == [(0, 510), (446, 511)]

    def test_hangul_repro_token_count_is_windowed(self):
        # "각 " * 170 + "x": BertNormalizer decomposes each syllable into three
        # Jamo tokens that share one word and one original offset, so 341
        # characters become 511 content tokens (513 with [CLS]/[SEP]).
        word_ids = _words(*([3] * 170), 1)
        assert len(word_ids) == 511
        windows = _plan_windows(word_ids, budget=510, overlap=64)
        assert len(windows) == 2
        _assert_valid_plan(word_ids, 510, 64, windows)

    def test_next_window_starts_on_a_word_boundary(self):
        word_ids = _words(*([3] * 400))
        windows = _plan_windows(word_ids, budget=510, overlap=64)
        _assert_valid_plan(word_ids, 510, 64, windows)
        for start, _ in windows[1:]:
            assert word_ids[start] != word_ids[start - 1]

    def test_progresses_through_one_word_longer_than_the_window(self):
        # Every token shares a word (and so an offset); planning must still
        # advance rather than snapping back to the same start forever.
        word_ids = [0] * 2000
        windows = _plan_windows(word_ids, budget=510, overlap=64)
        _assert_valid_plan(word_ids, 510, 64, windows)

    @given(
        lengths=st.lists(st.integers(min_value=1, max_value=120), max_size=60),
        budget=st.integers(min_value=2, max_value=600),
        overlap=st.integers(min_value=0, max_value=200),
    )
    def test_plan_is_bounded_complete_and_progresses(self, lengths, budget, overlap):
        overlap = min(overlap, budget - 1)
        word_ids = _words(*lengths)
        windows = _plan_windows(word_ids, budget=budget, overlap=overlap)
        if not word_ids:
            assert windows == []
            return
        _assert_valid_plan(word_ids, budget, overlap, windows)


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

    def test_merges_repeated_begin_labels_inside_a_word(self):
        # The bundled model labels every piece of "Luxembourg" B-CITY.
        value = "Luxembourg"
        spans = aggregate_tokens(
            value,
            [
                tok("B-CITY", 0, 3),
                tok("B-CITY", 3, 5, is_subword=True),
                tok("B-CITY", 5, 10, is_subword=True),
            ],
        )
        assert [(s.start, s.end, s.type) for s in spans] == [(0, 10, "CITY")]

    def test_merges_repeated_begin_labels_inside_an_identifier(self):
        # The model emits B-DRIVERS_LICENSE for every subword of this IBAN.
        value = "US64SVBKUS6S3300958879"
        pieces = [
            "US",
            "64",
            "S",
            "VB",
            "KUS",
            "6",
            "S",
            "33",
            "00",
            "9",
            "58",
            "8",
            "7",
            "9",
        ]
        assert "".join(pieces) == value
        tokens = []
        start = 0
        for piece in pieces:
            end = start + len(piece)
            tokens.append(tok("B-DRIVERS_LICENSE", start, end, is_subword=start > 0))
            start = end

        spans = aggregate_tokens(value, tokens)
        assert [(s.start, s.end, s.type) for s in spans] == [
            (0, len(value), "DRIVERS_LICENSE")
        ]

    def test_merges_subwords_and_continuations_in_a_multiword_entity(self):
        value = "Allée des Chênes"
        spans = aggregate_tokens(
            value,
            [
                tok("B-STREET_NAME", 0, 3),
                tok("B-STREET_NAME", 3, 5, is_subword=True),
                tok("I-STREET_NAME", 6, 9),
                tok("I-STREET_NAME", 10, 14),
                tok("I-STREET_NAME", 14, 16, is_subword=True),
            ],
        )
        assert [(s.start, s.end, s.type) for s in spans] == [
            (0, len(value), "STREET_NAME")
        ]

    def test_begin_token_after_whitespace_starts_new_span(self):
        # A space separates two B- tokens of the same type into distinct entities.
        value = "Alex Sam"
        spans = aggregate_tokens(
            value,
            [tok("B-GIVEN_NAME", 0, 4), tok("B-GIVEN_NAME", 5, 8)],
        )
        assert len(spans) == 2

    def test_touching_begin_token_on_new_word_starts_new_span(self):
        # The punctuation is a separate tokenizer word, not a subword of 12.
        value = "12$"
        spans = aggregate_tokens(
            value,
            [tok("B-BUILDING_NUMBER", 0, 2), tok("B-BUILDING_NUMBER", 2, 3)],
        )
        assert [(s.start, s.end, s.type) for s in spans] == [
            (0, 2, "BUILDING_NUMBER"),
        ]

    def test_touching_begin_token_after_subword_starts_new_span(self):
        value = "Lux$"
        spans = aggregate_tokens(
            value,
            [
                tok("B-CITY", 0, 2),
                tok("B-CITY", 2, 3, is_subword=True),
                tok("B-CITY", 3, 4),
            ],
        )
        assert [(s.start, s.end) for s in spans] == [(0, 3)]

    def test_punctuation_only_model_label_is_not_an_entity(self):
        assert aggregate_tokens("$", [tok("B-EMAIL", 0, 1)]) == []

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
