"""Tests for match-filters export."""

from __future__ import annotations

from arcjet_analyze import AnalyzeComponent, FilterResult, Ok


class TestMatchFilters:
    def test_ok_no_expressions(self, component: AnalyzeComponent) -> None:
        result = component.match_filters("{}", [], True)
        assert isinstance(result, Ok)
        assert isinstance(result.value, FilterResult)
        assert result.value.matched_expressions == []
        assert result.value.undetermined_expressions == []

    def test_ok_allow_if_match(self, component: AnalyzeComponent) -> None:
        result = component.match_filters("{}", [], True)
        assert isinstance(result, Ok)
        # No expressions means no matches — allowed defaults to False
        assert result.value.allowed is False

    def test_ok_deny_if_match(self, component: AnalyzeComponent) -> None:
        result = component.match_filters("{}", [], False)
        assert isinstance(result, Ok)
        # No expressions, allow-if-match=False -> allowed=True
        assert result.value.allowed is True

    def test_multiple_sequential_calls(self, component: AnalyzeComponent) -> None:
        """Fresh Store per call — multiple calls must work."""
        r1 = component.match_filters("{}", [], True)
        r2 = component.match_filters("{}", [], False)
        r3 = component.match_filters("{}", [], True)
        assert isinstance(r1, Ok)
        assert isinstance(r2, Ok)
        assert isinstance(r3, Ok)
