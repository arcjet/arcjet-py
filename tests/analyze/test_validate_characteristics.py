"""Tests for validate-characteristics export."""

from __future__ import annotations

import json

from arcjet._analyze import AnalyzeComponent, Err, Ok

REQUEST = json.dumps(
    {
        "ip": "1.2.3.4",
        "method": "GET",
        "host": "example.com",
    }
)


class TestValidateCharacteristics:
    def test_valid_characteristics(self, component: AnalyzeComponent) -> None:
        result = component.validate_characteristics(REQUEST, ["ip.src"])
        assert isinstance(result, Ok)
        assert result.value is None

    def test_invalid_characteristic(self, component: AnalyzeComponent) -> None:
        result = component.validate_characteristics(REQUEST, ["nonexistent_field"])
        assert isinstance(result, Err)
        assert isinstance(result.value, str)

    def test_empty_characteristics(self, component: AnalyzeComponent) -> None:
        """Empty characteristics is valid."""
        result = component.validate_characteristics(REQUEST, [])
        assert isinstance(result, Ok)
        assert result.value is None

    def test_invalid_error_message(self, component: AnalyzeComponent) -> None:
        """Error message mentions the missing characteristic."""
        result = component.validate_characteristics(
            json.dumps({"ip": "1.1.1.1"}), ["hi"]
        )
        assert isinstance(result, Err)
        assert "hi" in result.value
