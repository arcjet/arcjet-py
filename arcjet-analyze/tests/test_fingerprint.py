"""Tests for generate-fingerprint export."""

from __future__ import annotations

import json

from arcjet_analyze import AnalyzeComponent, Err, Ok

REQUEST = json.dumps(
    {
        "ip": "1.2.3.4",
        "method": "GET",
        "host": "example.com",
        "path": "/",
        "headers": {},
    }
)


class TestGenerateFingerprint:
    def test_ok_with_ip_src(self, component: AnalyzeComponent) -> None:
        result = component.generate_fingerprint(REQUEST, ["ip.src"])
        assert isinstance(result, Ok)
        assert isinstance(result.value, str)
        assert result.value.startswith("fp::")

    def test_stable_fingerprint(self, component: AnalyzeComponent) -> None:
        """Same input produces the same fingerprint."""
        r1 = component.generate_fingerprint(REQUEST, ["ip.src"])
        r2 = component.generate_fingerprint(REQUEST, ["ip.src"])
        assert isinstance(r1, Ok)
        assert isinstance(r2, Ok)
        assert r1.value == r2.value

    def test_err_unknown_characteristic(self, component: AnalyzeComponent) -> None:
        """Unknown user-defined characteristic with empty value -> error."""
        result = component.generate_fingerprint(REQUEST, ["nonexistent"])
        assert isinstance(result, Err)
        assert isinstance(result.value, str)

    def test_empty_characteristics(self, component: AnalyzeComponent) -> None:
        """Empty characteristics still returns a (default) fingerprint."""
        result = component.generate_fingerprint(REQUEST, [])
        assert isinstance(result, Ok)
        assert isinstance(result.value, str)
