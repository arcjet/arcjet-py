"""Tests for generate-fingerprint export."""

from __future__ import annotations

import json

from arcjet._analyze import AnalyzeComponent, Err, Ok

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

    def test_specific_fingerprint_127(self, component: AnalyzeComponent) -> None:
        """Fingerprint for 127.0.0.1 matches known value from JS tests."""
        request = json.dumps({"ip": "127.0.0.1"})
        result = component.generate_fingerprint(request, [])
        assert isinstance(result, Ok)
        assert result.value == (
            "fp::2::0d219da6100b99f95cf639b77e088c6df3c096aa5fd61dec5287c5cf94d5e545"
        )

    def test_specific_fingerprint_1111(self, component: AnalyzeComponent) -> None:
        """Fingerprint for 1.1.1.1 with ip.src matches known value from JS tests."""
        request = json.dumps({"ip": "1.1.1.1"})
        result = component.generate_fingerprint(request, ["ip.src"])
        assert isinstance(result, Ok)
        assert result.value == (
            "fp::2::10182843b9721ec9901b0b127e10705ae447f41391c1bdb153c9fec8d82bb875"
        )

    def test_specific_fingerprint_other_ip(self, component: AnalyzeComponent) -> None:
        """Fingerprint for 76.76.21.21 matches known value from JS tests."""
        request = json.dumps({"ip": "76.76.21.21"})
        result = component.generate_fingerprint(request, [])
        assert isinstance(result, Ok)
        assert result.value == (
            "fp::2::30cc6b092efff7b35f658730073f40ceae0a724873e1ff175826fc57e1462149"
        )

    def test_different_ips_different_fingerprints(
        self, component: AnalyzeComponent
    ) -> None:
        r1 = component.generate_fingerprint(json.dumps({"ip": "1.2.3.4"}), ["ip.src"])
        r2 = component.generate_fingerprint(json.dumps({"ip": "5.6.7.8"}), ["ip.src"])
        assert isinstance(r1, Ok)
        assert isinstance(r2, Ok)
        assert r1.value != r2.value

    def test_empty_ip_error(self, component: AnalyzeComponent) -> None:
        """Empty request with ip.src characteristic -> error."""
        result = component.generate_fingerprint(json.dumps({}), ["ip.src"])
        assert isinstance(result, Err)
        assert "ip" in result.value.lower()
