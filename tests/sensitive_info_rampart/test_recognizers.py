"""Tests for the deterministic recognizers.

Ported from arcjet-js/sensitive-info-rampart/test/recognizers.test.ts.
"""

from __future__ import annotations

from arcjet_sensitive_info_rampart._recognizers import (
    credit_card_recognizer,
    default_recognizers,
    email_recognizer,
    ip_address_recognizer,
    is_phone_number,
    luhn,
    phone_recognizer,
    run_recognizers,
    ssn_recognizer,
    url_recognizer,
)


def _types(spans):
    return sorted(s.type for s in spans)


def _text(value, span):
    return value[span.start : span.end]


class TestLuhn:
    def test_valid_card(self):
        assert luhn("4242424242424242") is True

    def test_invalid_card(self):
        assert luhn("4242424242424241") is False


class TestEmail:
    def test_matches_email(self):
        value = "reach me at alice@example.com please"
        spans = email_recognizer(value)
        assert len(spans) == 1
        assert _text(value, spans[0]) == "alice@example.com"
        assert spans[0].type == "EMAIL"

    def test_no_match(self):
        assert email_recognizer("no address here") == []


class TestUrl:
    def test_https(self):
        value = "see https://example.com/path?x=1 for more"
        spans = url_recognizer(value)
        assert len(spans) == 1
        assert _text(value, spans[0]) == "https://example.com/path?x=1"

    def test_www(self):
        value = "visit www.example.com today"
        spans = url_recognizer(value)
        assert _text(value, spans[0]) == "www.example.com"

    def test_trailing_period_trimmed(self):
        value = "see https://example.com."
        spans = url_recognizer(value)
        assert len(spans) == 1
        assert _text(value, spans[0]) == "https://example.com"

    def test_trailing_comma_in_list_trimmed(self):
        value = "https://a.example.com, https://b.example.com"
        spans = url_recognizer(value)
        assert [_text(value, s) for s in spans] == [
            "https://a.example.com",
            "https://b.example.com",
        ]


class TestIpAddress:
    def test_ipv4(self):
        value = "server at 192.168.0.1 responded"
        spans = ip_address_recognizer(value)
        assert any(_text(value, s) == "192.168.0.1" for s in spans)

    def test_ipv6(self):
        value = "addr 2001:0db8:85a3:0000:0000:8a2e:0370:7334 ok"
        spans = ip_address_recognizer(value)
        assert any("2001:0db8" in _text(value, s) for s in spans)

    def test_clock_time_not_matched(self):
        # A clock time must not be mistaken for an IPv6 address.
        assert ip_address_recognizer("at 12:34:56 today") == []


class TestSsn:
    def test_dashed_ssn(self):
        value = "ssn 472-81-0094 on file"
        spans = ssn_recognizer(value)
        assert _text(value, spans[0]) == "472-81-0094"
        assert spans[0].type == "SSN"


class TestPhone:
    def test_matches_phone(self):
        value = "call +1 (555) 123-4567 now"
        spans = phone_recognizer(value)
        assert len(spans) >= 1
        assert spans[0].type == "PHONE_NUMBER"

    def test_short_number_rejected(self):
        # Fewer than 7 digits should not be treated as a phone number.
        assert phone_recognizer("only 123 45") == []

    def test_bare_digit_run_rejected(self):
        # A run of digits with no phone structure (no +, parens, or separator)
        # is an order number / SKU / account id, not a phone number.
        assert phone_recognizer("order 12345678 shipped") == []
        assert phone_recognizer("SKU 1234567890123") == []
        assert phone_recognizer("account 987654321") == []

    def test_separated_number_still_matches(self):
        # A separator is enough structure to treat it as a phone number.
        value = "call 555-123-4567 today"
        spans = phone_recognizer(value)
        assert len(spans) == 1
        assert _text(value, spans[0]) == "555-123-4567"

    def test_ip_address_not_matched_as_phone(self):
        # IP addresses must not be misclassified as phone numbers.
        assert phone_recognizer("connect to 192.126.0.1 now") == []
        assert phone_recognizer("host 255.255.255.255") == []


# Parity with the Rust `is_phone_number` parser in arcjet-analyze
# (parsers/src/parsers/phone_number.rs). Mirrors its rstest cases exactly.
_PHONE_CASES = [
    ("911", False),
    ("112", False),
    ("14020", False),
    ("14 020", False),
    ("this is not a number", False),
    ("555.223.4562", True),
    ("087 123 4567", True),
    ("+353871234567", True),
    ("5552341234", True),
    ("1552341234", False),
    ("5551341234", False),
    ("(555)-123-1234", True),
    ("(555) 123 1234", True),
    ("(555) 555 5555", True),
    ("555-555-5555", True),
    ("+1 (555) 555-5555", True),
    ("020 334 4522", True),
    ("(020) 334 4522", True),
    ("+31 20 1234567", True),
    ("(049) 1234567", True),
    ("+39 049 1234567", True),
    ("018258291", True),
    ("01 825 1829", True),
    ("+353 1 825 1829", True),
    ("02031237890", True),
    ("0125/12345678", True),
    ("1.2.3.4", False),
    ("192.126.0.1", False),
    ("127.0.0.1", False),
    ("255.255.255.255", False),
]


class TestIsPhoneNumber:
    def test_matches_rust_parser(self):
        for candidate, expected in _PHONE_CASES:
            assert is_phone_number(candidate) is expected, candidate


class TestCreditCard:
    def test_luhn_valid_card(self):
        value = "card 4242 4242 4242 4242 charged"
        spans = credit_card_recognizer(value)
        assert len(spans) == 1
        assert _text(value, spans[0]) == "4242 4242 4242 4242"
        assert spans[0].type == "CREDIT_CARD_NUMBER"

    def test_luhn_invalid_card_rejected(self):
        # 16 digits but fails the Luhn checksum.
        assert credit_card_recognizer("card 4242 4242 4242 4241") == []


class TestRunRecognizers:
    def test_collects_all(self):
        value = "alice@example.com and 4242 4242 4242 4242"
        spans = run_recognizers(value)
        assert "EMAIL" in _types(spans)
        assert "CREDIT_CARD_NUMBER" in _types(spans)

    def test_custom_recognizer_list(self):
        value = "alice@example.com and 4242 4242 4242 4242"
        spans = run_recognizers(value, [email_recognizer])
        assert _types(spans) == ["EMAIL"]

    def test_empty_recognizer_list(self):
        assert run_recognizers("alice@example.com", []) == []

    def test_default_recognizers_order(self):
        assert default_recognizers[0] is credit_card_recognizer
        assert phone_recognizer not in default_recognizers
        assert run_recognizers("bank account 0123456789", default_recognizers) == []
