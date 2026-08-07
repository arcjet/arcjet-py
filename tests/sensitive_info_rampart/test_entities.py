"""Tests for label normalization and entity conversion.

Ported from arcjet-js/sensitive-info-rampart/test/index.test.ts (entity parts).
"""

from __future__ import annotations

from arcjet_sensitive_info_rampart._entities import (
    from_analyze_entity,
    normalize_label,
    rampart_entities,
    to_analyze_entity,
)

from arcjet._analyze import (
    SensitiveInfoEntityCreditCardNumber,
    SensitiveInfoEntityCustom,
    SensitiveInfoEntityEmail,
    SensitiveInfoEntityIpAddress,
    SensitiveInfoEntityPhoneNumber,
)


class TestNormalizeLabel:
    def test_strips_bio_prefix(self):
        assert normalize_label("B-GIVEN_NAME") == "GIVEN_NAME"
        assert normalize_label("I-SURNAME") == "SURNAME"

    def test_lowercase_input(self):
        assert normalize_label("b-phone") == "PHONE_NUMBER"

    def test_aliases_model_names(self):
        assert normalize_label("PHONE") == "PHONE_NUMBER"
        assert normalize_label("CREDIT_CARD") == "CREDIT_CARD_NUMBER"
        assert normalize_label("ZIP") == "ZIP_CODE"
        assert normalize_label("POSTAL_CODE") == "ZIP_CODE"

    def test_outside_label_is_none(self):
        assert normalize_label("O") is None

    def test_unknown_label_is_none(self):
        assert normalize_label("B-NONSENSE") is None

    def test_empty_after_strip_is_none(self):
        assert normalize_label("B-") is None


class TestToAnalyzeEntity:
    def test_native_types(self):
        assert isinstance(to_analyze_entity("EMAIL"), SensitiveInfoEntityEmail)
        assert isinstance(
            to_analyze_entity("PHONE_NUMBER"), SensitiveInfoEntityPhoneNumber
        )
        assert isinstance(to_analyze_entity("IP_ADDRESS"), SensitiveInfoEntityIpAddress)
        assert isinstance(
            to_analyze_entity("CREDIT_CARD_NUMBER"),
            SensitiveInfoEntityCreditCardNumber,
        )

    def test_backend_only_type_is_custom(self):
        entity = to_analyze_entity("GIVEN_NAME")
        assert isinstance(entity, SensitiveInfoEntityCustom)
        assert entity.value == "GIVEN_NAME"


class TestFromAnalyzeEntity:
    def test_native_types(self):
        assert from_analyze_entity(SensitiveInfoEntityEmail()) == "EMAIL"
        assert from_analyze_entity(SensitiveInfoEntityPhoneNumber()) == "PHONE_NUMBER"
        assert from_analyze_entity(SensitiveInfoEntityIpAddress()) == "IP_ADDRESS"
        assert (
            from_analyze_entity(SensitiveInfoEntityCreditCardNumber())
            == "CREDIT_CARD_NUMBER"
        )

    def test_custom_type(self):
        assert from_analyze_entity(SensitiveInfoEntityCustom(value="SURNAME")) == (
            "SURNAME"
        )

    def test_round_trip(self):
        for t in rampart_entities:
            assert from_analyze_entity(to_analyze_entity(t)) == t


class TestRampartEntities:
    def test_has_twenty_types(self):
        assert len(rampart_entities) == 20

    def test_includes_native_and_backend_only(self):
        assert "EMAIL" in rampart_entities
        assert "GIVEN_NAME" in rampart_entities
        assert "ZIP_CODE" in rampart_entities
