"""Tests for nested-JSON metadata encoding (``arcjet._metadata``)."""

from __future__ import annotations

import json
from datetime import datetime

from arcjet._metadata import (
    METADATA_ENCODE_FAILED_CODE,
    LocalWarning,
    encode_metadata,
)


class TestEncodeMetadata:
    def test_none_and_empty(self) -> None:
        assert encode_metadata(None) == ({}, [])
        assert encode_metadata({}) == ({}, [])

    def test_strings_are_json_encoded(self) -> None:
        encoded, warnings = encode_metadata({"env": "staging"})
        # Values are JSON, so a string arrives quoted — this is what makes
        # `metadata['env'] = '"staging"'` the ClickHouse query form.
        assert encoded == {"env": '"staging"'}
        assert warnings == []

    def test_scalar_types_keep_their_json_type(self) -> None:
        encoded, warnings = encode_metadata(
            {
                "duration_ms": 160,
                "score": 0.5,
                "success": True,
                "missing": None,
            }
        )
        assert encoded == {
            "duration_ms": "160",
            "score": "0.5",
            "success": "true",
            "missing": "null",
        }
        assert warnings == []

    def test_nested_values_are_encoded_per_top_level_key(self) -> None:
        encoded, warnings = encode_metadata(
            {
                "user": {"id": "u_1", "roles": ["admin", "ops"]},
                "tool_name": "Bash",
            }
        )
        assert warnings == []
        assert set(encoded) == {"user", "tool_name"}
        assert json.loads(encoded["user"]) == {
            "id": "u_1",
            "roles": ["admin", "ops"],
        }

    def test_large_integers_survive_exactly(self) -> None:
        # The wire format is a verbatim JSON string, so Python's arbitrary
        # precision ints are not coerced to float64 by the SDK.
        big = 2**63 - 1
        encoded, warnings = encode_metadata({"cursor": big})
        assert encoded == {"cursor": str(big)}
        assert warnings == []

    def test_tuples_encode_as_arrays(self) -> None:
        encoded, _ = encode_metadata({"tags": ("a", "b")})
        assert json.loads(encoded["tags"]) == ["a", "b"]

    def test_unicode_is_not_escaped(self) -> None:
        encoded, _ = encode_metadata({"city": "Zürich"})
        assert encoded == {"city": '"Zürich"'}

    def test_compact_separators(self) -> None:
        encoded, _ = encode_metadata({"a": {"b": 1, "c": 2}})
        assert encoded["a"] == '{"b":1,"c":2}'

    def test_unencodable_value_is_dropped_with_a_warning(self) -> None:
        encoded, warnings = encode_metadata(
            {"when": datetime(2026, 7, 24), "ok": "yes"}  # type: ignore[invalid-argument-type]
        )
        # The good key survives; only the bad one is dropped.
        assert encoded == {"ok": '"yes"'}
        assert len(warnings) == 1
        assert warnings[0].code == METADATA_ENCODE_FAILED_CODE
        assert '"when"' in warnings[0].message
        assert "dropped" in warnings[0].message

    def test_nan_and_infinity_are_dropped(self) -> None:
        # NaN/Infinity are not valid JSON, so they must not reach the server.
        encoded, warnings = encode_metadata({"nan": float("nan"), "inf": float("inf")})
        assert encoded == {}
        assert [w.code for w in warnings] == [METADATA_ENCODE_FAILED_CODE] * 2

    def test_circular_reference_is_dropped(self) -> None:
        cycle: dict[str, object] = {}
        cycle["self"] = cycle
        encoded, warnings = encode_metadata({"loop": cycle})
        assert encoded == {}
        assert len(warnings) == 1
        assert warnings[0].code == METADATA_ENCODE_FAILED_CODE

    def test_non_string_key_is_dropped(self) -> None:
        encoded, warnings = encode_metadata({1: "one", "ok": "yes"})  # type: ignore[dict-item]
        assert encoded == {"ok": '"yes"'}
        assert len(warnings) == 1
        assert warnings[0].code == METADATA_ENCODE_FAILED_CODE
        assert "int" in warnings[0].message

    def test_warning_message_never_contains_the_value(self) -> None:
        # Warnings are persisted server-side and are a potential PII sink, so
        # they must reference only the key name.
        encoded, warnings = encode_metadata(
            {"secret": {"token"}}  # type: ignore[invalid-argument-type]
        )
        assert encoded == {}
        assert "token" not in warnings[0].message

    def test_message_prefix_identifies_the_source(self) -> None:
        _, warnings = encode_metadata(
            {"bad": {"set"}},  # type: ignore[invalid-argument-type]
            message_prefix="rules[2].",
        )
        assert warnings[0].message.startswith("rules[2].metadata value")

    def test_insertion_order_is_preserved(self) -> None:
        # The server keeps the first 128 keys, so ordering is the SDK's only
        # influence over which keys survive an over-count blob.
        encoded, _ = encode_metadata({f"k{i}": i for i in range(200)})
        assert list(encoded)[:3] == ["k0", "k1", "k2"]
        assert len(encoded) == 200

    def test_over_limit_values_are_left_to_the_server(self) -> None:
        # Size/depth/count caps are server-enforced (and per-account
        # configurable), so the SDK must not silently pre-truncate.
        deep: dict[str, object] = {"leaf": 1}
        for _ in range(30):
            deep = {"nested": deep}
        encoded, warnings = encode_metadata({"deep": deep, "big": "x" * 8192})
        assert set(encoded) == {"deep", "big"}
        assert warnings == []


class TestLocalWarning:
    def test_is_immutable(self) -> None:
        w = LocalWarning(code="AJ1017", message="dropped")
        assert (w.code, w.message) == ("AJ1017", "dropped")
