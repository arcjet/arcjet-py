"""Tests for nested-JSON metadata encoding (``arcjet._metadata``)."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Mapping

from arcjet._metadata import (
    MAX_METADATA_BYTES,
    METADATA_ENCODE_FAILED_CODE,
    LocalWarning,
    encode_metadata,
    enforce_metadata_budget,
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

    def test_many_dropped_keys_produce_a_single_warning(self) -> None:
        # One encode call must never flood the warning channel, which the
        # server bounds and persists.
        encoded, warnings = encode_metadata({f"k{i}": object() for i in range(15)})  # type: ignore[misc]
        assert encoded == {}
        assert len(warnings) == 1
        assert "15 key(s)" in warnings[0].message
        # Only the first few names are listed, then the list is elided.
        assert warnings[0].message.endswith('"k9", ...')

    def test_dropped_key_names_are_escaped(self) -> None:
        # Keys are user-controlled and warnings reach logs and server storage, so
        # a newline must not be able to forge a log entry.
        _, warnings = encode_metadata({"ev\nil INFO forged": object()})  # type: ignore[misc]
        assert "\n" not in warnings[0].message
        assert "ev\\x0ail INFO forged" in warnings[0].message

    def test_quotes_and_backslashes_cannot_forge_extra_keys(self) -> None:
        # The key list wraps each name in double quotes, so a key containing one
        # could otherwise look like several keys.
        forging = 'ev"il", "other'
        _, warnings = encode_metadata({forging: object()})  # type: ignore[misc]
        assert "1 key(s)" in warnings[0].message
        # Only the two quotes the formatter itself added remain.
        assert warnings[0].message.count('"') == 2
        assert "ev\\x22il\\x22, \\x22other" in warnings[0].message

        _, warnings = encode_metadata({"back\\slash": object()})  # type: ignore[misc]
        assert "back\\x5cslash" in warnings[0].message

    def test_separators_and_c1_controls_are_escaped_but_not_plain_non_ascii(
        self,
    ) -> None:
        # Same escape set and format as arcjet-js, so both SDKs render the same
        # warning for the same key.
        _, warnings = encode_metadata({"a\u2028b\u0085c\u00fcd": object()})  # type: ignore[misc]
        assert '"a\\u2028b\\x85c\u00fcd"' in warnings[0].message

    def test_unreadable_mapping_is_ignored(self) -> None:
        # A custom Mapping whose iteration raises costs the metadata, not the
        # call — matching the Object.entries() guard in arcjet-js.
        class Hostile(Mapping[str, object]):
            def __iter__(self):
                raise RuntimeError("nope")

            def __len__(self) -> int:
                return 1

            def __getitem__(self, key: str) -> object:
                raise RuntimeError("nope")

        assert encode_metadata(Hostile()) == ({}, [])  # type: ignore[arg-type]

    def test_long_dropped_key_names_are_truncated(self) -> None:
        _, warnings = encode_metadata({"x" * 200: object()})  # type: ignore[misc]
        assert len(warnings[0].message) < 160

    def test_non_mapping_metadata_is_ignored(self) -> None:
        # A wrong type costs the metadata, never the call.
        assert encode_metadata(["not", "a", "mapping"]) == ({}, [])  # type: ignore[arg-type]

    def test_non_finite_numbers_are_dropped_nested_or_not(self) -> None:
        # NaN/Infinity are not valid JSON, so they must not reach the server.
        # arcjet-js drops them too, via a JSON.stringify replacer.
        encoded, warnings = encode_metadata(
            {"nan": float("nan"), "deep": {"inner": float("inf")}, "ok": 1}
        )
        assert encoded == {"ok": "1"}
        assert [w.code for w in warnings] == [METADATA_ENCODE_FAILED_CODE]
        assert "2 key(s)" in warnings[0].message

    def test_lone_surrogates_are_dropped_nested_or_in_a_key(self) -> None:
        # Not encodable as UTF-8; protobuf raises on them and would take the whole
        # request down. arcjet-js drops them too, via its stringify replacer.
        for value in (
            {"bad": "\ud800", "ok": 1},
            {"bad": {"nested": "\udfff"}, "ok": 1},
            {"\ud800key": 1, "ok": 1},
        ):
            encoded, warnings = encode_metadata(value)
            assert encoded == {"ok": "1"}
            assert len(warnings) == 1
        # A valid astral character is fine.
        assert encode_metadata({"emoji": "\U0001f600"})[0] == {"emoji": '"\U0001f600"'}

    def test_encoded_values_are_always_utf8_encodable(self) -> None:
        # The guarantee that matters: whatever survives can go on the wire.
        encoded, _ = encode_metadata({"a": "\ud800", "b": "ok", "c": {"d": "\udc00"}})
        for key, value in encoded.items():
            key.encode("utf-8")
            value.encode("utf-8")

    def test_hostile_truthiness_is_ignored(self) -> None:
        class Hostile:
            def __bool__(self) -> bool:
                raise RuntimeError("nope")

        assert encode_metadata(Hostile()) == ({}, [])  # type: ignore[arg-type]

    def test_hostile_key_str_is_ignored(self) -> None:
        class BadKey:
            def __str__(self) -> str:
                raise RuntimeError("nope")

            def __hash__(self) -> int:
                return 1

        encoded, warnings = encode_metadata({BadKey(): 1})  # type: ignore[dict-item]
        assert encoded == {}
        assert "unprintable" in warnings[0].message

    def test_truncation_never_splits_a_character(self) -> None:
        _, warnings = encode_metadata({"a" * 63 + "\U0001f600": object()})  # type: ignore[misc]
        warnings[0].message.encode("utf-8")

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
        assert '"1"' in warnings[0].message

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
        assert warnings[0].message.startswith("rules[2].metadata:")

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


class TestEnforceMetadataBudget:
    def test_does_not_trim_what_fits(self) -> None:
        m = {"a": '"x"', "b": '"y"'}
        assert enforce_metadata_budget([m]) == []
        assert m == {"a": '"x"', "b": '"y"'}

    def test_sits_above_what_the_server_would_accept(self) -> None:
        # The SDK ceiling is a protocol backstop, not a copy of server policy: the
        # server can accept ~512 KiB in one map, so the SDK must not trim that.
        assert MAX_METADATA_BYTES > 128 * 4096
        assert MAX_METADATA_BYTES < 1024 * 1024

    def test_trims_across_every_map_in_order_with_one_warning(self) -> None:
        envelope = {"big": "x" * 500_000, "keep": "1"}
        rule = {"also_big": "y" * 500_000, "tail": "2"}
        warnings = enforce_metadata_budget([envelope, rule])

        # The envelope is served first; the rule map is starved.
        assert list(envelope) == ["big", "keep"]
        assert list(rule) == []
        assert len(warnings) == 1
        assert "2 key(s)" in warnings[0].message
        assert "request metadata budget" in warnings[0].message
        assert warnings[0].code == METADATA_ENCODE_FAILED_CODE

    def test_drops_a_single_value_larger_than_the_budget(self) -> None:
        m: dict[str, str] = {"huge": "x" * (MAX_METADATA_BYTES + 1)}
        warnings = enforce_metadata_budget([m])
        assert m == {}
        assert len(warnings) == 1
