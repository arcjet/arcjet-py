"""Tests for ``protect(metadata=...)`` on both the async and sync clients.

Uses the stubbed protobuf modules (``mock_protobuf_modules``) and captures the
``DecideRequest`` the client builds via ``decide_behavior``.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest

_SCOPE = {"headers": [], "type": "http"}


def _capture(monkeypatch: pytest.MonkeyPatch, *, sync: bool) -> list[Any]:
    """Capture every DecideRequest the client sends."""
    from arcjet.proto.decide.v1alpha1.decide_connect import (
        DecideServiceClient,
        DecideServiceClientSync,
    )

    captured: list[Any] = []
    client = DecideServiceClientSync if sync else DecideServiceClient

    def behavior(request: Any):
        captured.append(request)
        from fixtures.protobuf_stubs import (
            CONCLUSION_ALLOW,
            StubDecideResponse,
            StubDecision,
        )

        return StubDecideResponse(
            StubDecision(id="test_decision", conclusion=CONCLUSION_ALLOW, ttl=0)
        )

    monkeypatch.setattr(client, "decide_behavior", behavior, raising=False)
    return captured


def test_metadata_is_json_encoded_on_decide_request(
    mock_protobuf_modules, monkeypatch: pytest.MonkeyPatch
):
    from arcjet import arcjet

    captured = _capture(monkeypatch, sync=False)
    aj = arcjet(key="ajkey_x", rules=[])
    asyncio.run(
        aj.protect(
            _SCOPE,
            metadata={
                "requestId": "req_1",
                "flags": {"beta": True},
                "duration_ms": 160,
            },
        )
    )

    assert len(captured) == 1
    assert captured[0].metadata_json == {
        "requestId": '"req_1"',
        "flags": '{"beta":true}',
        "duration_ms": "160",
    }
    assert captured[0].local_warnings == []


def test_metadata_is_json_encoded_on_decide_request_sync(
    mock_protobuf_modules, monkeypatch: pytest.MonkeyPatch
):
    from arcjet import arcjet_sync

    captured = _capture(monkeypatch, sync=True)
    aj = arcjet_sync(key="ajkey_x", rules=[])
    aj.protect(_SCOPE, metadata={"user": {"id": "u_1"}})

    assert len(captured) == 1
    assert captured[0].metadata_json == {"user": '{"id":"u_1"}'}


def test_no_metadata_sends_an_empty_map(
    mock_protobuf_modules, monkeypatch: pytest.MonkeyPatch
):
    from arcjet import arcjet

    captured = _capture(monkeypatch, sync=False)
    aj = arcjet(key="ajkey_x", rules=[])
    asyncio.run(aj.protect(_SCOPE))

    assert captured[0].metadata_json == {}
    assert captured[0].local_warnings == []


def test_metadata_is_kept_out_of_extra(
    mock_protobuf_modules, monkeypatch: pytest.MonkeyPatch
):
    # `extra` is SDK-derived request context and stays a flat string map;
    # metadata must not leak into it.
    from arcjet import arcjet

    captured = _capture(monkeypatch, sync=False)
    aj = arcjet(key="ajkey_x", rules=[])
    asyncio.run(aj.protect(_SCOPE, extra={"a": "b"}, metadata={"c": {"d": 1}}))

    details = captured[0].details
    assert dict(details.extra) == {"a": "b"}
    assert captured[0].metadata_json == {"c": '{"d":1}'}


def test_unencodable_metadata_is_dropped_and_reported(
    mock_protobuf_modules,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    from arcjet import arcjet

    captured = _capture(monkeypatch, sync=False)
    aj = arcjet(key="ajkey_x", rules=[])
    with caplog.at_level(logging.WARNING, logger="arcjet"):
        decision = asyncio.run(
            aj.protect(
                _SCOPE,
                metadata={"ok": "yes", "bad": object()},  # type: ignore[invalid-argument-type]
            )
        )

    # Fails open: the bad key costs you the key, not the call.
    assert not decision.is_denied()
    assert captured[0].metadata_json == {"ok": '"yes"'}
    # Reported to the server as an untrusted client-side warning...
    assert [w.code for w in captured[0].local_warnings] == ["AJ1017"]
    assert '"bad"' in captured[0].local_warnings[0].message
    # ...and locally, since protect()'s Decision has no warnings channel.
    assert "1 key(s) dropped" in caplog.text


def test_metadata_is_not_part_of_the_cache_key(
    mock_protobuf_modules, monkeypatch: pytest.MonkeyPatch
):
    # Metadata never affects a decision, so two calls that differ only in
    # metadata must still share a cached DENY.
    from fixtures.protobuf_stubs import (
        CONCLUSION_DENY,
        StubDecideResponse,
        StubDecision,
    )

    from arcjet import arcjet_sync
    from arcjet._rules import token_bucket
    from arcjet.proto.decide.v1alpha1.decide_connect import DecideServiceClientSync

    calls: list[Any] = []

    def behavior(request: Any):
        calls.append(request)
        return StubDecideResponse(
            StubDecision(id="d1", conclusion=CONCLUSION_DENY, ttl=60)
        )

    monkeypatch.setattr(
        DecideServiceClientSync, "decide_behavior", behavior, raising=False
    )
    aj = arcjet_sync(
        key="ajkey_x", rules=[token_bucket(refill_rate=1, interval=1, capacity=1)]
    )
    # The cache key falls back to the client IP, so the scope needs one.
    scope = {**_SCOPE, "client": ("1.2.3.4", 1234)}
    first = aj.protect(scope, metadata={"attempt": 1})
    second = aj.protect(scope, metadata={"attempt": 2})

    assert first.is_denied()
    assert second.is_denied()
    # Second call was served from cache — only one Decide round trip.
    assert len(calls) == 1
