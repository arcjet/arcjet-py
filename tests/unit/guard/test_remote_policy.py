from __future__ import annotations

import asyncio
from typing import cast

import pytest

from arcjet._analyze import (
    DetectedSensitiveInfoEntity,
    SensitiveInfoEntities,
    SensitiveInfoEntityEmail,
    SensitiveInfoResult,
)
from arcjet._sensitive_info_backend import (
    SensitiveInfoBackend,
    SensitiveInfoBackendContext,
    SensitiveInfoBackendOptions,
)
from arcjet.guard import _remote_policy as remote_policy
from arcjet.guard import local_input
from arcjet.guard.proto.decide.v2 import decide_pb2 as pb


def _available(revision: str) -> pb.GetGuardPolicyResponse:
    return pb.GetGuardPolicyResponse(
        status=pb.GUARD_POLICY_LOOKUP_STATUS_AVAILABLE,
        policy=pb.GuardLocalPolicyProjection(
            policy_id="policy-1", revision=revision, label="test"
        ),
    )


def test_local_sensitive_info_result_reports_denied_findings_only() -> None:
    finding = DetectedSensitiveInfoEntity(
        start=0, end=19, identified_type=SensitiveInfoEntityEmail()
    )

    class Backend:
        def detect(
            self,
            _context: SensitiveInfoBackendContext,
            _value: str,
            _entities: SensitiveInfoEntities,
            _options: SensitiveInfoBackendOptions | None = None,
        ) -> SensitiveInfoResult:
            if _value.startswith("allowed"):
                return SensitiveInfoResult(allowed=[finding], denied=[])
            return SensitiveInfoResult(allowed=[], denied=[finding])

    response = _available("one")
    response.policy.sensitive_info_rules.add(
        rule_id="rule-1",
        input_name="value",
        entities_allow=pb.EntityList(entities=["EMAIL"]),
    )
    runtime = remote_policy.SyncRemotePolicyRuntime(
        lambda _label: response,
        sensitive_info_backend=cast(SensitiveInfoBackend, Backend()),
    )

    prepared = runtime.prepare(
        "test", {"value": local_input.string("allowed@example.com")}
    )

    assert len(prepared.results) == 1
    sensitive_info = prepared.results[0].local_sensitive_info
    assert sensitive_info.conclusion == pb.GUARD_CONCLUSION_ALLOW
    assert not sensitive_info.detected
    assert list(sensitive_info.detected_entity_types) == []
    assert list(sensitive_info.detected_entities) == []

    denied = (
        runtime.prepare("test", {"value": local_input.string("denied@example.com")})
        .results[0]
        .local_sensitive_info
    )
    assert denied.conclusion == pb.GUARD_CONCLUSION_DENY
    assert denied.detected
    assert list(denied.detected_entity_types) == ["EMAIL"]
    assert [
        (entity.type, entity.start, entity.end) for entity in denied.detected_entities
    ] == [("EMAIL", 0, 19)]


def test_sync_projection_refreshes_every_five_minutes_and_survives_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = 10.0
    responses = iter((_available("one"), None, _available("two")))
    fetches = 0

    def fetch(_label: str) -> pb.GetGuardPolicyResponse | None:
        nonlocal fetches
        fetches += 1
        return next(responses)

    monkeypatch.setattr(remote_policy.time, "monotonic", lambda: now)
    runtime = remote_policy.SyncRemotePolicyRuntime(fetch)
    inputs = {"value": local_input.string("secret")}

    assert runtime.prepare("test", inputs).revision == "one"
    now += 299
    assert runtime.prepare("test", inputs).revision == "one"
    assert fetches == 1
    now += 1
    assert runtime.prepare("test", inputs).revision == "one"
    now += 299
    assert runtime.prepare("test", inputs).revision == "one"
    assert fetches == 2
    now += 1
    assert runtime.prepare("test", inputs).revision == "two"
    assert fetches == 3


def test_sync_not_configured_is_cached_and_refreshed_after_five_minutes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = 10.0
    fetches = 0

    def fetch(_label: str) -> pb.GetGuardPolicyResponse:
        nonlocal fetches
        fetches += 1
        if fetches == 1:
            return pb.GetGuardPolicyResponse(
                status=pb.GUARD_POLICY_LOOKUP_STATUS_NOT_CONFIGURED
            )
        return _available("added")

    monkeypatch.setattr(remote_policy.time, "monotonic", lambda: now)
    runtime = remote_policy.SyncRemotePolicyRuntime(fetch)
    inputs = {"value": local_input.string("secret")}

    assert runtime.prepare("test", inputs).revision == ""
    now += 299
    assert runtime.prepare("test", inputs).revision == ""
    assert fetches == 1
    now += 1
    assert runtime.prepare("test", inputs).revision == "added"
    assert fetches == 2


def test_sync_initial_error_uses_short_backoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = 10.0
    fetches = 0

    def fetch(_label: str) -> pb.GetGuardPolicyResponse | None:
        nonlocal fetches
        fetches += 1
        return None if fetches == 1 else _available("recovered")

    monkeypatch.setattr(remote_policy.time, "monotonic", lambda: now)
    runtime = remote_policy.SyncRemotePolicyRuntime(fetch)
    inputs = {"value": local_input.string("secret")}

    assert runtime.prepare("test", inputs).revision == ""
    now += 4
    assert runtime.prepare("test", inputs).revision == ""
    assert fetches == 1
    now += 1
    assert runtime.prepare("test", inputs).revision == "recovered"


def test_sync_not_configured_clears_projection_and_force_refreshes() -> None:
    responses = iter(
        (
            _available("one"),
            pb.GetGuardPolicyResponse(
                status=pb.GUARD_POLICY_LOOKUP_STATUS_NOT_CONFIGURED
            ),
            None,
        )
    )
    runtime = remote_policy.SyncRemotePolicyRuntime(lambda _label: next(responses))
    inputs = {"value": local_input.string("secret")}

    assert runtime.prepare("test", inputs).revision == "one"
    assert runtime.prepare("test", inputs, force=True).revision == ""
    assert runtime.prepare("test", inputs, force=True).revision == ""


def test_async_force_refresh_deduplicates_and_keeps_stale_projection() -> None:
    asyncio.run(_test_async_force_refresh_deduplicates_and_keeps_stale_projection())


async def _test_async_force_refresh_deduplicates_and_keeps_stale_projection() -> None:
    calls = 0
    started = asyncio.Event()
    release = asyncio.Event()

    async def fetch(_label: str) -> pb.GetGuardPolicyResponse | None:
        nonlocal calls
        calls += 1
        if calls == 1:
            return _available("one")
        started.set()
        await release.wait()
        return None

    runtime = remote_policy.AsyncRemotePolicyRuntime(fetch)
    inputs = {"value": local_input.string("secret")}
    assert (await runtime.prepare("test", inputs)).revision == "one"

    first = asyncio.create_task(runtime.prepare("test", inputs, force=True))
    second = asyncio.create_task(runtime.prepare("test", inputs, force=True))
    await started.wait()
    assert calls == 2
    release.set()
    assert (await first).revision == "one"
    assert (await second).revision == "one"


def test_async_not_configured_clears_and_caches_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asyncio.run(_test_async_not_configured_clears_and_caches_projection(monkeypatch))


async def _test_async_not_configured_clears_and_caches_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = 10.0
    calls = 0
    responses = iter(
        (
            _available("one"),
            pb.GetGuardPolicyResponse(
                status=pb.GUARD_POLICY_LOOKUP_STATUS_NOT_CONFIGURED
            ),
            _available("two"),
        )
    )

    async def fetch(_label: str) -> pb.GetGuardPolicyResponse:
        nonlocal calls
        calls += 1
        return next(responses)

    monkeypatch.setattr(remote_policy.time, "monotonic", lambda: now)
    runtime = remote_policy.AsyncRemotePolicyRuntime(fetch)
    inputs = {"value": local_input.string("secret")}
    assert (await runtime.prepare("test", inputs)).revision == "one"
    assert (await runtime.prepare("test", inputs, force=True)).revision == ""
    now += 299
    assert (await runtime.prepare("test", inputs)).revision == ""
    assert calls == 2
    now += 1
    assert (await runtime.prepare("test", inputs)).revision == "two"
    assert calls == 3


def test_async_cancelled_waiter_does_not_cancel_shared_refresh() -> None:
    asyncio.run(_test_async_cancelled_waiter_does_not_cancel_shared_refresh())


async def _test_async_cancelled_waiter_does_not_cancel_shared_refresh() -> None:
    calls = 0
    started = asyncio.Event()
    release = asyncio.Event()

    async def fetch(_label: str) -> pb.GetGuardPolicyResponse:
        nonlocal calls
        calls += 1
        if calls == 1:
            return _available("one")
        started.set()
        await release.wait()
        return pb.GetGuardPolicyResponse(
            status=pb.GUARD_POLICY_LOOKUP_STATUS_NOT_CONFIGURED
        )

    runtime = remote_policy.AsyncRemotePolicyRuntime(fetch)
    inputs = {"value": local_input.string("secret")}
    assert (await runtime.prepare("test", inputs)).revision == "one"

    cancelled = asyncio.create_task(runtime.prepare("test", inputs, force=True))
    surviving = asyncio.create_task(runtime.prepare("test", inputs, force=True))
    await started.wait()
    cancelled.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cancelled
    release.set()

    assert (await surviving).revision == ""
    assert (await runtime.prepare("test", inputs)).revision == ""
    assert calls == 2
