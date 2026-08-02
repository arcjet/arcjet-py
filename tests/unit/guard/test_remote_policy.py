from __future__ import annotations

import asyncio

import pytest

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
    now += 10_000
    assert runtime.prepare("test", inputs).revision == "two"
    assert fetches == 3


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


def test_async_not_configured_clears_projection() -> None:
    asyncio.run(_test_async_not_configured_clears_projection())


async def _test_async_not_configured_clears_projection() -> None:
    responses = iter(
        (
            _available("one"),
            pb.GetGuardPolicyResponse(
                status=pb.GUARD_POLICY_LOOKUP_STATUS_NOT_CONFIGURED
            ),
        )
    )

    async def fetch(_label: str) -> pb.GetGuardPolicyResponse:
        return next(responses)

    runtime = remote_policy.AsyncRemotePolicyRuntime(fetch)
    inputs = {"value": local_input.string("secret")}
    assert (await runtime.prepare("test", inputs)).revision == "one"
    assert (await runtime.prepare("test", inputs, force=True)).revision == ""
