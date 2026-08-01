from __future__ import annotations

import time
from typing import Any

from arcjet.guard import ArcjetGuardSync, local_input, server_input
from arcjet.guard._remote_policy import SyncRemotePolicyRuntime, local_string_digest
from arcjet.guard.proto.decide.v2 import decide_pb2 as pb


def test_local_digest_matches_pinned_wire_encoding() -> None:
    assert (
        local_string_digest("hello").hex()
        == "344c730291b0156792dbdd8e4528370616e70ba828e9f4c614491b46cbcd4f8a"
    )


def test_local_input_uses_projection_cache_and_never_sends_raw_value() -> None:
    fetches = 0
    now = int(time.time() * 1000)

    def fetch(_label: str) -> pb.GetGuardPolicyResponse:
        nonlocal fetches
        fetches += 1
        return pb.GetGuardPolicyResponse(
            status=pb.GUARD_POLICY_LOOKUP_STATUS_AVAILABLE,
            server_time_unix_ms=now,
            policy=pb.GuardLocalPolicyProjection(
                policy_id="policy-1",
                revision="revision-1",
                label="email.sent",
                refresh_after_unix_ms=now + 60_000,
                valid_until_unix_ms=now + 120_000,
            ),
        )

    runtime = SyncRemotePolicyRuntime(fetch)
    first = runtime.prepare(
        "email.sent", {"subject": local_input.string("private subject")}
    )
    second = runtime.prepare(
        "email.sent", {"subject": local_input.string("private subject")}
    )

    assert fetches == 1
    assert first.revision == second.revision == "revision-1"
    assert first.inputs["subject"].WhichOneof("representation") == "local"
    assert len(first.inputs["subject"].local.value_sha256) == 32
    assert b"private subject" not in first.inputs["subject"].SerializeToString()


class _Transport:
    def __init__(self) -> None:
        self.request: pb.GuardRequest | None = None

    def guard(self, request: pb.GuardRequest, **_kwargs: Any) -> pb.GuardResponse:
        self.request = request
        return pb.GuardResponse(
            decision=pb.GuardDecision(
                id="gdec_test", conclusion=pb.GUARD_CONCLUSION_ALLOW
            )
        )

    def capture(
        self, _request: pb.CaptureRequest, **_kwargs: Any
    ) -> pb.CaptureResponse:
        return pb.CaptureResponse()


def test_direct_guard_sends_actor_and_typed_server_inputs_without_policy_fetch() -> (
    None
):
    transport = _Transport()
    guard = ArcjetGuardSync("key", transport, 1000, "test-agent")  # type: ignore[arg-type]

    decision = guard.guard(
        label="email.sent",
        actor="user-1",
        inputs={
            "recipient": server_input.string("person@example.com"),
            "attempts": server_input.integer(2),
        },
    )

    assert decision.id == "gdec_test"
    assert transport.request is not None
    assert transport.request.actor == "user-1"
    assert (
        transport.request.policy_inputs["recipient"].server.string_value
        == "person@example.com"
    )
    assert transport.request.policy_inputs["attempts"].server.integer_value == 2
