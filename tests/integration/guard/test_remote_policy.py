from __future__ import annotations

from typing import Any

from arcjet.guard import ArcjetGuardSync, local_input, server_input
from arcjet.guard._convert import decision_from_proto
from arcjet.guard._remote_policy import SyncRemotePolicyRuntime, local_string_digest
from arcjet.guard.proto.decide.v2 import decide_pb2 as pb


def test_local_digest_matches_pinned_wire_encoding() -> None:
    assert (
        local_string_digest("hello").hex()
        == "344c730291b0156792dbdd8e4528370616e70ba828e9f4c614491b46cbcd4f8a"
    )


def test_local_input_uses_projection_cache_and_never_sends_raw_value() -> None:
    fetches = 0

    def fetch(_label: str) -> pb.GetGuardPolicyResponse:
        nonlocal fetches
        fetches += 1
        return pb.GetGuardPolicyResponse(
            status=pb.GUARD_POLICY_LOOKUP_STATUS_AVAILABLE,
            policy=pb.GuardLocalPolicyProjection(
                policy_id="policy-1",
                revision="revision-1",
                label="email.sent",
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


def test_remote_results_are_keyed_separately_from_sdk_results() -> None:
    decision = decision_from_proto(
        pb.GuardResponse(
            decision=pb.GuardDecision(
                id="gdec_policy",
                conclusion=pb.GUARD_CONCLUSION_DENY,
                policy_evaluation=pb.GuardPolicyEvaluation(
                    revision="revision-1", status=pb.GUARD_POLICY_STATUS_APPLIED
                ),
                policy_rule_results=[
                    pb.GuardPolicyRuleResult(
                        policy_id="policy-1",
                        policy_revision="revision-1",
                        rule_id="allowed-recipient",
                        mode=pb.GUARD_RULE_MODE_LIVE,
                        execution=pb.GUARD_RULE_EXECUTION_SERVER,
                        source=pb.GUARD_RULE_SOURCE_REMOTE,
                        allowed_string_values=pb.ResultStringConstraint(
                            conclusion=pb.GUARD_CONCLUSION_DENY
                        ),
                    )
                ],
            )
        )
    )

    assert decision.results == ()
    assert decision.policy_evaluation is not None
    assert decision.policy_evaluation.status == "APPLIED"
    assert decision.policy_results[0].rule_id == "allowed-recipient"
    assert decision.policy_results[0].result.reason == "INPUT_CONSTRAINT"
