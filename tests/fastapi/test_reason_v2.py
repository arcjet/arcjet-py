from collections.abc import Mapping, Sequence

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from fastapi.testclient import TestClient
from pyqwest import Headers

from arcjet import Arcjet, RuleSpec, shield
from arcjet import arcjet as arcjet_fastapi
from arcjet.proto.decide.v1alpha1 import decide_pb2


# TODO: Remove protobuf types from client and define a protocol.
class MockClient:
    """Mock DecideServiceClient for testing purposes."""

    _decision: decide_pb2.Decision | None = None

    def set_decicion(self, decision: decide_pb2.Decision | None) -> None:
        self._decision = decision

    async def decide(
        self,
        request: decide_pb2.DecideRequest,
        *,
        headers: Headers | Mapping[str, str] | None = None,
        timeout_ms: int | None = None,
    ) -> decide_pb2.DecideResponse:
        response = decide_pb2.DecideResponse(
            decision=self._decision,
        )
        return response

    async def report(
        self,
        request: decide_pb2.ReportRequest,
        *,
        headers: Headers | Mapping[str, str] | None = None,
        timeout_ms: int | None = None,
    ) -> decide_pb2.ReportResponse:
        return decide_pb2.ReportResponse()


def create_app() -> tuple[FastAPI, MockClient]:
    app = FastAPI()

    mock_client = MockClient()
    # rules: Sequence[RuleSpec] = [shield()]
    rules: Sequence[RuleSpec] = []

    # Use Arcjet class directly to inject a client.
    # TODO: Accept a remote_client parameter in `arcjet` / `arcjet_sync` factory functions.
    arcjet = Arcjet(
        # TODO: Change `_client` type to protocol to make it easier to do dependency injection.
        _client=mock_client,  # type: ignore - `DecideServiceClient` inherits from `ConnectClient`
        _fail_open=True,
        _has_token_bucket=False,
        _key="ajkey_dummy",
        _needs_email=False,
        _proxies=(),
        _rules=tuple(rules),
        _sdk_stack=None,
        _sdk_version="0.0.0",
        _timeout_ms=0,
    )

    @app.get("/shield")
    async def protected_route(request: Request):
        decision = await arcjet.protect(request)

        if decision.is_error():
            return PlainTextResponse(
                f'Internal Server Error: "${decision.reason}', status_code=500
            )
        if decision.is_allowed():
            return decision.reason_v2
        if decision.is_denied():
            return PlainTextResponse("Forbidden", status_code=403)

        pytest.fail("Unexpected decision state.")

    return app, mock_client


def test_basic_get_no_rules():
    app, mock_client = create_app()
    client = TestClient(app)

    mock_client.set_decicion(None)

    response = client.get("/shield")

    # With fail_open=True and a None decision, we get an ERROR decision
    assert response.status_code == 500, f"Unexpected status: {response.text}"
    # The error message is returned as plain text, not JSON
    assert "missing decision in response" in response.text


def test_basic_get_reason_v2():
    app, mock_client = create_app()
    client = TestClient(app)

    mock_client.set_decicion(
        decision=decide_pb2.Decision(
            id="decision_123",
            conclusion=decide_pb2.CONCLUSION_ALLOW,
            reason=decide_pb2.Reason(
                shield=decide_pb2.ShieldReason(
                    shield_triggered=False,
                ),
            ),
            rule_results=[
                decide_pb2.RuleResult(
                    rule_id="rule_shield",
                    conclusion=decide_pb2.CONCLUSION_ALLOW,
                    reason=decide_pb2.Reason(
                        shield=decide_pb2.ShieldReason(
                            shield_triggered=False,
                        ),
                    ),
                )
            ],
            ttl=900,
        )
    )

    response = client.get("/shield")

    assert response.status_code == 200, f"Unexpected status: {response.text}"
    assert response.json() == {
        "shield_triggered": False,
        "type": "SHIELD",
    }
