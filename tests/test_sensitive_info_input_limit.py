"""Input over a backend's declared ``max_input_chars`` is denied, never truncated.

A backend that scans only a prefix of its input would otherwise let content past
the limit through unscanned (a padding bypass). These tests pin that every SDK
path that calls ``backend.detect`` denies over-limit input without running the
backend: ``protect()`` on both clients, the Guard local sensitive info rule, and
the remote Guard policy LOCAL input path.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any, cast

import pytest

from arcjet._analyze import (
    DetectedSensitiveInfoEntity,
    SensitiveInfoEntities,
    SensitiveInfoEntityEmail,
    SensitiveInfoResult,
)
from arcjet._client import _run_local_rules
from arcjet._context import RequestContext
from arcjet._enums import Mode
from arcjet._local import evaluate_sensitive_info_locally
from arcjet._rules import detect_sensitive_info
from arcjet._sensitive_info_backend import (
    SensitiveInfoBackend,
    SensitiveInfoBackendContext,
    SensitiveInfoBackendOptions,
    backend_input_limit,
    oversize_input_message,
)
from arcjet.proto.decide.v1alpha1 import decide_pb2

LIMIT = 10
# Padding up to the limit, then personal data past it.
OVER = "x" * LIMIT + " alice@example.com"
AT_LIMIT = "y" * LIMIT
MESSAGE = (
    f"sensitive info input of {len(OVER)} characters exceeds the backend limit "
    f"of {LIMIT}"
)


class _RecordingBackend:
    """Backend that denies an email in any input and records each call."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def detect(
        self,
        context: SensitiveInfoBackendContext,
        value: str,
        entities: SensitiveInfoEntities,
        options: SensitiveInfoBackendOptions | None = None,
    ) -> SensitiveInfoResult:
        self.calls.append(value)
        return SensitiveInfoResult(
            allowed=[],
            denied=[
                DetectedSensitiveInfoEntity(
                    start=0, end=1, identified_type=SensitiveInfoEntityEmail()
                )
            ],
        )


class _LimitedBackend(_RecordingBackend):
    """Backend that declares ``max_input_chars`` as a plain attribute."""

    def __init__(self, limit: object = LIMIT) -> None:
        super().__init__()
        self.max_input_chars = limit


class _PropertyLimitedBackend(_RecordingBackend):
    """Backend that declares ``max_input_chars`` as a property."""

    @property
    def max_input_chars(self) -> int:
        return LIMIT


class _RaisingLimitBackend(_RecordingBackend):
    @property
    def max_input_chars(self) -> int:
        raise RuntimeError("broken property")


def _rule(backend: object, mode: Mode = Mode.LIVE):
    return detect_sensitive_info(
        mode=mode, deny=["EMAIL"], backend=cast(SensitiveInfoBackend, backend)
    )


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


class TestBackendInputLimit:
    def test_reads_attribute_and_property(self):
        assert backend_input_limit(_LimitedBackend()) == LIMIT
        assert backend_input_limit(_PropertyLimitedBackend()) == LIMIT

    def test_missing_attribute_is_no_limit(self):
        assert backend_input_limit(_RecordingBackend()) is None

    @pytest.mark.parametrize("value", [0, -1, True, False, "10", 10.0, None])
    def test_invalid_declared_limit_is_no_limit(self, value):
        assert backend_input_limit(_LimitedBackend(value)) is None

    def test_raising_property_is_no_limit(self):
        assert backend_input_limit(_RaisingLimitBackend()) is None

    def test_message_and_warning_never_include_text(self, caplog):
        with caplog.at_level(logging.WARNING, logger="arcjet"):
            message = oversize_input_message(_LimitedBackend(), OVER)
        assert message == MESSAGE
        assert message is not None and "alice" not in message
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1
        logged = warnings[0].getMessage()
        assert str(len(OVER)) in logged and str(LIMIT) in logged
        assert "alice" not in logged

    def test_at_limit_is_not_oversize(self):
        assert oversize_input_message(_LimitedBackend(), AT_LIMIT) is None

    def test_counts_code_points(self):
        # Ten multi-byte characters are ten characters, not 40 bytes.
        assert oversize_input_message(_LimitedBackend(), "\U0001f600" * LIMIT) is None


# ---------------------------------------------------------------------------
# protect(): evaluate_sensitive_info_locally
# ---------------------------------------------------------------------------


class TestEvaluateLocally:
    def test_over_limit_live_denies_without_detect(self, caplog):
        backend = _LimitedBackend()
        ctx = RequestContext(sensitive_info_value=OVER)
        with caplog.at_level(logging.WARNING, logger="arcjet"):
            result = evaluate_sensitive_info_locally(ctx, _rule(backend))

        assert backend.calls == []
        assert result is not None
        assert result.conclusion == decide_pb2.CONCLUSION_DENY
        assert result.state == decide_pb2.RULE_STATE_RUN
        assert result.reason.WhichOneof("reason") == "error"
        assert result.reason.error.message == MESSAGE
        assert "alice" not in str(result)
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1

    def test_over_limit_dry_run_is_dry_run_state(self):
        backend = _LimitedBackend()
        ctx = RequestContext(sensitive_info_value=OVER)
        result = evaluate_sensitive_info_locally(ctx, _rule(backend, Mode.DRY_RUN))

        assert backend.calls == []
        assert result is not None
        assert result.conclusion == decide_pb2.CONCLUSION_DENY
        assert result.state == decide_pb2.RULE_STATE_DRY_RUN
        assert result.reason.error.message == MESSAGE

    def test_property_limit_is_enforced(self):
        backend = _PropertyLimitedBackend()
        ctx = RequestContext(sensitive_info_value=OVER)
        result = evaluate_sensitive_info_locally(ctx, _rule(backend))
        assert backend.calls == []
        assert result is not None
        assert result.reason.WhichOneof("reason") == "error"

    def test_at_limit_is_scanned(self):
        backend = _LimitedBackend()
        ctx = RequestContext(sensitive_info_value=AT_LIMIT)
        result = evaluate_sensitive_info_locally(ctx, _rule(backend))
        assert backend.calls == [AT_LIMIT]
        assert result is not None
        assert result.reason.WhichOneof("reason") == "sensitive_info"

    def test_backend_without_limit_is_unchanged(self):
        backend = _RecordingBackend()
        long_value = "z" * 200_000
        ctx = RequestContext(sensitive_info_value=long_value)
        result = evaluate_sensitive_info_locally(ctx, _rule(backend))
        assert backend.calls == [long_value]
        assert result is not None
        assert result.reason.WhichOneof("reason") == "sensitive_info"

    def test_run_local_rules_live_short_circuits(self):
        backend = _LimitedBackend()
        ctx = RequestContext(sensitive_info_value=OVER)
        decision = _run_local_rules(ctx, (_rule(backend),))
        assert decision is not None
        assert decision.is_denied()
        assert decision.reason_v2.type == "ERROR"
        assert backend.calls == []

    def test_run_local_rules_dry_run_does_not_enforce(self):
        backend = _LimitedBackend()
        ctx = RequestContext(sensitive_info_value=OVER)
        assert _run_local_rules(ctx, (_rule(backend, Mode.DRY_RUN),)) is None
        assert backend.calls == []


# ---------------------------------------------------------------------------
# protect() end to end, async and sync clients
# ---------------------------------------------------------------------------

_SCOPE = {"headers": [], "type": "http"}


def _allow_response() -> decide_pb2.DecideResponse:
    return decide_pb2.DecideResponse(
        decision=decide_pb2.Decision(
            id="remote_allow", conclusion=decide_pb2.CONCLUSION_ALLOW
        )
    )


class _AsyncTransport:
    def __init__(self) -> None:
        self.decides: list[decide_pb2.DecideRequest] = []
        self.reports: list[decide_pb2.ReportRequest] = []

    async def decide(self, req: Any, **_kwargs: Any) -> decide_pb2.DecideResponse:
        self.decides.append(req)
        return _allow_response()

    async def report(self, req: Any, **_kwargs: Any) -> decide_pb2.ReportResponse:
        self.reports.append(req)
        return decide_pb2.ReportResponse()


class _SyncTransport:
    def __init__(self) -> None:
        self.decides: list[decide_pb2.DecideRequest] = []
        self.reports: list[decide_pb2.ReportRequest] = []
        self.reported = threading.Event()

    def decide(self, req: Any, **_kwargs: Any) -> decide_pb2.DecideResponse:
        self.decides.append(req)
        return _allow_response()

    def report(self, req: Any, **_kwargs: Any) -> decide_pb2.ReportResponse:
        self.reports.append(req)
        self.reported.set()
        return decide_pb2.ReportResponse()


@pytest.fixture
def _dev_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ARCJET_ENV", "development")


def _protect_async(backend: object, mode: Mode, value: str):
    from arcjet import arcjet

    aj = arcjet(key="ajkey_x", rules=[_rule(backend, mode)])
    transport = _AsyncTransport()
    aj._client = cast(Any, transport)

    async def run():
        decision = await aj.protect(_SCOPE, sensitive_info_value=value)
        # Let the fire-and-forget report task run.
        for _ in range(5):
            await asyncio.sleep(0)
        return decision

    return asyncio.run(run()), transport


def _protect_sync(backend: object, mode: Mode, value: str):
    from arcjet import arcjet_sync

    aj = arcjet_sync(key="ajkey_x", rules=[_rule(backend, mode)])
    transport = _SyncTransport()
    aj._client = cast(Any, transport)
    decision = aj.protect(_SCOPE, sensitive_info_value=value)
    return decision, transport


def _assert_live_denial(decision: Any, transport: Any, backend: _RecordingBackend):
    assert backend.calls == []
    assert decision.is_denied()
    assert decision.reason_v2.type != "SENSITIVE_INFO"
    assert decision.reason_v2.type == "ERROR"
    assert decision.reason_v2.message == MESSAGE
    # The local denial is reported, and never falls through to Decide.
    assert transport.decides == []
    assert len(transport.reports) == 1
    report = transport.reports[0]
    assert report.decision.conclusion == decide_pb2.CONCLUSION_DENY
    assert "alice" not in str(report)


@pytest.mark.usefixtures("_dev_env")
class TestProtect:
    def test_async_live_denies_and_reports(self):
        backend = _LimitedBackend()
        decision, transport = _protect_async(backend, Mode.LIVE, OVER)
        _assert_live_denial(decision, transport, backend)

    def test_sync_live_denies_and_reports(self):
        backend = _LimitedBackend()
        decision, transport = _protect_sync(backend, Mode.LIVE, OVER)
        assert transport.reported.wait(timeout=5)
        _assert_live_denial(decision, transport, backend)

    @pytest.mark.parametrize("protect", [_protect_async, _protect_sync])
    def test_dry_run_does_not_enforce(self, protect):
        backend = _LimitedBackend()
        decision, transport = protect(backend, Mode.DRY_RUN, OVER)
        assert backend.calls == []
        assert not decision.is_denied()
        assert len(transport.decides) == 1

    @pytest.mark.parametrize("protect", [_protect_async, _protect_sync])
    def test_at_limit_is_scanned(self, protect):
        backend = _LimitedBackend()
        decision, _transport = protect(backend, Mode.LIVE, AT_LIMIT)
        assert backend.calls == [AT_LIMIT]
        assert decision.is_denied()
        assert decision.reason_v2.type == "SENSITIVE_INFO"

    @pytest.mark.parametrize("protect", [_protect_async, _protect_sync])
    def test_backend_without_limit_is_unchanged(self, protect):
        backend = _RecordingBackend()
        decision, _transport = protect(backend, Mode.LIVE, OVER)
        assert backend.calls == [OVER]
        assert decision.reason_v2.type == "SENSITIVE_INFO"


# ---------------------------------------------------------------------------
# Guard: LocalDetectSensitiveInfo
# ---------------------------------------------------------------------------


def _guard_allow(request: Any) -> Any:
    from arcjet.guard.proto.decide.v2 import decide_pb2 as pb

    return pb.GuardResponse(
        decision=pb.GuardDecision(id="gdec_test", conclusion=pb.GUARD_CONCLUSION_ALLOW)
    )


class _GuardSyncTransport:
    def __init__(self) -> None:
        self.requests: list[Any] = []

    def guard(self, request: Any, **_kwargs: Any) -> Any:
        self.requests.append(request)
        return _guard_allow(request)


class _GuardAsyncTransport:
    def __init__(self) -> None:
        self.requests: list[Any] = []

    async def guard(self, request: Any, **_kwargs: Any) -> Any:
        self.requests.append(request)
        return _guard_allow(request)


def _local_si(request: Any) -> Any:
    [submission] = request.rule_submissions
    return submission.rule.local_sensitive_info


def _guard_sync(transport: Any) -> Any:
    from arcjet.guard import ArcjetGuardSync

    return ArcjetGuardSync(
        _key="ajkey_x", _client=transport, _timeout_ms=1000, _user_agent="test"
    )


class TestGuardRule:
    def test_local_evaluator_over_limit_is_computed_deny(self):
        from arcjet.guard._local import (
            LocalSensitiveInfoResult,
        )
        from arcjet.guard._local import (
            evaluate_sensitive_info_locally as guard_evaluate,
        )

        backend = _LimitedBackend()
        result = guard_evaluate(
            OVER, deny=("EMAIL",), backend=cast(SensitiveInfoBackend, backend)
        )
        assert backend.calls == []
        assert isinstance(result, LocalSensitiveInfoResult)
        assert result.conclusion == "DENY"
        assert result.detected_entity_types == []
        assert result.detected_entities == []

    def test_local_evaluator_at_limit_and_no_limit_scan(self):
        from arcjet.guard._local import (
            evaluate_sensitive_info_locally as guard_evaluate,
        )

        limited = _LimitedBackend()
        guard_evaluate(
            AT_LIMIT, deny=("EMAIL",), backend=cast(SensitiveInfoBackend, limited)
        )
        assert limited.calls == [AT_LIMIT]
        unlimited = _RecordingBackend()
        guard_evaluate(
            OVER, deny=("EMAIL",), backend=cast(SensitiveInfoBackend, unlimited)
        )
        assert unlimited.calls == [OVER]

    def _assert_computed_deny(self, request: Any, backend: _RecordingBackend):
        from arcjet.guard.proto.decide.v2 import decide_pb2 as pb

        assert backend.calls == []
        local_si = _local_si(request)
        # A computed DENY, never result_error (the server treats that as
        # fail-open).
        assert local_si.HasField("result_computed")
        assert not local_si.HasField("result_error")
        assert not local_si.HasField("result_not_run")
        assert local_si.result_computed.conclusion == pb.GUARD_CONCLUSION_DENY
        assert not local_si.result_computed.detected
        assert list(local_si.result_computed.detected_entities) == []
        assert list(local_si.result_computed.detected_entity_types) == []
        assert "alice" not in str(request)

    def test_sync_client_sends_computed_deny(self):
        from arcjet.guard import LocalDetectSensitiveInfo

        backend = _LimitedBackend()
        transport = _GuardSyncTransport()
        rule = LocalDetectSensitiveInfo(
            deny=["EMAIL"], backend=cast(SensitiveInfoBackend, backend)
        )
        _guard_sync(transport).guard([rule(OVER)], label="test")
        [request] = transport.requests
        self._assert_computed_deny(request, backend)

    def test_async_client_sends_computed_deny(self):
        from arcjet.guard import ArcjetGuard, LocalDetectSensitiveInfo

        backend = _LimitedBackend()
        transport = _GuardAsyncTransport()
        guard = ArcjetGuard(
            _key="ajkey_x",
            _client=cast(Any, transport),
            _timeout_ms=1000,
            _user_agent="test",
        )
        rule = LocalDetectSensitiveInfo(
            deny=["EMAIL"], backend=cast(SensitiveInfoBackend, backend)
        )
        asyncio.run(guard.guard([rule(OVER)], label="test"))
        [request] = transport.requests
        self._assert_computed_deny(request, backend)


# ---------------------------------------------------------------------------
# Guard: remote policy LOCAL sensitive info input
# ---------------------------------------------------------------------------


def _policy(mode: int) -> Any:
    from arcjet.guard.proto.decide.v2 import decide_pb2 as pb

    response = pb.GetGuardPolicyResponse(
        status=pb.GUARD_POLICY_LOOKUP_STATUS_AVAILABLE,
        policy=pb.GuardLocalPolicyProjection(
            policy_id="policy-1", revision="one", label="test"
        ),
    )
    response.policy.sensitive_info_rules.add(
        rule_id="pii-1",
        input_name="message",
        mode=mode,
        entities_deny=pb.EntityList(entities=["EMAIL"]),
    )
    return response


class TestRemotePolicy:
    def _prepare(self, backend: object, mode: int, value: str):
        from arcjet.guard import _remote_policy as remote_policy
        from arcjet.guard import local_input

        runtime = remote_policy.SyncRemotePolicyRuntime(
            lambda _label: _policy(mode),
            sensitive_info_backend=cast(SensitiveInfoBackend, backend),
        )
        return runtime.prepare("test", {"message": local_input.string(value)})

    def test_live_over_limit_is_local_denial(self):
        from arcjet.guard.proto.decide.v2 import decide_pb2 as pb

        backend = _LimitedBackend()
        prepared = self._prepare(backend, pb.GUARD_RULE_MODE_LIVE, OVER)
        assert backend.calls == []
        [result] = prepared.results
        assert result.WhichOneof("result") == "local_sensitive_info"
        assert result.local_sensitive_info.conclusion == pb.GUARD_CONCLUSION_DENY
        assert not result.local_sensitive_info.detected
        assert list(result.local_sensitive_info.detected_entities) == []
        assert prepared.has_live_denial

    def test_dry_run_over_limit_is_not_enforced(self):
        from arcjet.guard.proto.decide.v2 import decide_pb2 as pb

        backend = _LimitedBackend()
        prepared = self._prepare(backend, pb.GUARD_RULE_MODE_DRY_RUN, OVER)
        assert backend.calls == []
        [result] = prepared.results
        assert result.local_sensitive_info.conclusion == pb.GUARD_CONCLUSION_DENY
        assert not prepared.has_live_denial

    def test_at_limit_is_scanned(self):
        from arcjet.guard.proto.decide.v2 import decide_pb2 as pb

        backend = _LimitedBackend()
        prepared = self._prepare(backend, pb.GUARD_RULE_MODE_LIVE, AT_LIMIT)
        assert backend.calls == [AT_LIMIT]
        assert prepared.results[0].local_sensitive_info.detected

    def test_sync_guard_client_denies_over_limit_policy_input(self):
        from arcjet.guard import ArcjetGuardSync, local_input
        from arcjet.guard.proto.decide.v2 import decide_pb2 as pb

        class PolicyTransport(_GuardSyncTransport):
            def get_guard_policy(self, *_args: Any, **_kwargs: Any) -> Any:
                return _policy(pb.GUARD_RULE_MODE_LIVE)

            def guard(self, request: Any, **_kwargs: Any) -> Any:
                self.requests.append(request)
                # No server decision: the SDK returns its own local denial.
                return pb.GuardResponse()

        backend = _LimitedBackend()
        transport = PolicyTransport()
        guard = ArcjetGuardSync(
            _key="ajkey_x",
            _client=cast(Any, transport),
            _timeout_ms=1000,
            _user_agent="test",
            _sensitive_info_backend=cast(SensitiveInfoBackend, backend),
        )
        decision = guard.guard(
            label="test", inputs={"message": local_input.string(OVER)}
        )
        assert backend.calls == []
        assert decision.conclusion == "DENY"
        [request] = transport.requests
        assert "alice" not in str(request)
