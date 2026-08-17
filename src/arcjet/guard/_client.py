"""Async and sync guard clients for ``arcjet.guard``.

Provides :func:`launch_arcjet` (async) and :func:`launch_arcjet_sync` (sync)
factory functions that create configured guard clients.  The returned objects
expose a ``.guard()`` method that converts rules to proto, calls the Decide
v2 Guard RPC, and returns a typed :class:`~arcjet.guard._types.Decision`.
"""

from __future__ import annotations

import logging
import platform
import threading
import time
from dataclasses import dataclass, field, replace
from datetime import datetime
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from typing import Any, Protocol, Sequence, Union

import pyqwest

from arcjet._errors import ArcjetError, ArcjetMisconfiguration
from arcjet._logging import logger
from arcjet._metadata import (
    LocalWarning,
    Metadata,
    encode_metadata,
    enforce_metadata_budget,
)
from arcjet._sensitive_info_backend import SensitiveInfoBackend
from arcjet._transport import build_async_transport, build_sync_transport

from ._capture import build_capture_request, normalize_capture_event
from ._convert import (
    decision_from_proto,
    local_warnings_to_proto,
    local_warnings_to_sdk,
    rule_to_proto,
)
from ._delivery import AsyncCaptureDelivery, SyncCaptureDelivery
from ._diagnostics import Diagnose, create_diagnose
from ._local import (
    LocalSensitiveInfoError,
    LocalSensitiveInfoResult,
    evaluate_sensitive_info_locally,
)
from ._policy_input import PolicyInputMap
from ._remote_policy import (
    POLICY_CAPABILITIES,
    AsyncRemotePolicyRuntime,
    PreparedPolicy,
    SyncRemotePolicyRuntime,
)
from ._rules import RuleWithInput, SensitiveInfoWithInput
from ._types import Decision, RuleResultError
from .proto.decide.v2 import decide_pb2 as pb


def _sdk_version(default: str = "0.0.0") -> str:
    try:
        return pkg_version("arcjet")
    except PackageNotFoundError:
        return default


def _build_user_agent() -> str:
    return f"arcjet-py/{_sdk_version()} (python/{platform.python_version()})"


_DEFAULT_BASE_URL = "https://decide.arcjet.com"
# Deadline for a guard() call when timeout_ms is not set.
#
# Sized for the slowest rules rather than the fastest: content moderation and
# prompt injection take materially longer than a rate-limit check, and a
# deadline yields a fail-open decision, so a tight default drops those rules
# instead of evaluating them.
_DEFAULT_TIMEOUT_MS = 2000

# The fallback sink, shared by every client that was not given a logger. Shared
# on purpose: it exists to keep a repeated best-effort drop from flooding the
# log, and the log is per-process, so two clients hitting the same problem should
# produce one line rather than two.
#
# A client built with `logger=` gets its own uncoalesced sink instead — see
# `launch_arcjet`. That is what makes a caller able to count drops, and what
# makes client-level diagnostics observable in a test.
_default_diagnose = create_diagnose()

# Guards first-capture delivery construction. Module-level rather than
# per-client because it is held only while building one delivery object, so
# cross-client contention is not measurable, and a per-instance lock would mean
# another dataclass field for callers that construct clients directly.
_delivery_init_lock = threading.Lock()


def _drain(diagnose: Diagnose) -> None:
    """Release any counts a coalescing sink is holding back.

    Only coalescing sinks have anything to drain, and an injected one may not, so
    this is duck-typed rather than required by the `Diagnose` protocol.
    """
    drain = getattr(diagnose, "drain", None)
    if callable(drain):
        drain()


def _auth_headers(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def _build_request(
    submissions: list[pb.GuardRuleSubmission],
    *,
    user_agent: str,
    label: str,
    metadata: Metadata | None,
    local_eval_duration_ms: int,
    correlation_id: str | None = None,
    local_warnings: list[LocalWarning] | None = None,
) -> pb.GuardRequest:
    req = pb.GuardRequest(
        user_agent=user_agent,
        local_eval_duration_ms=local_eval_duration_ms,
        sent_at_unix_ms=int(time.time() * 1000),
        label=label,
    )
    metadata_json, metadata_warnings = encode_metadata(metadata)
    if metadata_json:
        for k, v in metadata_json.items():
            req.metadata_json[k] = v
    if correlation_id:
        req.correlation_id = correlation_id
    req.rule_submissions.extend(submissions)
    # Trim to the SDK ceiling across every metadata map on the request — the
    # envelope plus one per rule — so an oversized blob cannot push the request
    # past the 1 MiB protocol limit and get it rejected. A rejected request is a
    # fail open, which would let metadata affect the decision.
    budget_warnings = enforce_metadata_budget(
        [req.metadata_json, *(sub.metadata_json for sub in req.rule_submissions)]
    )
    warnings = [*(local_warnings or []), *metadata_warnings, *budget_warnings]
    if warnings:
        req.local_warnings.extend(local_warnings_to_proto(warnings))
    return req


def _with_local_warnings(decision: Decision, request: pb.GuardRequest) -> Decision:
    """Merge the request's client-side ``local_warnings`` into
    ``decision.warnings``.

    The server persists ``local_warnings`` but never echoes them back on the
    response, so without this a metadata key the SDK dropped would be invisible
    to the caller. Reading them back off the built request keeps the encode in
    one place.
    """
    if not request.local_warnings:
        return decision
    local = local_warnings_to_sdk(
        LocalWarning(code=w.code, message=w.message) for w in request.local_warnings
    )
    return replace(decision, warnings=(*decision.warnings, *local))


def _apply_prepared_policy(request: pb.GuardRequest, policy: PreparedPolicy) -> None:
    request.policy_inputs.clear()
    for name, policy_input in policy.inputs.items():
        request.policy_inputs[name].CopyFrom(policy_input)
    request.local_policy_revision = policy.revision
    del request.local_policy_results[:]
    request.local_policy_results.extend(policy.results)


def _apply_sanitized_policy(request: pb.GuardRequest, policy: PreparedPolicy) -> None:
    """Attach policy evidence while retaining only local policy inputs."""
    request.policy_inputs.clear()
    for name, policy_input in policy.inputs.items():
        if policy_input.WhichOneof("representation") == "local":
            request.policy_inputs[name].CopyFrom(policy_input)
    request.local_policy_revision = policy.revision
    del request.local_policy_results[:]
    request.local_policy_results.extend(policy.results)
    del request.policy_capabilities[:]
    request.policy_capabilities.extend(POLICY_CAPABILITIES)


def _build_local_denial_request(
    policy: PreparedPolicy,
    *,
    user_agent: str,
    label: str,
    metadata: Metadata | None,
    local_eval_duration_ms: int,
    correlation_id: str | None,
) -> pb.GuardRequest:
    request = _build_request(
        [],
        user_agent=user_agent,
        label=label,
        metadata=metadata,
        local_eval_duration_ms=local_eval_duration_ms,
        correlation_id=correlation_id,
    )
    _apply_sanitized_policy(request, policy)
    return request


def _sanitized_decision_or_local_denial(
    response: pb.GuardResponse, policy: PreparedPolicy
) -> Decision:
    if not response.HasField("decision") or not response.decision.id:
        return _make_local_policy_denial(policy)
    return decision_from_proto(response)


def _make_local_policy_denial(policy: PreparedPolicy) -> Decision:
    """Build the server-shaped decision returned for an enforced local rule."""
    decision = pb.GuardDecision(
        # decision_from_proto treats an absent ID as a malformed server response.
        # Use a conversion-only sentinel, then remove it from the public decision:
        # locally enforced denials have no corresponding server decision.
        id="local-conversion-sentinel",
        conclusion=pb.GUARD_CONCLUSION_DENY,
        reason=pb.GUARD_REASON_SENSITIVE_INFO,
        policy_evaluation=pb.GuardPolicyEvaluation(
            revision=policy.revision,
            status=pb.GUARD_POLICY_STATUS_APPLIED,
        ),
    )
    for result, mode in zip(policy.results, policy.result_modes):
        policy_result = decision.policy_rule_results.add(
            policy_id=result.policy_id,
            policy_revision=result.policy_revision,
            rule_id=result.rule_id,
            type=result.type,
            mode=mode,
            execution=pb.GUARD_RULE_EXECUTION_SDK,
            source=pb.GUARD_RULE_SOURCE_REMOTE,
        )
        which = result.WhichOneof("result")
        if which is not None:
            getattr(policy_result, which).CopyFrom(getattr(result, which))
    converted = decision_from_proto(pb.GuardResponse(decision=decision))
    return replace(converted, id="")


def _make_error_decision(message: str) -> Decision:
    return Decision(
        conclusion="ALLOW",
        id="",
        results=(RuleResultError(message=message, code="TRANSPORT_ERROR"),),
        reason="ERROR",
    )


_LocalEvalResult = Union[LocalSensitiveInfoResult, LocalSensitiveInfoError]


def _run_local_evaluations(
    rules: list[RuleWithInput],
) -> dict[str, _LocalEvalResult]:
    """Evaluate local rules before proto serialization.

    Returns a mapping of ``input_id`` → local evaluation result.
    Rules without local evaluation (e.g. rate limits, prompt injection)
    are skipped.  Custom rules are already evaluated at bind time.
    """
    results: dict[str, _LocalEvalResult] = {}
    for rule in rules:
        if isinstance(rule, SensitiveInfoWithInput):
            result = evaluate_sensitive_info_locally(
                rule.text,
                allow=rule.config.allow,
                deny=rule.config.deny,
                backend=rule.config.backend,
            )
            if result is not None:
                results[rule._input_id] = result
    return results


def _prepare_guard(
    rules: Sequence[RuleWithInput],
    *,
    user_agent: str,
    label: str,
    metadata: Metadata | None,
    correlation_id: str | None = None,
) -> Decision | pb.GuardRequest:
    """Validate rules, run local evaluations, and build the proto request.

    Returns a :class:`Decision` for early returns (e.g. empty rules) or a
    :class:`~pb.GuardRequest` ready for transport.
    """
    rule_list = list(rules)

    t0 = time.perf_counter()
    local_results = _run_local_evaluations(rule_list)
    # Per-rule metadata keys the SDK could not encode ride on the request
    # envelope's local_warnings — GuardRuleSubmission has no warning field.
    rule_warnings: list[LocalWarning] = []
    try:
        submissions = [
            rule_to_proto(r, local_results, rule_index=i, warnings_out=rule_warnings)
            for i, r in enumerate(rule_list)
        ]
    except ArcjetError:
        raise
    except Exception as e:
        raise ArcjetError(f"Failed to encode rules: {e}") from e
    local_eval_duration_ms = int((time.perf_counter() - t0) * 1000)

    return _build_request(
        submissions,
        user_agent=user_agent,
        label=label,
        metadata=metadata,
        local_eval_duration_ms=local_eval_duration_ms,
        correlation_id=correlation_id,
        local_warnings=rule_warnings,
    )


class _GuardClient(Protocol):
    """What a checkpoint needs of a client, by shape rather than by class.

    Private, because it cannot yet describe the clients honestly: ``guard`` is
    a coroutine function on one client and a blocking one on the other, so the
    return has to stay ``Any``; the blocking spelling is ``guard_sync`` on the
    recorder but ``guard`` on ``ArcjetGuardSync``; and a *registered* client
    additionally needs ``capture`` and ``flush``, which a client passed to
    ``guard_tool`` does not. Publishing this shape would commit to a contract
    that has to widen, so it stays internal until the flavour question is
    settled.

    The clients are dispatched on structurally — whether ``guard`` is a
    coroutine function decides the flavour, and a double offering both spells
    the blocking one ``guard_sync`` — so the type that describes them has to be
    structural too. Naming the two concrete classes instead would make the
    in-memory recorder, and any hand-rolled double, a type error at every
    wiring site the documentation recommends.

    Describes the call a checkpoint makes, not the flavour it is made in:
    ``guard`` returns a decision or something awaitable that produces one, and
    which is which is decided per call site, because the recorder answers both.
    """

    def guard(
        self,
        rules: Sequence[RuleWithInput] = ...,
        *,
        label: str,
        actor: str | None = ...,
        inputs: PolicyInputMap | None = ...,
    ) -> Any: ...


def _shared_with_copies(self: Any, memo: dict[int, Any]) -> Any:
    """A ``__deepcopy__`` that shares the client rather than duplicating it.

    A client owns a transport holding a connection pool and a lock, which
    ``copy.deepcopy`` cannot copy at all, and duplicating one would not be
    meaningful if it could. Answering on the client rather than only where a
    client happens to be held makes the sharing independent of traversal
    order: a structure that reaches the client before whatever else refers to
    it copies as readily as one that reaches it after.
    """
    memo[id(self)] = self
    return self


def _redacted_repr(self: Any) -> str:
    """Render a client without the site key.

    The key authenticates as this site, and a client reaches a great many
    places that render objects: a traceback captured with frame locals, a log
    line, an error reporter, a debugger. Redacting it here covers every one of
    them, where each holder redacting its own copy covers only the holders
    anyone thought of.
    """
    return f"{type(self).__name__}(key=<redacted>, timeout_ms={self._timeout_ms})"


class _AsyncGuardTransport(Protocol):
    async def guard(
        self,
        request: pb.GuardRequest,
        *,
        headers: dict[str, str] | None = None,
        timeout_ms: int | None = None,
    ) -> pb.GuardResponse: ...

    async def get_guard_policy(
        self,
        request: pb.GetGuardPolicyRequest,
        *,
        headers: dict[str, str] | None = None,
        timeout_ms: int | None = None,
    ) -> pb.GetGuardPolicyResponse: ...

    async def capture(
        self,
        request: pb.CaptureRequest,
        *,
        headers: dict[str, str] | None = None,
        timeout_ms: int | None = None,
    ) -> pb.CaptureResponse: ...


class _SyncGuardTransport(Protocol):
    def guard(
        self,
        request: pb.GuardRequest,
        *,
        headers: dict[str, str] | None = None,
        timeout_ms: int | None = None,
    ) -> pb.GuardResponse: ...

    def get_guard_policy(
        self,
        request: pb.GetGuardPolicyRequest,
        *,
        headers: dict[str, str] | None = None,
        timeout_ms: int | None = None,
    ) -> pb.GetGuardPolicyResponse: ...

    def capture(
        self,
        request: pb.CaptureRequest,
        *,
        headers: dict[str, str] | None = None,
        timeout_ms: int | None = None,
    ) -> pb.CaptureResponse: ...


@dataclass(slots=True)
class ArcjetGuard:
    """Async guard client — call ``.guard()`` with bound rule inputs."""

    _key: str
    _client: _AsyncGuardTransport
    _timeout_ms: int
    _user_agent: str
    _sensitive_info_backend: SensitiveInfoBackend | None = None
    # Built on the first capture() call, so a client that never captures never
    # starts a worker task. Not a constructor argument.
    _delivery: AsyncCaptureDelivery | None = field(default=None, repr=False, init=False)
    # Where this client reports drops. Defaults to the shared coalescing
    # sink; `launch_arcjet(logger=...)` replaces it, and tests inject it.
    _diagnose: Diagnose = field(default=_default_diagnose, repr=False)
    _remote_policy: AsyncRemotePolicyRuntime = field(init=False, repr=False)

    def __post_init__(self) -> None:
        async def fetch(label: str) -> pb.GetGuardPolicyResponse:
            return await self._client.get_guard_policy(
                pb.GetGuardPolicyRequest(
                    user_agent=self._user_agent,
                    label=label,
                    policy_capabilities=POLICY_CAPABILITIES,
                ),
                headers=_auth_headers(self._key),
                timeout_ms=self._timeout_ms,
            )

        self._remote_policy = AsyncRemotePolicyRuntime(
            fetch, self._sensitive_info_backend
        )

    __repr__ = _redacted_repr
    __deepcopy__ = _shared_with_copies

    def capture(
        self,
        *,
        action: str,
        correlation_id: str | None = None,
        decision_id: str | None = None,
        occurred_at: datetime | None = None,
        metadata: Metadata | None = None,
    ) -> None:
        """Record something the application did, for visibility only.

        Returns immediately: the event is queued and sent in the background,
        batched with any others. It never affects a decision, never raises, and
        is best-effort — under sustained load or a failing backend, events are
        dropped rather than delaying your request. Drops are reported through
        the ``arcjet`` logger, never silently.

        Because delivery is asynchronous, an event queued when your process
        exits may never be sent. Call :meth:`flush` when you need delivery
        before shutdown.

        Args:
            action: What happened, e.g. ``"refund.issued"``. Convention is
                ``"resource.verb"`` in the past tense. Required; an event with
                no usable action is dropped, since it records nothing.
            correlation_id: Optional opaque identifier tying this event to
                ``guard()`` and ``capture()`` calls in the same workflow or
                agent run.
            decision_id: Optional id of a decision this event relates to, e.g.
                ``decision.id`` from an earlier ``guard()`` call.
            occurred_at: When it happened. Defaults to now. A naive datetime is
                read as local time, matching
                :meth:`datetime.datetime.timestamp`. A pre-epoch value
                cannot be represented — the wire field is unsigned — so the
                field falls back to the current time and is reported as a
                dropped field rather than dropping the whole event.
            metadata: Optional metadata — string keys mapped to any
                JSON-serializable value, including nested objects and arrays.
                Untrusted: do not put secrets or PII in it.
        """
        event = normalize_capture_event(
            action=action,
            correlation_id=correlation_id,
            decision_id=decision_id,
            occurred_at=occurred_at,
            metadata=metadata,
            diagnose=self._diagnose,
        )
        if event is None:
            return
        self._ensure_delivery().capture(event)

    async def flush(self, timeout_ms: int | None = None) -> None:
        """Wait for queued capture events to be sent.

        Args:
            timeout_ms: Deadline in milliseconds (default 1000). Events still
                queued when it expires are dropped and reported as ``AJ3003``.

        Does nothing if nothing has been captured. There is no ``close()``: a
        client holds no connection of its own to release, and flushing is the
        only shutdown step that affects what gets delivered.
        """
        if self._delivery is None:
            return
        await self._delivery.flush(timeout_ms)
        # Report counts the diagnostics channel held back while coalescing.
        # Without this a burst that stops reports only its first event.
        _drain(self._diagnose)

    def _ensure_delivery(self) -> AsyncCaptureDelivery:
        if self._delivery is not None:
            return self._delivery

        async def send(events: list[pb.CaptureEvent]) -> None:
            await self._client.capture(
                build_capture_request(events, user_agent=self._user_agent),
                headers=_auth_headers(self._key),
                timeout_ms=self._timeout_ms,
            )

        self._delivery = AsyncCaptureDelivery(send=send, diagnose=self._diagnose)
        return self._delivery

    async def guard(
        self,
        rules: Sequence[RuleWithInput] = (),
        *,
        label: str,
        metadata: Metadata | None = None,
        correlation_id: str | None = None,
        actor: str | None = None,
        inputs: PolicyInputMap | None = None,
    ) -> Decision:
        """Evaluate *rules* via the Arcjet Guard v2 API (async).

        Args:
            rules: Bound rule inputs (e.g. ``TokenBucket(...)(key="u")``)
            label: Label identifying this guard call (required by the server).
                Validated server-side as a slug: lowercase letters, digits,
                dash (``-``), and dot (``.``) only; must start and end with
                a lowercase letter or digit; max 256 bytes.
            metadata: Optional metadata for correlation and analytics —
                string keys mapped to any JSON-serializable value, including
                nested objects and arrays. Each top-level value is JSON-encoded
                by the SDK and stored verbatim, so exact integers survive.
                Server-enforced limits: 128 top-level keys, 4 KiB per
                serialized value, 10 levels of nesting, and key names limited
                to letters, digits, dash, dot, and underscore. Anything over a
                limit drops that one key and reports it on
                ``decision.warnings`` — never a failed call, and never a
                changed decision (metadata is excluded from fingerprinting).
                Metadata is untrusted: do not put secrets or PII in it.
            correlation_id: Optional opaque identifier used to correlate this
                guard call with other ``guard()``/``protect()`` calls in the
                same workflow or agent run. A dedicated, indexable field (unlike
                ``metadata``); does not affect the decision. Bounded server-side
                to 256 bytes of printable ASCII; invalid values are dropped.

        Returns:
            A :class:`Decision` with conclusion, reason, and per-rule results.
        """
        policy_eval_start = time.perf_counter()
        prepared = await self._remote_policy.prepare(label, inputs)
        sanitizes_inputs = prepared.sanitizes_inputs
        if prepared.has_live_denial:
            result = _build_local_denial_request(
                prepared,
                user_agent=self._user_agent,
                label=label,
                metadata=metadata,
                local_eval_duration_ms=int(
                    (time.perf_counter() - policy_eval_start) * 1000
                ),
                correlation_id=correlation_id,
            )
            local_denial = True
        else:
            result = _prepare_guard(
                rules,
                user_agent=self._user_agent,
                label=label,
                metadata=metadata,
                correlation_id=correlation_id,
            )
            local_denial = False
        if isinstance(result, Decision):
            return result
        if actor is not None:
            result.actor = actor
        if sanitizes_inputs:
            _apply_sanitized_policy(result, prepared)
        else:
            _apply_prepared_policy(result, prepared)
            result.policy_capabilities.extend(POLICY_CAPABILITIES)

        try:
            resp = await self._client.guard(
                result,
                headers=_auth_headers(self._key),
                timeout_ms=self._timeout_ms,
            )
            if local_denial and resp.HasField("decision") and resp.decision.id:
                return _with_local_warnings(decision_from_proto(resp), result)
            evaluation = resp.decision.policy_evaluation
            should_refresh = bool(inputs) and (
                evaluation.refresh_required
                or (
                    prepared.revision
                    and evaluation.revision
                    and evaluation.revision != prepared.revision
                )
            )
            if should_refresh:
                prepared = await self._remote_policy.prepare(label, inputs, force=True)
                sanitizes_inputs = sanitizes_inputs or prepared.sanitizes_inputs
                if sanitizes_inputs:
                    _apply_sanitized_policy(result, prepared)
                else:
                    _apply_prepared_policy(result, prepared)
                local_denial = prepared.has_live_denial
                resp = await self._client.guard(
                    result,
                    headers=_auth_headers(self._key),
                    timeout_ms=self._timeout_ms,
                )
        except ArcjetError:
            raise
        except Exception as e:
            logger.warning(
                "arcjet guard transport error: %s", e, extra={"event": "guard_error"}
            )
            if local_denial:
                return _with_local_warnings(_make_local_policy_denial(prepared), result)
            return _with_local_warnings(_make_error_decision(str(e)), result)

        decision = (
            _sanitized_decision_or_local_denial(resp, prepared)
            if local_denial
            else decision_from_proto(resp)
        )
        return _with_local_warnings(decision, result)


@dataclass(slots=True)
class ArcjetGuardSync:
    """Sync guard client — call ``.guard()`` with bound rule inputs."""

    _key: str
    _client: _SyncGuardTransport
    _timeout_ms: int
    _user_agent: str
    _sensitive_info_backend: SensitiveInfoBackend | None = None
    # Built on the first capture() call, so a client that never captures never
    # starts a worker thread. Not a constructor argument.
    _delivery: SyncCaptureDelivery | None = field(default=None, repr=False, init=False)
    # Where this client reports drops. Defaults to the shared coalescing
    # sink; `launch_arcjet(logger=...)` replaces it, and tests inject it.
    _diagnose: Diagnose = field(default=_default_diagnose, repr=False)
    _remote_policy: SyncRemotePolicyRuntime = field(init=False, repr=False)

    def __post_init__(self) -> None:
        def fetch(label: str) -> pb.GetGuardPolicyResponse:
            return self._client.get_guard_policy(
                pb.GetGuardPolicyRequest(
                    user_agent=self._user_agent,
                    label=label,
                    policy_capabilities=POLICY_CAPABILITIES,
                ),
                headers=_auth_headers(self._key),
                timeout_ms=self._timeout_ms,
            )

        self._remote_policy = SyncRemotePolicyRuntime(
            fetch, self._sensitive_info_backend
        )

    __repr__ = _redacted_repr
    __deepcopy__ = _shared_with_copies

    def capture(
        self,
        *,
        action: str,
        correlation_id: str | None = None,
        decision_id: str | None = None,
        occurred_at: datetime | None = None,
        metadata: Metadata | None = None,
    ) -> None:
        """Record something the application did, for visibility only.

        Returns immediately: the event is queued and sent on a background
        daemon thread, batched with any others. It never affects a decision,
        never raises, and is best-effort — under sustained load or a failing
        backend, events are dropped rather than delaying your request. Drops are
        reported through the ``arcjet`` logger, never silently.

        The worker is a daemon thread, so a queued event will not keep your
        process alive and may never be sent if you exit straight away. Call
        :meth:`flush` when you need delivery before shutdown.

        Args:
            action: What happened, e.g. ``"refund.issued"``. Convention is
                ``"resource.verb"`` in the past tense. Required; an event with
                no usable action is dropped, since it records nothing.
            correlation_id: Optional opaque identifier tying this event to
                ``guard()`` and ``capture()`` calls in the same workflow or
                agent run.
            decision_id: Optional id of a decision this event relates to, e.g.
                ``decision.id`` from an earlier ``guard()`` call.
            occurred_at: When it happened. Defaults to now. A naive datetime is
                read as local time, matching
                :meth:`datetime.datetime.timestamp`. A pre-epoch value
                cannot be represented — the wire field is unsigned — so the
                field falls back to the current time and is reported as a
                dropped field rather than dropping the whole event.
            metadata: Optional metadata — string keys mapped to any
                JSON-serializable value, including nested objects and arrays.
                Untrusted: do not put secrets or PII in it.
        """
        event = normalize_capture_event(
            action=action,
            correlation_id=correlation_id,
            decision_id=decision_id,
            occurred_at=occurred_at,
            metadata=metadata,
            diagnose=self._diagnose,
        )
        if event is None:
            return
        self._ensure_delivery().capture(event)

    def flush(self, timeout_ms: int | None = None) -> None:
        """Wait for queued capture events to be sent.

        Args:
            timeout_ms: Deadline in milliseconds (default 1000). Events still
                queued when it expires are dropped and reported as ``AJ3003``.

        Does nothing if nothing has been captured. There is no ``close()``: a
        client holds no connection of its own to release, and flushing is the
        only shutdown step that affects what gets delivered.
        """
        if self._delivery is None:
            return
        self._delivery.flush(timeout_ms)
        # Report counts the diagnostics channel held back while coalescing.
        # Without this a burst that stops reports only its first event.
        _drain(self._diagnose)

    def _ensure_delivery(self) -> SyncCaptureDelivery:
        # Double-checked locking. Two threads calling capture() for the first
        # time can otherwise both see None, each build a SyncCaptureDelivery and
        # start a worker thread, and one gets overwritten — orphaning its thread
        # along with any events already queued on it. The unlocked fast path
        # keeps the steady state free of lock traffic on the request path.
        delivery = self._delivery
        if delivery is not None:
            return delivery

        with _delivery_init_lock:
            delivery = self._delivery
            if delivery is not None:
                return delivery

            def send(events: list[pb.CaptureEvent]) -> None:
                self._client.capture(
                    build_capture_request(events, user_agent=self._user_agent),
                    headers=_auth_headers(self._key),
                    timeout_ms=self._timeout_ms,
                )

            delivery = SyncCaptureDelivery(send=send, diagnose=self._diagnose)
            self._delivery = delivery
            return delivery

    def guard(
        self,
        rules: Sequence[RuleWithInput] = (),
        *,
        label: str,
        metadata: Metadata | None = None,
        correlation_id: str | None = None,
        actor: str | None = None,
        inputs: PolicyInputMap | None = None,
    ) -> Decision:
        """Evaluate *rules* via the Arcjet Guard v2 API (sync).

        Args:
            rules: Bound rule inputs (e.g. ``TokenBucket(...)(key="u")``)
            label: Label identifying this guard call (required by the server).
                Validated server-side as a slug: lowercase letters, digits,
                dash (``-``), and dot (``.``) only; must start and end with
                a lowercase letter or digit; max 256 bytes.
            metadata: Optional metadata for correlation and analytics —
                string keys mapped to any JSON-serializable value, including
                nested objects and arrays. Each top-level value is JSON-encoded
                by the SDK and stored verbatim, so exact integers survive.
                Server-enforced limits: 128 top-level keys, 4 KiB per
                serialized value, 10 levels of nesting, and key names limited
                to letters, digits, dash, dot, and underscore. Anything over a
                limit drops that one key and reports it on
                ``decision.warnings`` — never a failed call, and never a
                changed decision (metadata is excluded from fingerprinting).
                Metadata is untrusted: do not put secrets or PII in it.
            correlation_id: Optional opaque identifier used to correlate this
                guard call with other ``guard()``/``protect()`` calls in the
                same workflow or agent run. A dedicated, indexable field (unlike
                ``metadata``); does not affect the decision. Bounded server-side
                to 256 bytes of printable ASCII; invalid values are dropped.

        Returns:
            A :class:`Decision` with conclusion, reason, and per-rule results.
        """
        policy_eval_start = time.perf_counter()
        prepared = self._remote_policy.prepare(label, inputs)
        sanitizes_inputs = prepared.sanitizes_inputs
        if prepared.has_live_denial:
            result = _build_local_denial_request(
                prepared,
                user_agent=self._user_agent,
                label=label,
                metadata=metadata,
                local_eval_duration_ms=int(
                    (time.perf_counter() - policy_eval_start) * 1000
                ),
                correlation_id=correlation_id,
            )
            local_denial = True
        else:
            result = _prepare_guard(
                rules,
                user_agent=self._user_agent,
                label=label,
                metadata=metadata,
                correlation_id=correlation_id,
            )
            local_denial = False
        if isinstance(result, Decision):
            return result
        if actor is not None:
            result.actor = actor
        if sanitizes_inputs:
            _apply_sanitized_policy(result, prepared)
        else:
            _apply_prepared_policy(result, prepared)
            result.policy_capabilities.extend(POLICY_CAPABILITIES)

        try:
            resp = self._client.guard(
                result,
                headers=_auth_headers(self._key),
                timeout_ms=self._timeout_ms,
            )
            if local_denial and resp.HasField("decision") and resp.decision.id:
                return _with_local_warnings(decision_from_proto(resp), result)
            evaluation = resp.decision.policy_evaluation
            should_refresh = bool(inputs) and (
                evaluation.refresh_required
                or (
                    prepared.revision
                    and evaluation.revision
                    and evaluation.revision != prepared.revision
                )
            )
            if should_refresh:
                prepared = self._remote_policy.prepare(label, inputs, force=True)
                sanitizes_inputs = sanitizes_inputs or prepared.sanitizes_inputs
                if sanitizes_inputs:
                    _apply_sanitized_policy(result, prepared)
                else:
                    _apply_prepared_policy(result, prepared)
                local_denial = prepared.has_live_denial
                resp = self._client.guard(
                    result,
                    headers=_auth_headers(self._key),
                    timeout_ms=self._timeout_ms,
                )
        except ArcjetError:
            raise
        except Exception as e:
            logger.warning(
                "arcjet guard transport error: %s", e, extra={"event": "guard_error"}
            )
            if local_denial:
                return _with_local_warnings(_make_local_policy_denial(prepared), result)
            return _with_local_warnings(_make_error_decision(str(e)), result)

        decision = (
            _sanitized_decision_or_local_denial(resp, prepared)
            if local_denial
            else decision_from_proto(resp)
        )
        return _with_local_warnings(decision, result)


def launch_arcjet(
    *,
    key: str,
    base_url: str = _DEFAULT_BASE_URL,
    timeout_ms: int = _DEFAULT_TIMEOUT_MS,
    logger: logging.Logger | None = None,
    sensitive_info_backend: SensitiveInfoBackend | None = None,
) -> ArcjetGuard:
    """Create an async Arcjet Guard client.

    Args:
        key: Your Arcjet site key.
        base_url: Override the Arcjet API endpoint.
        timeout_ms: Request timeout in milliseconds (default 2000).
        logger: Where to report capture diagnostics — dropped events, failed
            sends, expired flushes. Defaults to the ``arcjet`` logger with
            repeats of the same code coalesced for a minute, which keeps a drop
            storm from flooding your logs.

            Pass your own and you receive **every** diagnostic, uncoalesced,
            because you are then the one deciding what to filter or count. That
            is what makes it possible to keep a metric of dropped events; the
            coalesced default cannot be counted from.

    Returns:
        An :class:`ArcjetGuard` async client.

    Raises:
        ArcjetMisconfiguration: If *key* is empty.
    """
    if not key:
        raise ArcjetMisconfiguration("Arcjet key is required.")

    from arcjet.guard.proto.decide.v2.decide_connect import DecideServiceClient

    transport = build_async_transport()
    client = DecideServiceClient(
        base_url.rstrip("/"), http_client=pyqwest.Client(transport)
    )
    return ArcjetGuard(
        _key=key,
        _client=client,
        _timeout_ms=timeout_ms,
        _user_agent=_build_user_agent(),
        _sensitive_info_backend=sensitive_info_backend,
        # A caller-supplied logger sees every diagnostic: they control filtering,
        # so coalescing would only hide detail they asked for.
        _diagnose=(
            _default_diagnose
            if logger is None
            else create_diagnose(logger=logger, coalesce_seconds=0)
        ),
    )


def launch_arcjet_sync(
    *,
    key: str,
    base_url: str = _DEFAULT_BASE_URL,
    timeout_ms: int = _DEFAULT_TIMEOUT_MS,
    logger: logging.Logger | None = None,
    sensitive_info_backend: SensitiveInfoBackend | None = None,
) -> ArcjetGuardSync:
    """Create a sync Arcjet Guard client.

    Args:
        key: Your Arcjet site key.
        base_url: Override the Arcjet API endpoint.
        timeout_ms: Request timeout in milliseconds (default 2000).
        logger: Where to report capture diagnostics — dropped events, failed
            sends, expired flushes. Defaults to the ``arcjet`` logger with
            repeats of the same code coalesced for a minute, which keeps a drop
            storm from flooding your logs.

            Pass your own and you receive **every** diagnostic, uncoalesced,
            because you are then the one deciding what to filter or count. That
            is what makes it possible to keep a metric of dropped events; the
            coalesced default cannot be counted from.

    Returns:
        An :class:`ArcjetGuardSync` sync client.

    Raises:
        ArcjetMisconfiguration: If *key* is empty.
    """
    if not key:
        raise ArcjetMisconfiguration("Arcjet key is required.")

    from arcjet.guard.proto.decide.v2.decide_connect import DecideServiceClientSync

    transport = build_sync_transport()
    client = DecideServiceClientSync(
        base_url.rstrip("/"), http_client=pyqwest.SyncClient(transport)
    )
    return ArcjetGuardSync(
        _key=key,
        _client=client,
        _timeout_ms=timeout_ms,
        _user_agent=_build_user_agent(),
        _sensitive_info_backend=sensitive_info_backend,
        # A caller-supplied logger sees every diagnostic: they control filtering,
        # so coalescing would only hide detail they asked for.
        _diagnose=(
            _default_diagnose
            if logger is None
            else create_diagnose(logger=logger, coalesce_seconds=0)
        ),
    )
