"""Async and sync guard clients for ``arcjet.guard``.

Provides :func:`launch_arcjet` (async) and :func:`launch_arcjet_sync` (sync)
factory functions that create configured guard clients.  The returned objects
expose a ``.guard()`` method that converts rules to proto, calls the Decide
v2 Guard RPC, and returns a typed :class:`~arcjet.guard._types.Decision`.
"""

from __future__ import annotations

import asyncio
import platform
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from typing import Any, Protocol, Sequence, Union

import pyqwest

from arcjet._errors import ArcjetError, ArcjetMisconfiguration
from arcjet._logging import logger

from ._convert import decision_from_proto, rule_to_proto
from ._local import (
    LocalSensitiveInfoError,
    LocalSensitiveInfoResult,
    evaluate_sensitive_info_locally,
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
_DEFAULT_TIMEOUT_MS = 1000


def _auth_headers(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def _build_request(
    submissions: list[pb.GuardRuleSubmission],
    *,
    user_agent: str,
    label: str,
    metadata: dict[str, str] | None,
    local_eval_duration_ms: int,
    correlation_id: str | None = None,
) -> pb.GuardRequest:
    req = pb.GuardRequest(
        user_agent=user_agent,
        local_eval_duration_ms=local_eval_duration_ms,
        sent_at_unix_ms=int(time.time() * 1000),
        label=label,
    )
    if metadata:
        for k, v in metadata.items():
            req.metadata[k] = v
    if correlation_id:
        req.correlation_id = correlation_id
    req.rule_submissions.extend(submissions)
    return req


def _build_capture_request(
    action: str,
    *,
    user_agent: str,
    correlation_id: str | None,
    decision_id: str | None,
    occurred_at: datetime | None,
    metadata: dict[str, str] | None,
) -> pb.CaptureRequest:
    sent_at_unix_ms = int(time.time() * 1000)
    if occurred_at is not None:
        # Naive datetimes would otherwise be interpreted in the local
        # timezone, making the emitted unix-ms environment-dependent.
        if occurred_at.tzinfo is None:
            occurred_at = occurred_at.replace(tzinfo=timezone.utc)
        occurred_at_unix_ms = int(occurred_at.timestamp() * 1000)
    else:
        occurred_at_unix_ms = sent_at_unix_ms
    event = pb.CaptureEvent(
        occurred_at_unix_ms=occurred_at_unix_ms,
        action=action,
    )
    if correlation_id:
        event.correlation_id = correlation_id
    if decision_id:
        event.decision_id = decision_id
    if metadata:
        for k, v in metadata.items():
            event.metadata[k] = v
    req = pb.CaptureRequest(
        user_agent=user_agent,
        sent_at_unix_ms=sent_at_unix_ms,
    )
    req.events.append(event)
    return req


# Bound on concurrent in-flight capture sends per client. Calls beyond the
# bound drop their event (the best-effort contract) rather than accumulating
# unbounded background threads/tasks under high call volume.
_MAX_INFLIGHT_CAPTURES = 32


def _log_capture_drop(error: BaseException) -> None:
    # Capture is best-effort by contract: a failed send drops the event and
    # must never surface into caller code, so drops are only logged at debug.
    logger.debug(
        "arcjet capture event dropped: %s", error, extra={"event": "capture_error"}
    )


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
            )
            if result is not None:
                results[rule._input_id] = result
    return results


def _prepare_guard(
    rules: Sequence[RuleWithInput],
    *,
    user_agent: str,
    label: str,
    metadata: dict[str, str] | None,
    correlation_id: str | None = None,
) -> Decision | pb.GuardRequest:
    """Validate rules, run local evaluations, and build the proto request.

    Returns a :class:`Decision` for early returns (e.g. empty rules) or a
    :class:`~pb.GuardRequest` ready for transport.
    """
    rule_list = list(rules)

    if not rule_list:
        return Decision(
            conclusion="ALLOW",
            id="",
            results=(
                RuleResultError(
                    message="at least one rule is required",
                    code="VALIDATION_ERROR",
                ),
            ),
            reason="ERROR",
        )

    t0 = time.perf_counter()
    local_results = _run_local_evaluations(rule_list)
    try:
        submissions = [rule_to_proto(r, local_results) for r in rule_list]
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
    )


class _AsyncGuardTransport(Protocol):
    async def guard(
        self,
        request: pb.GuardRequest,
        *,
        headers: dict[str, str] | None = None,
        timeout_ms: int | None = None,
    ) -> pb.GuardResponse: ...

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
    # Strong references to in-flight capture tasks so the event loop cannot
    # garbage-collect them before they complete.
    _pending_captures: set[asyncio.Task[Any]] = field(default_factory=set)

    async def guard(
        self,
        rules: Sequence[RuleWithInput],
        *,
        label: str,
        metadata: dict[str, str] | None = None,
        correlation_id: str | None = None,
    ) -> Decision:
        """Evaluate *rules* via the Arcjet Guard v2 API (async).

        Args:
            rules: Bound rule inputs (e.g. ``TokenBucket(...)(key="u")``)
            label: Label identifying this guard call (required by the server).
                Validated server-side as a slug: lowercase letters, digits,
                dash (``-``), and dot (``.``) only; must start and end with
                a lowercase letter or digit; max 256 bytes.
            metadata: Optional key/value metadata.
            correlation_id: Optional opaque identifier used to correlate this
                guard call with other ``guard()``/``protect()`` calls in the
                same workflow or agent run. A dedicated, indexable field (unlike
                ``metadata``); does not affect the decision. Bounded server-side
                to 256 bytes of printable ASCII; invalid values are dropped.

        Returns:
            A :class:`Decision` with conclusion, reason, and per-rule results.
        """
        result = _prepare_guard(
            rules,
            user_agent=self._user_agent,
            label=label,
            metadata=metadata,
            correlation_id=correlation_id,
        )
        if isinstance(result, Decision):
            return result

        try:
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
            return _make_error_decision(str(e))

        return decision_from_proto(resp)

    def experimental_capture(
        self,
        action: str,
        *,
        correlation_id: str | None = None,
        decision_id: str | None = None,
        occurred_at: datetime | None = None,
        metadata: dict[str, str] | None = None,
    ) -> None:
        """Record a fact about what the application did — never a judgment.

        **Experimental.** Dogfooding only: the API shape may change and there
        is no delivery guarantee. Fire-and-forget: the RPC runs as a
        background task on the running event loop and a failure of any kind
        (invalid input, transport error, server rejection, no running loop,
        or too many in-flight sends) drops the event, logged at debug level
        only. Returning means the send
        has been initiated, not that the event was durably recorded: an ack
        from the server means "received," not "stored."

        Event identifiers are authored by the server when the event is
        received; the SDK does not mint or expose them.

        Args:
            action: The fact itself: what the application did, in customer
                vocabulary. Convention: ``"resource.verb"``, past tense
                (e.g. ``"refund.issued"``). Required — events without an
                action are dropped server-side.
            correlation_id: Optional opaque identifier used to correlate this
                event with other ``guard()``/``capture()`` calls in the same
                workflow or agent run. Never inherited automatically.
            decision_id: Optional join key referencing the decision (e.g. a
                ``Decision.id``) this event's action relates to.
            occurred_at: When the action occurred. Defaults to the time of
                the call; pass it explicitly when emission is deferred (e.g.
                from a queue or background worker). Informational and
                untrusted like every client-supplied timestamp — the server
                records its own authoritative receive time.
            metadata: Arbitrary key/value metadata. Customer-supplied and
                untrusted, same size caps as ``guard()`` metadata.
        """
        try:
            if len(self._pending_captures) >= _MAX_INFLIGHT_CAPTURES:
                _log_capture_drop(RuntimeError("too many in-flight capture events"))
                return
            request = _build_capture_request(
                action,
                user_agent=self._user_agent,
                correlation_id=correlation_id,
                decision_id=decision_id,
                occurred_at=occurred_at,
                metadata=metadata,
            )
            task = asyncio.get_running_loop().create_task(
                self._client.capture(
                    request,
                    headers=_auth_headers(self._key),
                    timeout_ms=self._timeout_ms,
                )
            )
            self._pending_captures.add(task)
            task.add_done_callback(self._on_capture_done)
        except Exception as e:
            _log_capture_drop(e)

    def _on_capture_done(self, task: asyncio.Task[Any]) -> None:
        self._pending_captures.discard(task)
        if task.cancelled():
            return
        error = task.exception()
        if error is not None:
            _log_capture_drop(error)


@dataclass(slots=True)
class ArcjetGuardSync:
    """Sync guard client — call ``.guard()`` with bound rule inputs."""

    _key: str
    _client: _SyncGuardTransport
    _timeout_ms: int
    _user_agent: str
    # Bounds concurrent capture daemon threads; see _MAX_INFLIGHT_CAPTURES.
    _capture_slots: threading.BoundedSemaphore = field(
        default_factory=lambda: threading.BoundedSemaphore(_MAX_INFLIGHT_CAPTURES)
    )

    def guard(
        self,
        rules: Sequence[RuleWithInput],
        *,
        label: str,
        metadata: dict[str, str] | None = None,
        correlation_id: str | None = None,
    ) -> Decision:
        """Evaluate *rules* via the Arcjet Guard v2 API (sync).

        Args:
            rules: Bound rule inputs (e.g. ``TokenBucket(...)(key="u")``)
            label: Label identifying this guard call (required by the server).
                Validated server-side as a slug: lowercase letters, digits,
                dash (``-``), and dot (``.``) only; must start and end with
                a lowercase letter or digit; max 256 bytes.
            metadata: Optional key/value metadata.
            correlation_id: Optional opaque identifier used to correlate this
                guard call with other ``guard()``/``protect()`` calls in the
                same workflow or agent run. A dedicated, indexable field (unlike
                ``metadata``); does not affect the decision. Bounded server-side
                to 256 bytes of printable ASCII; invalid values are dropped.

        Returns:
            A :class:`Decision` with conclusion, reason, and per-rule results.
        """
        result = _prepare_guard(
            rules,
            user_agent=self._user_agent,
            label=label,
            metadata=metadata,
            correlation_id=correlation_id,
        )
        if isinstance(result, Decision):
            return result

        try:
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
            return _make_error_decision(str(e))

        return decision_from_proto(resp)

    def experimental_capture(
        self,
        action: str,
        *,
        correlation_id: str | None = None,
        decision_id: str | None = None,
        occurred_at: datetime | None = None,
        metadata: dict[str, str] | None = None,
    ) -> None:
        """Record a fact about what the application did — never a judgment.

        **Experimental.** Dogfooding only: the API shape may change and there
        is no delivery guarantee. Fire-and-forget: the RPC runs on a daemon
        thread (bounded; calls beyond the in-flight cap drop their event) and
        a failure of any kind (invalid input, transport error, server
        rejection) drops the event, logged at debug level only. Returning
        means the send has been initiated, not that the event was durably
        recorded: an ack from the server means "received," not "stored."

        Event identifiers are authored by the server when the event is
        received; the SDK does not mint or expose them.

        Args:
            action: The fact itself: what the application did, in customer
                vocabulary. Convention: ``"resource.verb"``, past tense
                (e.g. ``"refund.issued"``). Required — events without an
                action are dropped server-side.
            correlation_id: Optional opaque identifier used to correlate this
                event with other ``guard()``/``capture()`` calls in the same
                workflow or agent run. Never inherited automatically.
            decision_id: Optional join key referencing the decision (e.g. a
                ``Decision.id``) this event's action relates to.
            occurred_at: When the action occurred. Defaults to the time of
                the call; pass it explicitly when emission is deferred (e.g.
                from a queue or background worker). Informational and
                untrusted like every client-supplied timestamp — the server
                records its own authoritative receive time.
            metadata: Arbitrary key/value metadata. Customer-supplied and
                untrusted, same size caps as ``guard()`` metadata.
        """
        if not self._capture_slots.acquire(blocking=False):
            _log_capture_drop(RuntimeError("too many in-flight capture events"))
            return
        try:
            request = _build_capture_request(
                action,
                user_agent=self._user_agent,
                correlation_id=correlation_id,
                decision_id=decision_id,
                occurred_at=occurred_at,
                metadata=metadata,
            )
            threading.Thread(
                target=self._send_capture,
                args=(request,),
                name="arcjet-capture",
                daemon=True,
            ).start()
        except Exception as e:
            self._capture_slots.release()
            _log_capture_drop(e)

    def _send_capture(self, request: pb.CaptureRequest) -> None:
        try:
            self._client.capture(
                request,
                headers=_auth_headers(self._key),
                timeout_ms=self._timeout_ms,
            )
        except Exception as e:
            _log_capture_drop(e)
        finally:
            self._capture_slots.release()


def launch_arcjet(
    *,
    key: str,
    base_url: str = _DEFAULT_BASE_URL,
    timeout_ms: int = _DEFAULT_TIMEOUT_MS,
) -> ArcjetGuard:
    """Create an async Arcjet Guard client.

    Args:
        key: Your Arcjet site key.
        base_url: Override the Arcjet API endpoint.
        timeout_ms: Request timeout in milliseconds (default 1000).

    Returns:
        An :class:`ArcjetGuard` async client.

    Raises:
        ArcjetMisconfiguration: If *key* is empty.
    """
    if not key:
        raise ArcjetMisconfiguration("Arcjet key is required.")

    from arcjet.guard.proto.decide.v2.decide_connect import DecideServiceClient

    transport = pyqwest.HTTPTransport(http_version=pyqwest.HTTPVersion.HTTP2)
    client = DecideServiceClient(
        base_url.rstrip("/"), http_client=pyqwest.Client(transport)
    )
    return ArcjetGuard(
        _key=key,
        _client=client,
        _timeout_ms=timeout_ms,
        _user_agent=_build_user_agent(),
    )


def launch_arcjet_sync(
    *,
    key: str,
    base_url: str = _DEFAULT_BASE_URL,
    timeout_ms: int = _DEFAULT_TIMEOUT_MS,
) -> ArcjetGuardSync:
    """Create a sync Arcjet Guard client.

    Args:
        key: Your Arcjet site key.
        base_url: Override the Arcjet API endpoint.
        timeout_ms: Request timeout in milliseconds (default 1000).

    Returns:
        An :class:`ArcjetGuardSync` sync client.

    Raises:
        ArcjetMisconfiguration: If *key* is empty.
    """
    if not key:
        raise ArcjetMisconfiguration("Arcjet key is required.")

    from arcjet.guard.proto.decide.v2.decide_connect import DecideServiceClientSync

    transport = pyqwest.SyncHTTPTransport(http_version=pyqwest.HTTPVersion.HTTP2)
    client = DecideServiceClientSync(
        base_url.rstrip("/"), http_client=pyqwest.SyncClient(transport)
    )
    return ArcjetGuardSync(
        _key=key,
        _client=client,
        _timeout_ms=timeout_ms,
        _user_agent=_build_user_agent(),
    )
