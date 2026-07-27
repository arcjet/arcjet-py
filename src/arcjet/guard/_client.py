"""Async and sync guard clients for ``arcjet.guard``.

Provides :func:`launch_arcjet` (async) and :func:`launch_arcjet_sync` (sync)
factory functions that create configured guard clients.  The returned objects
expose a ``.guard()`` method that converts rules to proto, calls the Decide
v2 Guard RPC, and returns a typed :class:`~arcjet.guard._types.Decision`.
"""

from __future__ import annotations

import platform
import time
from dataclasses import dataclass, replace
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from typing import Protocol, Sequence, Union

import pyqwest

from arcjet._errors import ArcjetError, ArcjetMisconfiguration
from arcjet._logging import logger
from arcjet._metadata import (
    LocalWarning,
    Metadata,
    encode_metadata,
    enforce_metadata_budget,
)

from ._convert import (
    decision_from_proto,
    local_warnings_to_proto,
    local_warnings_to_sdk,
    rule_to_proto,
)
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


class _AsyncGuardTransport(Protocol):
    async def guard(
        self,
        request: pb.GuardRequest,
        *,
        headers: dict[str, str] | None = None,
        timeout_ms: int | None = None,
    ) -> pb.GuardResponse: ...


class _SyncGuardTransport(Protocol):
    def guard(
        self,
        request: pb.GuardRequest,
        *,
        headers: dict[str, str] | None = None,
        timeout_ms: int | None = None,
    ) -> pb.GuardResponse: ...


@dataclass(slots=True)
class ArcjetGuard:
    """Async guard client — call ``.guard()`` with bound rule inputs."""

    _key: str
    _client: _AsyncGuardTransport
    _timeout_ms: int
    _user_agent: str

    async def guard(
        self,
        rules: Sequence[RuleWithInput],
        *,
        label: str,
        metadata: Metadata | None = None,
        correlation_id: str | None = None,
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
            return _with_local_warnings(_make_error_decision(str(e)), result)

        return _with_local_warnings(decision_from_proto(resp), result)


@dataclass(slots=True)
class ArcjetGuardSync:
    """Sync guard client — call ``.guard()`` with bound rule inputs."""

    _key: str
    _client: _SyncGuardTransport
    _timeout_ms: int
    _user_agent: str

    def guard(
        self,
        rules: Sequence[RuleWithInput],
        *,
        label: str,
        metadata: Metadata | None = None,
        correlation_id: str | None = None,
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
            return _with_local_warnings(_make_error_decision(str(e)), result)

        return _with_local_warnings(decision_from_proto(resp), result)


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
