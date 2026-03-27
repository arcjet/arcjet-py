"""Async and sync guard clients for ``arcjet.guard``.

Provides :func:`launch_arcjet` (async) and :func:`launch_arcjet_sync` (sync)
factory functions that create configured guard clients.  The returned objects
expose a ``.guard()`` method that converts rules to proto, calls the Decide
v2 Guard RPC, and returns a typed :class:`~arcjet.guard.types.Decision`.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from typing import Sequence

import pyqwest

from arcjet._errors import ArcjetMisconfiguration, ArcjetTransportError
from arcjet._logging import logger

from .convert import decision_from_proto, rule_to_proto
from .proto.decide.v2 import decide_pb2 as pb
from .rules import RuleWithInput
from .types import Decision, RuleResultError


def _sdk_version(default: str = "0.0.0") -> str:
    try:
        return pkg_version("arcjet")
    except PackageNotFoundError:
        return default


_DEFAULT_BASE_URL = (
    os.getenv("ARCJET_BASE_URL")
    or (
        "https://fly.decide.arcjet.com"
        if os.getenv("FLY_APP_NAME")
        else "https://decide.arcjet.com"
    )
).rstrip("/")

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
    req.rule_submissions.extend(submissions)
    return req


def _make_error_decision(message: str) -> Decision:
    return Decision(
        conclusion="ALLOW",
        id="",
        results=(RuleResultError(message=message, code="TRANSPORT_ERROR"),),
        reason="ERROR",
    )


@dataclass(slots=True)
class ArcjetGuard:
    """Async guard client — call ``.guard()`` with bound rule inputs."""

    _key: str
    _client: object  # pyqwest-based connect client
    _timeout_ms: int
    _fail_open: bool
    _user_agent: str

    async def guard(
        self,
        rules: Sequence[RuleWithInput],
        *,
        label: str,
        metadata: dict[str, str] | None = None,
    ) -> Decision:
        """Evaluate *rules* via the Arcjet Guard v2 API (async).

        Args:
            rules: Bound rule inputs (e.g. ``token_bucket(...)(key="u")``)
            label: Label identifying this guard call (required by the server).
            metadata: Optional key/value metadata.

        Returns:
            A :class:`Decision` with conclusion, reason, and per-rule results.
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
        submissions = [rule_to_proto(r) for r in rule_list]
        local_eval_duration_ms = int((time.perf_counter() - t0) * 1000)

        req = _build_request(
            submissions,
            user_agent=self._user_agent,
            label=label,
            metadata=metadata,
            local_eval_duration_ms=local_eval_duration_ms,
        )

        try:
            resp = await self._client.guard(  # type: ignore[union-attr]
                req,
                headers=_auth_headers(self._key),
                timeout_ms=self._timeout_ms,
            )
        except Exception as e:
            if self._fail_open:
                logger.warning(
                    "arcjet guard fail_open: %s", e, extra={"event": "guard_error"}
                )
                return _make_error_decision(str(e))
            raise ArcjetTransportError(str(e)) from e

        return decision_from_proto(resp, rule_list)


@dataclass(slots=True)
class ArcjetGuardSync:
    """Sync guard client — call ``.guard()`` with bound rule inputs."""

    _key: str
    _client: object  # pyqwest-based connect client (sync)
    _timeout_ms: int
    _fail_open: bool
    _user_agent: str

    def guard(
        self,
        rules: Sequence[RuleWithInput],
        *,
        label: str,
        metadata: dict[str, str] | None = None,
    ) -> Decision:
        """Evaluate *rules* via the Arcjet Guard v2 API (sync).

        Args:
            rules: Bound rule inputs (e.g. ``token_bucket(...)(key="u")``)
            label: Label identifying this guard call (required by the server).
            metadata: Optional key/value metadata.

        Returns:
            A :class:`Decision` with conclusion, reason, and per-rule results.
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
        submissions = [rule_to_proto(r) for r in rule_list]
        local_eval_duration_ms = int((time.perf_counter() - t0) * 1000)

        req = _build_request(
            submissions,
            user_agent=self._user_agent,
            label=label,
            metadata=metadata,
            local_eval_duration_ms=local_eval_duration_ms,
        )

        try:
            resp = self._client.guard(  # type: ignore[union-attr]
                req,
                headers=_auth_headers(self._key),
                timeout_ms=self._timeout_ms,
            )
        except Exception as e:
            if self._fail_open:
                logger.warning(
                    "arcjet guard fail_open: %s", e, extra={"event": "guard_error"}
                )
                return _make_error_decision(str(e))
            raise ArcjetTransportError(str(e)) from e

        return decision_from_proto(resp, rule_list)


def launch_arcjet(
    *,
    key: str,
    base_url: str = _DEFAULT_BASE_URL,
    timeout_ms: int = _DEFAULT_TIMEOUT_MS,
    fail_open: bool = True,
) -> ArcjetGuard:
    """Create an async Arcjet Guard client.

    Args:
        key: Your Arcjet site key.
        base_url: Override the Arcjet API endpoint.
        timeout_ms: Request timeout in milliseconds (default 1000).
        fail_open: Return an error decision on transport failure instead of
            raising (default ``True``).

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
        _fail_open=fail_open,
        _user_agent=f"arcjet-py/{_sdk_version()}",
    )


def launch_arcjet_sync(
    *,
    key: str,
    base_url: str = _DEFAULT_BASE_URL,
    timeout_ms: int = _DEFAULT_TIMEOUT_MS,
    fail_open: bool = True,
) -> ArcjetGuardSync:
    """Create a sync Arcjet Guard client.

    Args:
        key: Your Arcjet site key.
        base_url: Override the Arcjet API endpoint.
        timeout_ms: Request timeout in milliseconds (default 1000).
        fail_open: Return an error decision on transport failure instead of
            raising (default ``True``).

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
        _fail_open=fail_open,
        _user_agent=f"arcjet-py/{_sdk_version()}",
    )
