"""Local projection lifecycle and wire encoding for remote Guard policy."""

from __future__ import annotations

import asyncio
import hashlib
import math
import struct
import threading
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Union

from arcjet._sensitive_info_backend import SensitiveInfoBackend

from ._local import (
    LocalSensitiveInfoError,
    LocalSensitiveInfoResult,
    evaluate_sensitive_info_locally,
)
from ._policy_input import PolicyInput, PolicyInputMap
from .proto.decide.v2 import decide_pb2 as pb

POLICY_CAPABILITIES = ("guard-policy-v1", "local-sensitive-info-v1")
_REFRESH_INTERVAL_SECONDS = 5 * 60
_EMPTY_RETRY_SECONDS = 5
_DIGEST_DOMAIN = b"arcjet.guard.policy-input.v1\0"


@dataclass(frozen=True, slots=True)
class PreparedPolicy:
    inputs: dict[str, pb.GuardPolicyInput]
    revision: str = ""
    results: tuple[pb.GuardLocalPolicyResult, ...] = ()
    result_modes: tuple[int, ...] = ()

    @property
    def has_live_denial(self) -> bool:
        return any(
            mode == pb.GUARD_RULE_MODE_LIVE
            and result.WhichOneof("result") == "local_sensitive_info"
            and result.local_sensitive_info.conclusion == pb.GUARD_CONCLUSION_DENY
            for result, mode in zip(self.results, self.result_modes)
        )

    @property
    def sanitizes_inputs(self) -> bool:
        return any(
            result.WhichOneof("result") == "local_sensitive_info"
            and result.local_sensitive_info.conclusion == pb.GUARD_CONCLUSION_DENY
            for result in self.results
        )


@dataclass(frozen=True, slots=True)
class _AvailableState:
    policy: pb.GuardLocalPolicyProjection
    refresh_at: float


@dataclass(frozen=True, slots=True)
class _NotConfiguredState:
    refresh_at: float


_CachedState = Union[_AvailableState, _NotConfiguredState]


def local_string_digest(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return hashlib.sha256(
        _DIGEST_DOMAIN + struct.pack(">I", len(encoded)) + encoded
    ).digest()


def _server_input(name: str, policy_input: PolicyInput) -> pb.GuardPolicyInput:
    value = policy_input.value
    server = pb.GuardPolicyServerInput()
    if policy_input.kind == "STRING" and type(value) is str:
        server.string_value = value
    elif policy_input.kind == "BOOLEAN" and type(value) is bool:
        server.boolean_value = value
    elif policy_input.kind == "INTEGER" and type(value) is int:
        if value < -(2**63) or value > 2**63 - 1:
            raise ValueError(f"policy input {name!r} is outside signed 64-bit range")
        server.integer_value = value
    elif (
        policy_input.kind == "NUMBER"
        and isinstance(value, (int, float))
        and not isinstance(value, bool)
    ):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError(f"policy input {name!r} must be finite")
        server.number_value = number
    elif (
        policy_input.kind == "STRING_LIST"
        and isinstance(value, tuple)
        and all(type(item) is str for item in value)
    ):
        server.string_list_value.values.extend(value)
    else:
        raise TypeError(f"policy input {name!r} does not match {policy_input.kind}")
    return pb.GuardPolicyInput(server=server)


def _wire_inputs(
    inputs: PolicyInputMap | None,
) -> tuple[dict[str, pb.GuardPolicyInput], dict[str, tuple[str, bytes]]]:
    wire: dict[str, pb.GuardPolicyInput] = {}
    local: dict[str, tuple[str, bytes]] = {}
    for name, policy_input in (inputs or {}).items():
        if not isinstance(policy_input, PolicyInput):
            raise TypeError(
                "policy inputs must be created with server_input or local_input"
            )
        if policy_input.exposure == "LOCAL":
            if policy_input.kind != "STRING" or type(policy_input.value) is not str:
                raise TypeError(f"local policy input {name!r} must be a string")
            digest = local_string_digest(policy_input.value)
            local[name] = (policy_input.value, digest)
            wire[name] = pb.GuardPolicyInput(
                local=pb.GuardPolicyLocalInput(
                    kind=pb.GUARD_POLICY_INPUT_KIND_STRING,
                    value_sha256=digest,
                )
            )
        elif policy_input.exposure == "SERVER":
            wire[name] = _server_input(name, policy_input)
        else:
            raise ValueError(f"policy input {name!r} has invalid exposure")
    return wire, local


def _local_results(
    policy: pb.GuardLocalPolicyProjection,
    local: dict[str, tuple[str, bytes]],
    backend: SensitiveInfoBackend | None,
) -> tuple[
    tuple[pb.GuardLocalPolicyResult, ...],
    tuple[int, ...],
]:
    results: list[pb.GuardLocalPolicyResult] = []
    modes: list[int] = []
    stopped = False
    for rule in policy.sensitive_info_rules:
        bound = local.get(rule.input_name)
        if bound is None:
            continue
        value, digest = bound
        which = rule.WhichOneof("entity_filter")
        allow = tuple(rule.entities_allow.entities) if which == "entities_allow" else ()
        deny = tuple(rule.entities_deny.entities) if which == "entities_deny" else ()
        evaluated = (
            None
            if stopped
            else evaluate_sensitive_info_locally(
                value, allow=allow, deny=deny, backend=backend
            )
        )
        result = pb.GuardLocalPolicyResult(
            policy_id=policy.policy_id,
            policy_revision=policy.revision,
            rule_id=rule.rule_id,
            input_name=rule.input_name,
            value_sha256=digest,
            type=pb.GUARD_RULE_TYPE_LOCAL_SENSITIVE_INFO,
        )
        if isinstance(evaluated, LocalSensitiveInfoResult):
            result.duration_ms = evaluated.elapsed_ms
            # The wire contract reports denied findings only; allowed detections
            # are intentionally omitted by the local evaluator.
            result.local_sensitive_info.CopyFrom(
                pb.ResultLocalSensitiveInfo(
                    conclusion=(
                        pb.GUARD_CONCLUSION_DENY
                        if evaluated.conclusion == "DENY"
                        else pb.GUARD_CONCLUSION_ALLOW
                    ),
                    detected=bool(evaluated.detected_entity_types),
                    detected_entity_types=evaluated.detected_entity_types,
                    detected_entities=[
                        pb.GuardSensitiveInfoEntity(type=entity, start=start, end=end)
                        for entity, start, end in evaluated.detected_entities
                    ],
                )
            )
        elif isinstance(evaluated, LocalSensitiveInfoError):
            result.error.CopyFrom(
                pb.ResultError(message=evaluated.message, code=evaluated.code)
            )
        else:
            result.not_run.CopyFrom(pb.ResultNotRun())
        results.append(result)
        modes.append(rule.mode)
        if (
            rule.mode == pb.GUARD_RULE_MODE_LIVE
            and isinstance(evaluated, LocalSensitiveInfoResult)
            and evaluated.conclusion == "DENY"
        ):
            stopped = True
    return tuple(results), tuple(modes)


def _available_state(
    response: pb.GetGuardPolicyResponse, refresh_at: float
) -> _AvailableState | None:
    if (
        response.status != pb.GUARD_POLICY_LOOKUP_STATUS_AVAILABLE
        or not response.HasField("policy")
    ):
        return None
    policy = pb.GuardLocalPolicyProjection()
    policy.CopyFrom(response.policy)
    return _AvailableState(policy=policy, refresh_at=refresh_at)


def _refresh_state(
    response: pb.GetGuardPolicyResponse | None,
    cached: _CachedState | None,
    now: float,
) -> _CachedState:
    refresh_at = now + _REFRESH_INTERVAL_SECONDS
    if response is not None:
        available = _available_state(response, refresh_at)
        if available is not None:
            return available
        if response.status == pb.GUARD_POLICY_LOOKUP_STATUS_NOT_CONFIGURED:
            return _NotConfiguredState(refresh_at)
    if cached is not None:
        if isinstance(cached, _AvailableState):
            return _AvailableState(cached.policy, refresh_at)
        return _NotConfiguredState(refresh_at)
    return _NotConfiguredState(now + _EMPTY_RETRY_SECONDS)


class SyncRemotePolicyRuntime:
    def __init__(
        self,
        fetch: Callable[[str], pb.GetGuardPolicyResponse | None],
        sensitive_info_backend: SensitiveInfoBackend | None = None,
    ) -> None:
        self._fetch = fetch
        self._sensitive_info_backend = sensitive_info_backend
        self._states: dict[str, _CachedState] = {}
        self._lock = threading.Lock()

    def prepare(
        self, label: str, inputs: PolicyInputMap | None, *, force: bool = False
    ) -> PreparedPolicy:
        wire, local = _wire_inputs(inputs)
        state = self._get(label, force=force) if local else None
        if not isinstance(state, _AvailableState):
            return PreparedPolicy(wire)
        results, modes = _local_results(
            state.policy, local, self._sensitive_info_backend
        )
        return PreparedPolicy(wire, state.policy.revision, results, modes)

    def _get(self, label: str, *, force: bool) -> _CachedState:
        now = time.monotonic()
        cached = self._states.get(label)
        if not force and cached is not None and now < cached.refresh_at:
            return cached
        with self._lock:
            cached = self._states.get(label)
            now = time.monotonic()
            if not force and cached is not None and now < cached.refresh_at:
                return cached
            try:
                response = self._fetch(label)
            except Exception:
                response = None
            state = _refresh_state(response, cached, time.monotonic())
            self._states[label] = state
            return state


class AsyncRemotePolicyRuntime:
    """Cache remote policy projections for one async client/event-loop context."""

    def __init__(
        self,
        fetch: Callable[[str], Awaitable[pb.GetGuardPolicyResponse | None]],
        sensitive_info_backend: SensitiveInfoBackend | None = None,
    ) -> None:
        self._fetch = fetch
        self._sensitive_info_backend = sensitive_info_backend
        self._states: dict[str, _CachedState] = {}
        self._tasks: dict[str, asyncio.Task[_CachedState]] = {}

    async def prepare(
        self, label: str, inputs: PolicyInputMap | None, *, force: bool = False
    ) -> PreparedPolicy:
        wire, local = _wire_inputs(inputs)
        state = await self._get(label, force=force) if local else None
        if not isinstance(state, _AvailableState):
            return PreparedPolicy(wire)
        results, modes = _local_results(
            state.policy, local, self._sensitive_info_backend
        )
        return PreparedPolicy(wire, state.policy.revision, results, modes)

    async def _get(self, label: str, *, force: bool) -> _CachedState:
        now = time.monotonic()
        cached = self._states.get(label)
        if not force and cached is not None and now < cached.refresh_at:
            return cached
        task = self._tasks.get(label)
        if task is None:
            task = asyncio.create_task(self._refresh(label, cached))
            self._tasks[label] = task
            task.add_done_callback(
                lambda completed: self._forget_task(label, completed)
            )
        return await asyncio.shield(task)

    def _forget_task(self, label: str, task: asyncio.Task[_CachedState]) -> None:
        if self._tasks.get(label) is task:
            self._tasks.pop(label, None)

    async def _refresh(self, label: str, cached: _CachedState | None) -> _CachedState:
        try:
            response = await self._fetch(label)
        except Exception:
            response = None
        state = _refresh_state(response, cached, time.monotonic())
        self._states[label] = state
        return state
