"""Local projection lifecycle and wire encoding for remote Guard policy."""

from __future__ import annotations

import asyncio
import hashlib
import struct
import threading
import time
from dataclasses import dataclass
from typing import Awaitable, Callable

from ._local import (
    LocalSensitiveInfoError,
    LocalSensitiveInfoResult,
    evaluate_sensitive_info_locally,
)
from ._policy_input import PolicyInput, PolicyInputMap
from .proto.decide.v2 import decide_pb2 as pb

POLICY_CAPABILITIES = ("guard-policy-v1", "local-sensitive-info-v1")
_DIGEST_DOMAIN = b"arcjet.guard.policy-input.v1\0"


@dataclass(frozen=True, slots=True)
class PreparedPolicy:
    inputs: dict[str, pb.GuardPolicyInput]
    revision: str = ""
    results: tuple[pb.GuardLocalPolicyResult, ...] = ()


@dataclass(frozen=True, slots=True)
class _Snapshot:
    policy: pb.GuardLocalPolicyProjection
    refresh_at: float
    valid_until: float


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
        if number != number or number in (float("inf"), float("-inf")):
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
) -> tuple[pb.GuardLocalPolicyResult, ...]:
    results: list[pb.GuardLocalPolicyResult] = []
    for rule in policy.sensitive_info_rules:
        bound = local.get(rule.input_name)
        if bound is None:
            continue
        value, digest = bound
        which = rule.WhichOneof("entity_filter")
        allow = tuple(rule.entities_allow.entities) if which == "entities_allow" else ()
        deny = tuple(rule.entities_deny.entities) if which == "entities_deny" else ()
        evaluated = evaluate_sensitive_info_locally(value, allow=allow, deny=deny)
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
            result.local_sensitive_info.CopyFrom(
                pb.ResultLocalSensitiveInfo(
                    conclusion=(
                        pb.GUARD_CONCLUSION_DENY
                        if evaluated.conclusion == "DENY"
                        else pb.GUARD_CONCLUSION_ALLOW
                    ),
                    detected=bool(evaluated.detected_entity_types),
                    detected_entity_types=evaluated.detected_entity_types,
                )
            )
        elif isinstance(evaluated, LocalSensitiveInfoError):
            result.error.CopyFrom(
                pb.ResultError(message=evaluated.message, code=evaluated.code)
            )
        else:
            result.not_run.CopyFrom(pb.ResultNotRun())
        results.append(result)
    return tuple(results)


def _snapshot(response: pb.GetGuardPolicyResponse) -> _Snapshot | None:
    if (
        response.status != pb.GUARD_POLICY_LOOKUP_STATUS_AVAILABLE
        or not response.HasField("policy")
    ):
        return None
    refresh_in = response.policy.refresh_after_unix_ms - response.server_time_unix_ms
    valid_for = response.policy.valid_until_unix_ms - response.server_time_unix_ms
    if valid_for <= 0:
        return None
    now = time.monotonic()
    policy = pb.GuardLocalPolicyProjection()
    policy.CopyFrom(response.policy)
    return _Snapshot(
        policy=policy,
        refresh_at=now + max(0, refresh_in) / 1000,
        valid_until=now + valid_for / 1000,
    )


class SyncRemotePolicyRuntime:
    def __init__(
        self, fetch: Callable[[str], pb.GetGuardPolicyResponse | None]
    ) -> None:
        self._fetch = fetch
        self._snapshots: dict[str, _Snapshot] = {}
        self._lock = threading.Lock()

    def prepare(
        self, label: str, inputs: PolicyInputMap | None, *, force: bool = False
    ) -> PreparedPolicy:
        wire, local = _wire_inputs(inputs)
        snapshot = self._get(label, force=force) if local else None
        if snapshot is None:
            return PreparedPolicy(wire)
        return PreparedPolicy(
            wire, snapshot.policy.revision, _local_results(snapshot.policy, local)
        )

    def _get(self, label: str, *, force: bool) -> _Snapshot | None:
        now = time.monotonic()
        cached = self._snapshots.get(label)
        if not force and cached is not None and now < cached.refresh_at:
            return cached
        with self._lock:
            cached = self._snapshots.get(label)
            now = time.monotonic()
            if not force and cached is not None and now < cached.refresh_at:
                return cached
            try:
                response = self._fetch(label)
            except Exception:
                response = None
            fresh = _snapshot(response) if response is not None else None
            if fresh is not None:
                self._snapshots[label] = fresh
                return fresh
            if cached is not None and now < cached.valid_until:
                return cached
            self._snapshots.pop(label, None)
            return None


class AsyncRemotePolicyRuntime:
    def __init__(
        self, fetch: Callable[[str], Awaitable[pb.GetGuardPolicyResponse | None]]
    ) -> None:
        self._fetch = fetch
        self._snapshots: dict[str, _Snapshot] = {}
        self._tasks: dict[str, asyncio.Task[_Snapshot | None]] = {}

    async def prepare(
        self, label: str, inputs: PolicyInputMap | None, *, force: bool = False
    ) -> PreparedPolicy:
        wire, local = _wire_inputs(inputs)
        snapshot = await self._get(label, force=force) if local else None
        if snapshot is None:
            return PreparedPolicy(wire)
        return PreparedPolicy(
            wire, snapshot.policy.revision, _local_results(snapshot.policy, local)
        )

    async def _get(self, label: str, *, force: bool) -> _Snapshot | None:
        now = time.monotonic()
        cached = self._snapshots.get(label)
        if not force and cached is not None and now < cached.refresh_at:
            return cached
        task = self._tasks.get(label)
        if task is None:
            task = asyncio.create_task(self._refresh(label, cached))
            self._tasks[label] = task
        try:
            return await task
        finally:
            if self._tasks.get(label) is task:
                self._tasks.pop(label, None)

    async def _refresh(self, label: str, cached: _Snapshot | None) -> _Snapshot | None:
        try:
            response = await self._fetch(label)
        except Exception:
            response = None
        fresh = _snapshot(response) if response is not None else None
        if fresh is not None:
            self._snapshots[label] = fresh
            return fresh
        if cached is not None and time.monotonic() < cached.valid_until:
            return cached
        self._snapshots.pop(label, None)
        return None
