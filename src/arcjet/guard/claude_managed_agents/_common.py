"""Shared checkpoint wiring for the Managed Agents events and tool gates.

``_events`` and ``_tool`` used to copy the resolver / decide / capture loop.
That is the fail-closed path — keep it in one place.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextvars
import functools
import inspect
from collections.abc import Callable, Coroutine, Mapping, Sequence
from dataclasses import dataclass
from functools import partial
from typing import Any, Optional, TypeVar, Union, cast

from arcjet._logging import logger
from arcjet._metadata import Metadata

from .._checkpoint import (
    ResolvedInputs,
    _classify_decision,
    _emit_capture,
    _guard_async,
    _guard_sync,
    _outcome_for_completed_action,
    _resolve_correlation_id,
)
from .._errors import ArcjetDeniedError, ArcjetUnavailableError, OnGuardError
from .._policy_input import PolicyInputMap
from .._registry import _awaitable
from .._rules import RuleWithInput
from ._context import SESSION_METADATA_KEY, claude_managed_agents_context

ActorResolver = Union[str, Callable[[Mapping[str, Any]], Optional[str]], None]
InputResolver = Union[
    PolicyInputMap,
    Callable[[Mapping[str, Any]], Optional[PolicyInputMap]],
    None,
]
RulesResolver = Union[
    Sequence[RuleWithInput],
    Callable[[Mapping[str, Any]], Sequence[RuleWithInput]],
]
MetadataResolver = Union[
    Metadata, Callable[[Mapping[str, Any]], Optional[Metadata]], None
]

#: Attribute wrappers put on the copy they return, so a second wrap of the
#: same object does not evaluate the same call twice.
_GUARD_BRAND = "_arcjet_guarded"

PHASE_METADATA_KEY = "claude-managed-agents.phase"
TOOL_METADATA_KEY = "claude-managed-agents.tool"

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class CheckpointOutcome:
    """Shared result of one Guard evaluation. Surfaces interpret *failure*."""

    decision: Any
    failure: Optional[BaseException]
    prepared: ResolvedInputs
    correlation_id: Optional[str]
    metadata: Optional[Metadata]
    proceeded_open: bool


def _read(source: Any, name: str) -> Any:
    if source is None:
        return None
    if isinstance(source, Mapping):
        return source.get(name)
    return getattr(source, name, None)


def _resolve(source: Any, arguments: Mapping[str, Any]) -> Any:
    if source is None or not callable(source):
        return source
    return source(arguments)


def prepared_inputs(
    actor: ActorResolver, inputs: InputResolver, arguments: Mapping[str, Any]
) -> ResolvedInputs:
    degraded: Optional[BaseException] = None
    resolved_actor: Optional[str] = None
    resolved_inputs: Optional[PolicyInputMap] = None
    try:
        resolved_actor = _resolve(actor, arguments)
    except Exception as exc:
        degraded = exc
    try:
        resolved_inputs = _resolve(inputs, arguments)
    except Exception as exc:
        degraded = degraded or exc
    return ResolvedInputs(
        actor=resolved_actor, inputs=resolved_inputs, degraded=degraded
    )


def resolved_rules(
    rules: RulesResolver, arguments: Mapping[str, Any]
) -> Sequence[RuleWithInput]:
    if not callable(rules):
        return rules
    return cast(
        Callable[[Mapping[str, Any]], Sequence[RuleWithInput]],
        rules,
    )(arguments)


def resolve_metadata_value(
    metadata: MetadataResolver, arguments: Mapping[str, Any]
) -> Optional[Metadata]:
    if callable(metadata):
        return cast(
            Callable[[Mapping[str, Any]], Optional[Metadata]],
            metadata,
        )(arguments)
    return metadata


def merge_metadata(
    *,
    correlation_id: Optional[str],
    session_id: Optional[str],
    extra: Optional[Metadata],
    reserved: Mapping[str, Any],
) -> Optional[Metadata]:
    """User metadata, then reserved keys so phase / session / tool cannot be forged."""
    derived = claude_managed_agents_context(
        correlation_id=correlation_id,
        session_id=session_id,
    )
    merged: dict[str, Any] = {}
    if derived.metadata:
        merged.update(derived.metadata)
    if extra:
        merged.update(extra)
    owned = None
    if derived.metadata:
        owned = derived.metadata.get(SESSION_METADATA_KEY)
    if owned is not None:
        merged[SESSION_METADATA_KEY] = owned
    merged.update(reserved)
    return merged or None


def correlation_id_for(
    *,
    correlation_id: Optional[str],
    session_id: Optional[str],
) -> Optional[str]:
    derived = claude_managed_agents_context(
        correlation_id=correlation_id,
        session_id=session_id,
    )
    return _resolve_correlation_id(derived.correlation_id)


def unavailable_error(action: str, cause: Optional[BaseException]) -> BaseException:
    return ArcjetUnavailableError(action, cause=cause)


async def decide(
    guard: Any,
    *,
    action: str,
    correlation_id: Optional[str],
    metadata: Optional[Metadata],
    prepared: ResolvedInputs,
    rules: Sequence[RuleWithInput],
) -> Any:
    kwargs = {
        "rules": rules,
        "label": action,
        "metadata": metadata,
        "correlation_id": correlation_id,
        "actor": prepared.actor,
        "inputs": prepared.inputs,
    }
    if _awaitable(guard, "guard") is not None or guard is None:
        return await _guard_async(guard, **kwargs)
    return await asyncio.to_thread(partial(_guard_sync, guard, **kwargs))


async def evaluate_checkpoint(
    *,
    guard: Any,
    action: str,
    actor: ActorResolver,
    inputs: InputResolver,
    rules: RulesResolver,
    metadata: MetadataResolver,
    correlation_id: Optional[str],
    session_id: Optional[str],
    on_guard_error: OnGuardError,
    arguments: Mapping[str, Any],
    reserved_metadata: Mapping[str, Any],
) -> CheckpointOutcome:
    """Evaluate one checkpoint. Never raises an Arcjet error."""
    resolved_correlation = _resolve_correlation_id(None)
    resolved_metadata: Optional[Metadata] = None
    decision: Any = None
    prepared = ResolvedInputs()

    try:
        resolved_correlation = correlation_id_for(
            correlation_id=correlation_id, session_id=session_id
        )
        extra = resolve_metadata_value(metadata, arguments)
        resolved_metadata = merge_metadata(
            correlation_id=correlation_id,
            session_id=session_id,
            extra=extra,
            reserved=reserved_metadata,
        )
        prepared = prepared_inputs(actor, inputs, arguments)
        resolved_rules_list = resolved_rules(rules, arguments)
        decision = await decide(
            guard,
            action=action,
            correlation_id=resolved_correlation,
            metadata=resolved_metadata,
            prepared=prepared,
            rules=resolved_rules_list,
        )
        failure = _classify_decision(
            decision,
            action=action,
            on_guard_error=on_guard_error,
            denied_error=ArcjetDeniedError,
            unavailable_error=unavailable_error,
            degraded=prepared.degraded,
        )
    except Exception:
        if on_guard_error == "allow":
            logger.warning(
                "arcjet: policy for action %r could not be evaluated; proceeding "
                "because on_guard_error is 'allow'",
                action,
            )
            return CheckpointOutcome(
                decision=None,
                failure=None,
                prepared=prepared,
                correlation_id=resolved_correlation,
                metadata=resolved_metadata,
                proceeded_open=True,
            )
        _emit_capture(
            client=guard,
            action=action,
            outcome="unavailable",
            correlation_id=resolved_correlation,
            decision=None,
            metadata=resolved_metadata,
        )
        return CheckpointOutcome(
            decision=None,
            failure=unavailable_error(action, None),
            prepared=prepared,
            correlation_id=resolved_correlation,
            metadata=resolved_metadata,
            proceeded_open=False,
        )

    if failure is not None:
        denied = getattr(decision, "conclusion", None) == "DENY"
        _emit_capture(
            client=guard,
            action=action,
            outcome="denied" if denied else "unavailable",
            correlation_id=resolved_correlation,
            decision=decision,
            metadata=resolved_metadata,
        )
    else:
        _emit_capture(
            client=guard,
            action=action,
            outcome=_outcome_for_completed_action(decision, degraded=prepared.degraded),
            correlation_id=resolved_correlation,
            decision=decision,
            metadata=resolved_metadata,
        )
    return CheckpointOutcome(
        decision=decision,
        failure=failure,
        prepared=prepared,
        correlation_id=resolved_correlation,
        metadata=resolved_metadata,
        proceeded_open=False,
    )


async def maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def looks_async(fn: Any) -> bool:
    """True when *fn* should be awaited.

    Covers ``async def`` functions, bound coroutine methods (the real
    ``AsyncAnthropic`` ``sessions.events.send`` / ``BetaAsyncFunctionTool.call``),
    and instances whose ``__call__`` is async.
    """
    if inspect.iscoroutinefunction(fn):
        return True
    call = getattr(fn, "__call__", None)
    if inspect.iscoroutinefunction(call):
        return True
    unwrapped = inspect.unwrap(fn)
    if inspect.iscoroutinefunction(unwrapped):
        return True
    unwrapped_call = getattr(unwrapped, "__call__", None)
    return inspect.iscoroutinefunction(unwrapped_call)


def run_coroutine_sync(coro: Coroutine[Any, Any, T]) -> T:
    """Run *coro* from sync code, including when a loop is already running.

    ``asyncio.run`` cannot be called from a running loop. A coroutine that
    has not been scheduled yet can be driven on a side thread with its own
    loop. Contextvars (Sequence correlation) are copied onto that thread.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    def _runner() -> T:
        return asyncio.run(coro)

    copied = contextvars.copy_context()

    def _in_copied_context() -> T:
        return copied.run(_runner)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(_in_copied_context).result()


def adopt_wrapper(wrapper: Any, wrapped: Any) -> Any:
    """``functools.update_wrapper`` that tolerates instances without ``__name__``."""
    try:
        functools.update_wrapper(wrapper, wrapped)
    except AttributeError:
        # Instances used as callables often lack ``__name__`` / ``__doc__``.
        # Copying wrapper metadata is best-effort and must not fail the wrap.
        pass
    return wrapper


def is_already_guarded(value: Any) -> bool:
    return bool(getattr(value, _GUARD_BRAND, False))


def brand(value: Any) -> None:
    try:
        object.__setattr__(value, _GUARD_BRAND, True)
    except AttributeError as exc:
        raise TypeError(
            "could not brand the wrapped copy with "
            f"{_GUARD_BRAND!r}; the type likely uses __slots__ "
            "without space for this attribute. The wrap cannot proceed "
            "without the brand — a second wrap would double-call Guard."
        ) from exc
