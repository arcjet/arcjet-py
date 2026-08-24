"""The single implementation of an Arcjet policy checkpoint.

Every guarding surface delegates here, so fail-closed semantics and the shape
of a capture event are defined once.  Surfaces above this module translate
framework constructs into its arguments; they do not re-implement any of it.

The four outcomes, their ordering, and the ``outcome`` metadata key match the
JavaScript helper (``arcjet-guard/src/agents/guarded.ts``) so one Sequence
reads the same whichever SDK produced it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import (
    Any,
    Awaitable,
    Callable,
    Literal,
    Optional,
    Sequence,
    TypeVar,
)

from arcjet._logging import logger
from arcjet._metadata import Metadata

from ._context import current_correlation_id, current_sequence_metadata
from ._errors import ArcjetDeniedError, ArcjetUnavailableError, OnGuardError
from ._policy_input import PolicyInputMap
from ._registry import _awaitable, _blocking
from ._registry import capture as _registry_capture
from ._registry import guard as _registry_guard
from ._registry import guard_sync as _registry_guard_sync
from ._rules import RuleWithInput
from ._types import Decision

T = TypeVar("T")

Outcome = Literal["success", "degraded", "denied", "error", "unavailable"]

DeniedFactory = Callable[[str, Decision], BaseException]
UnavailableFactory = Callable[[str, Optional[BaseException]], BaseException]

# Two distinct aliases, not one union. `make check` runs both `ty` and
# `pyright`, and a single `Callable[[], ResolvedInputs | Awaitable[...]]`
# would force every sync call site to narrow a value that can never be
# awaitable there.
SyncPrepare = Callable[[], "ResolvedInputs"]
AsyncPrepare = Callable[[], Awaitable["ResolvedInputs"]]


@dataclass(frozen=True, slots=True)
class ResolvedInputs:
    """What a surface resolved for a checkpoint, immediately before evaluation."""

    actor: Optional[str] = None
    inputs: Optional[PolicyInputMap] = None
    degraded: Optional[BaseException] = None
    """What stopped one of the above being resolved, if anything.

    A surface that can resolve *some* of what a decision is made from reports
    the failure here instead of raising it. Raising skips the guard call
    altogether, so under ``on_guard_error="allow"`` the action runs and Guard
    holds no record that it happened — a rate limit on the label then stops
    counting exactly the calls whose actor could not be resolved.

    Reporting it keeps the call on the record and leaves ``on_guard_error`` to
    decide whether an action the policy could not fully judge may proceed.
    """


def _default_denied(action: str, decision: Decision) -> BaseException:
    return ArcjetDeniedError(action, decision)


def _default_unavailable(action: str, cause: Optional[BaseException]) -> BaseException:
    return ArcjetUnavailableError(action, cause=cause)


def _resolve_correlation_id(explicit: Optional[str]) -> Optional[str]:
    """Explicit argument wins; otherwise fall back to the ambient sequence.

    A surface with a third tier — LangChain reads a ``RunnableConfig`` — folds
    that in before calling, by passing the config's value as *explicit*.
    """
    return explicit if explicit is not None else current_correlation_id()


def _outcome_for_completed_action(
    decision: Optional[Decision],
    *,
    degraded: Optional[BaseException],
) -> Outcome:
    """The outcome for an action that ran: ``success`` or ``degraded``.

    ``success`` claims that policy judged the action, so it is reserved for the
    case where policy judged all of it. Everything else here ran only because
    ``on_guard_error="allow"`` let it: the guard call failed, its answer could
    not be read, the decision failed open, or an input the decision needed
    could not be resolved.

    A ``degraded`` event still carries a decision ID when one exists. That is
    what separates policy judging the action in part from policy never judging
    it at all, and it is why one value covers three states.
    """
    if decision is None:
        return "degraded"
    if decision.has_failed_open() or degraded is not None:
        return "degraded"
    return "success"


def _merged_metadata(explicit: Optional[Metadata], outcome: Outcome) -> Metadata:
    """Sequence metadata, then the call's own, then the outcome.

    The outcome is applied last on purpose: it is what the engine observed, and
    a caller must not be able to overwrite it with a metadata key of the same
    name.
    """
    merged: dict[str, Any] = {}
    ambient = current_sequence_metadata()
    if ambient:
        merged.update(ambient)
    if explicit:
        merged.update(explicit)
    merged["outcome"] = outcome
    return merged


def _decision_id(decision: Optional[Decision]) -> Optional[str]:
    """The decision's id, or ``None`` when there is nothing correlatable.

    Every decision the client synthesizes on a fail-open path carries
    ``id=""``.  An empty string is not an id — putting it on an event is junk
    that looks like data.
    """
    if decision is None or not decision.id:
        return None
    return decision.id


def _emit_capture(
    *,
    client: Any,
    action: str,
    outcome: Outcome,
    correlation_id: Optional[str],
    decision: Optional[Decision],
    metadata: Optional[Metadata],
) -> None:
    """Record the outcome. Never raises.

    Capture is the reality half of a Sequence and is best-effort by design.  An
    audit-trail problem must not turn a successful application action into a
    failure, so every error here is swallowed and reported on the ``arcjet``
    logger instead.

    ``capture()`` is synchronous on both client flavors — it queues and
    returns, doing no I/O on the caller's path — so one code path serves both.
    """
    try:
        payload: dict[str, Any] = dict(
            action=action,
            correlation_id=correlation_id,
            decision_id=_decision_id(decision),
            metadata=_merged_metadata(metadata, outcome),
        )
        if client is None:
            _registry_capture(**payload)
        else:
            client.capture(**payload)
    except Exception:
        logger.warning(
            "arcjet: failed to capture checkpoint outcome for action %r", action
        )


def _classify_decision(
    decision: Decision,
    *,
    action: str,
    on_guard_error: OnGuardError,
    denied_error: DeniedFactory,
    unavailable_error: UnavailableFactory,
    degraded: Optional[BaseException] = None,
) -> Optional[BaseException]:
    """Return the exception this outcome requires, or ``None`` to proceed.

    A denied decision always raises, regardless of ``on_guard_error``, which
    only governs unevaluated policy.

    *degraded* is whatever stopped one of the decision's inputs being resolved.
    Guard saw the call either way, so the decision is on the record; what
    ``on_guard_error`` governs is whether an action the policy could not fully
    judge may run. It also travels as the cause of a failed-open refusal, so an
    operator is told what stopped the read rather than only that policy could
    not be evaluated — the two co-occur during an outage.
    """
    if decision.conclusion == "DENY":
        return denied_error(action, decision)
    if decision.has_failed_open():
        if on_guard_error != "allow":
            return unavailable_error(action, degraded)
        logger.warning(
            "arcjet: policy for action %r could not be evaluated; proceeding "
            "because on_guard_error is 'allow'",
            action,
        )
        return None
    if degraded is not None:
        if on_guard_error != "allow":
            return unavailable_error(action, degraded)
        logger.warning(
            "arcjet: could not resolve everything policy needed for action %r; "
            "it was evaluated without that, and the action proceeds because "
            "on_guard_error is 'allow'",
            action,
            exc_info=degraded,
        )
    return None


def _guard_sync(client: Any, **kwargs: Any) -> Decision:
    """Evaluate through *client*, or the registered client when it is ``None``.

    An explicitly passed client always wins over the registered one, per the
    client-lifecycle ADR.  ``None`` falls back to the free call, which fails
    open with an error decision when nothing is registered — so an unguarded
    process produces ``has_failed_open()``, and ``on_guard_error`` governs from
    there.
    """
    if client is None:
        return _registry_guard_sync(**kwargs)

    method = _blocking(client, "guard_sync", "guard")
    if method is None:
        # An async client handed to the sync path. Raising here is what routes
        # it into the caller's `except` and out as an unavailability error,
        # rather than letting a coroutine object escape as if it were a
        # decision.
        raise TypeError("A synchronous checkpoint requires a synchronous Arcjet client")
    return method(**kwargs)


async def _guard_async(client: Any, **kwargs: Any) -> Decision:
    """Evaluate through *client*, or the registered client when it is ``None``.

    Async counterpart of ``_guard_sync``.
    """
    if client is None:
        return await _registry_guard(**kwargs)

    method = _awaitable(client, "guard")
    if method is None:
        # A sync-only client handed to the async path.
        raise TypeError(
            "An asynchronous checkpoint requires an asynchronous Arcjet client"
        )
    return await method(**kwargs)


def run_checkpoint_sync(
    fn: Callable[[], T],
    *,
    action: str,
    guard: Any = None,
    prepare: Optional[SyncPrepare] = None,
    actor: Optional[str] = None,
    inputs: Optional[PolicyInputMap] = None,
    rules: Sequence[RuleWithInput] = (),
    metadata: Optional[Metadata] = None,
    correlation_id: Optional[str] = None,
    on_guard_error: OnGuardError = "deny",
    denied_error: DeniedFactory = _default_denied,
    unavailable_error: UnavailableFactory = _default_unavailable,
) -> T:
    """Evaluate a checkpoint, then run *fn* if policy allows it."""
    resolved_correlation_id = _resolve_correlation_id(correlation_id)
    decision: Optional[Decision] = None
    # Bound before the attempt, so the classification below reads it whether or
    # not `prepare` got far enough to return one.
    prepared = ResolvedInputs()
    # Cleared where the guard's answer could not be classified, which keeps
    # such an answer off the record below.
    decision_readable = True

    try:
        prepared = prepare() if prepare is not None else ResolvedInputs(actor, inputs)
        decision = _guard_sync(
            guard,
            rules=rules,
            label=action,
            metadata=metadata,
            correlation_id=resolved_correlation_id,
            actor=prepared.actor,
            inputs=prepared.inputs,
        )
    except Exception as exc:
        # The guard call itself, or the surface's own resolution, failed. Rare
        # on the guard side: the client turns transport failures into decisions
        # rather than raising.
        #
        # Tested against "allow" rather than for "deny", as every other branch
        # is: a value that is neither must fail closed, and only `guard_tool`
        # validates the knob before it gets here.
        if on_guard_error != "allow":
            _emit_capture(
                client=guard,
                action=action,
                outcome="unavailable",
                correlation_id=resolved_correlation_id,
                decision=None,
                metadata=metadata,
            )
            raise unavailable_error(action, exc) from exc
        logger.warning(
            "arcjet: policy for action %r could not be evaluated; proceeding "
            "because on_guard_error is 'allow'",
            action,
        )

    if decision is not None:
        try:
            failure = _classify_decision(
                decision,
                action=action,
                on_guard_error=on_guard_error,
                denied_error=denied_error,
                unavailable_error=unavailable_error,
                degraded=prepared.degraded,
            )
        except Exception as exc:
            # A client that answered with something that is not a decision.
            # Reading it is not the caller's mistake to receive raw: policy was
            # not evaluated, which is what `on_guard_error` governs.
            if on_guard_error != "allow":
                _emit_capture(
                    client=guard,
                    action=action,
                    outcome="unavailable",
                    correlation_id=resolved_correlation_id,
                    decision=None,
                    metadata=metadata,
                )
                raise unavailable_error(action, exc) from exc
            logger.warning(
                "arcjet: could not read the decision for action %r; proceeding "
                "because on_guard_error is 'allow'",
                action,
                exc_info=exc,
            )
            failure = None
            decision_readable = False
        if failure is not None:
            outcome: Outcome = (
                "denied" if decision.conclusion == "DENY" else "unavailable"
            )
            _emit_capture(
                client=guard,
                action=action,
                outcome=outcome,
                correlation_id=resolved_correlation_id,
                decision=decision,
                metadata=metadata,
            )
            raise failure

    # What goes on the record. It differs from `decision` only for an answer
    # the engine could not read: nothing correlatable comes off such an object,
    # and an answer that could not be classified judged nothing, which is
    # exactly what an absent decision ID reports. Passing it on would lose the
    # event altogether, because building one reads an id it does not have.
    recorded = decision if decision_readable else None

    try:
        result = fn()
    except Exception:
        _emit_capture(
            client=guard,
            action=action,
            outcome="error",
            correlation_id=resolved_correlation_id,
            decision=recorded,
            metadata=metadata,
        )
        raise

    _emit_capture(
        client=guard,
        action=action,
        outcome=_outcome_for_completed_action(recorded, degraded=prepared.degraded),
        correlation_id=resolved_correlation_id,
        decision=recorded,
        metadata=metadata,
    )
    return result


async def run_checkpoint(
    fn: Callable[[], Awaitable[T]],
    *,
    action: str,
    guard: Any = None,
    prepare: Optional[AsyncPrepare] = None,
    actor: Optional[str] = None,
    inputs: Optional[PolicyInputMap] = None,
    rules: Sequence[RuleWithInput] = (),
    metadata: Optional[Metadata] = None,
    correlation_id: Optional[str] = None,
    on_guard_error: OnGuardError = "deny",
    denied_error: DeniedFactory = _default_denied,
    unavailable_error: UnavailableFactory = _default_unavailable,
) -> T:
    """Evaluate a checkpoint, then run *fn* if policy allows it."""
    resolved_correlation_id = _resolve_correlation_id(correlation_id)
    decision: Optional[Decision] = None
    # Bound before the attempt, so the classification below reads it whether or
    # not `prepare` got far enough to return one.
    prepared = ResolvedInputs()
    # Cleared where the guard's answer could not be classified, which keeps
    # such an answer off the record below.
    decision_readable = True

    try:
        prepared = (
            await prepare() if prepare is not None else ResolvedInputs(actor, inputs)
        )
        decision = await _guard_async(
            guard,
            rules=rules,
            label=action,
            metadata=metadata,
            correlation_id=resolved_correlation_id,
            actor=prepared.actor,
            inputs=prepared.inputs,
        )
    except Exception as exc:
        # The guard call itself, or the surface's own resolution, failed. Rare
        # on the guard side: the client turns transport failures into decisions
        # rather than raising.
        #
        # Tested against "allow" rather than for "deny", as every other branch
        # is: a value that is neither must fail closed, and only `guard_tool`
        # validates the knob before it gets here.
        if on_guard_error != "allow":
            _emit_capture(
                client=guard,
                action=action,
                outcome="unavailable",
                correlation_id=resolved_correlation_id,
                decision=None,
                metadata=metadata,
            )
            raise unavailable_error(action, exc) from exc
        logger.warning(
            "arcjet: policy for action %r could not be evaluated; proceeding "
            "because on_guard_error is 'allow'",
            action,
        )

    if decision is not None:
        try:
            failure = _classify_decision(
                decision,
                action=action,
                on_guard_error=on_guard_error,
                denied_error=denied_error,
                unavailable_error=unavailable_error,
                degraded=prepared.degraded,
            )
        except Exception as exc:
            # A client that answered with something that is not a decision.
            # Reading it is not the caller's mistake to receive raw: policy was
            # not evaluated, which is what `on_guard_error` governs.
            if on_guard_error != "allow":
                _emit_capture(
                    client=guard,
                    action=action,
                    outcome="unavailable",
                    correlation_id=resolved_correlation_id,
                    decision=None,
                    metadata=metadata,
                )
                raise unavailable_error(action, exc) from exc
            logger.warning(
                "arcjet: could not read the decision for action %r; proceeding "
                "because on_guard_error is 'allow'",
                action,
                exc_info=exc,
            )
            failure = None
            decision_readable = False
        if failure is not None:
            outcome: Outcome = (
                "denied" if decision.conclusion == "DENY" else "unavailable"
            )
            _emit_capture(
                client=guard,
                action=action,
                outcome=outcome,
                correlation_id=resolved_correlation_id,
                decision=decision,
                metadata=metadata,
            )
            raise failure

    # What goes on the record. It differs from `decision` only for an answer
    # the engine could not read: nothing correlatable comes off such an object,
    # and an answer that could not be classified judged nothing, which is
    # exactly what an absent decision ID reports. Passing it on would lose the
    # event altogether, because building one reads an id it does not have.
    recorded = decision if decision_readable else None

    try:
        result = await fn()
    except Exception:
        _emit_capture(
            client=guard,
            action=action,
            outcome="error",
            correlation_id=resolved_correlation_id,
            decision=recorded,
            metadata=metadata,
        )
        raise

    _emit_capture(
        client=guard,
        action=action,
        outcome=_outcome_for_completed_action(recorded, degraded=prepared.degraded),
        correlation_id=resolved_correlation_id,
        decision=recorded,
        metadata=metadata,
    )
    return result
