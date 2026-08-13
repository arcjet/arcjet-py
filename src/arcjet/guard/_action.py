"""Guard arbitrary callables without framework coupling.

A checkpoint in its simplest form: guard an action, run the callable, return
its value unchanged.
"""

from __future__ import annotations

from typing import Awaitable, Callable, Optional, Sequence, TypeVar

from arcjet._metadata import Metadata

from ._checkpoint import run_checkpoint, run_checkpoint_sync
from ._client import ArcjetGuard, ArcjetGuardSync
from ._errors import OnGuardError
from ._policy_input import PolicyInputMap
from ._registry import capture
from ._rules import RuleWithInput

T = TypeVar("T")

__all__ = [
    "guard_action",
    "guard_action_sync",
    "capture_action",
]


async def guard_action(
    fn: Callable[[], Awaitable[T]],
    *,
    action: str,
    guard: Optional[ArcjetGuard] = None,
    actor: Optional[str] = None,
    inputs: Optional[PolicyInputMap] = None,
    rules: Sequence[RuleWithInput] = (),
    metadata: Optional[Metadata] = None,
    correlation_id: Optional[str] = None,
    on_guard_error: OnGuardError = "deny",
) -> T:
    """Evaluate an Arcjet guard checkpoint and run the callable if allowed.

    The async surface for guarding arbitrary callables: pass a coroutine
    function, get its return value back, or an exception on denial.

    Fails closed by default — an unevaluated policy blocks the action unless
    ``on_guard_error="allow"``.  This is the one place Arcjet diverges from
    its platform-wide fail-open convention, because guarded callables wrap
    consequential effects: guard checkpoints exist specifically to stop
    unvetted effects from running.

    A ``DENY`` decision always blocks, regardless of ``on_guard_error`` —
    which only governs unevaluated policy (when the guard call failed).

    Args:
        fn: An awaitable callable (no arguments) — the action to guard.
        action: A short name for the checkpoint, passed to the guard server.
        guard: The Arcjet client. Defaults to the registered one; ``None`` still
            uses the registered client if one exists. With nothing registered
            the call fails open into an error decision, and ``on_guard_error``
            governs from there.
        actor: Who is performing the action.
        inputs: Values offered for remote policy evaluation.
        rules: Local guard rules. Defaults to none, which still contacts the
            server — it selects remote policy by ``label``.
        metadata: Application context.
        correlation_id: An identifier linking this event to a Sequence.
        on_guard_error: What to do if policy could not be evaluated:
            ``"deny"`` (default) blocks the action, ``"allow"`` runs it.

    Returns:
        The return value of *fn*.

    Raises:
        ArcjetDeniedError: The policy denied the action.
        ArcjetUnavailableError: Policy could not be evaluated under
            ``on_guard_error="deny"``.

    Example:
        ::

            from arcjet.guard import guard_action

            result = await guard_action(
                some_async_function,
                action="data.process",
            )
    """
    return await run_checkpoint(
        fn,
        action=action,
        guard=guard,
        actor=actor,
        inputs=inputs,
        rules=rules,
        metadata=metadata,
        correlation_id=correlation_id,
        on_guard_error=on_guard_error,
    )


def guard_action_sync(
    fn: Callable[[], T],
    *,
    action: str,
    guard: Optional[ArcjetGuardSync] = None,
    actor: Optional[str] = None,
    inputs: Optional[PolicyInputMap] = None,
    rules: Sequence[RuleWithInput] = (),
    metadata: Optional[Metadata] = None,
    correlation_id: Optional[str] = None,
    on_guard_error: OnGuardError = "deny",
) -> T:
    """Evaluate an Arcjet guard checkpoint and run the callable if allowed.

    The synchronous surface for guarding arbitrary callables: pass a callable
    (no arguments), get its return value back, or an exception on denial.

    Fails closed by default — an unevaluated policy blocks the action unless
    ``on_guard_error="allow"``.  This is the one place Arcjet diverges from
    its platform-wide fail-open convention, because guarded callables wrap
    consequential effects: guard checkpoints exist specifically to stop
    unvetted effects from running.

    A ``DENY`` decision always blocks, regardless of ``on_guard_error`` —
    which only governs unevaluated policy (when the guard call failed).

    Args:
        fn: A synchronous callable (no arguments) — the action to guard.
        action: A short name for the checkpoint, passed to the guard server.
        guard: The Arcjet client. Defaults to the registered one; ``None`` still
            uses the registered client if one exists. With nothing registered
            the call fails open into an error decision, and ``on_guard_error``
            governs from there.
        actor: Who is performing the action.
        inputs: Values offered for remote policy evaluation.
        rules: Local guard rules. Defaults to none, which still contacts the
            server — it selects remote policy by ``label``.
        metadata: Application context.
        correlation_id: An identifier linking this event to a Sequence.
        on_guard_error: What to do if policy could not be evaluated:
            ``"deny"`` (default) blocks the action, ``"allow"`` runs it.

    Returns:
        The return value of *fn*.

    Raises:
        ArcjetDeniedError: The policy denied the action.
        ArcjetUnavailableError: Policy could not be evaluated under
            ``on_guard_error="deny"``.

    Example:
        ::

            from arcjet.guard import guard_action_sync

            result = guard_action_sync(
                some_function,
                action="data.process",
            )
    """
    return run_checkpoint_sync(
        fn,
        action=action,
        guard=guard,
        actor=actor,
        inputs=inputs,
        rules=rules,
        metadata=metadata,
        correlation_id=correlation_id,
        on_guard_error=on_guard_error,
    )


def capture_action(
    *,
    action: str,
    metadata: Optional[Metadata] = None,
    correlation_id: Optional[str] = None,
    decision_id: Optional[str] = None,
) -> None:
    """Record something the application did, on the enclosing Sequence.

    The agent-facing spelling of :func:`arcjet.guard.capture`: identical,
    except that an omitted *correlation_id* is taken from the enclosing
    :func:`arcjet_sequence`, and *metadata* is merged with the sequence's.
    Never raises.

    The merge is unconditional, matching what a checkpoint emits: the
    sequence's metadata is applied first, then the call's own, so the
    caller's key wins on collision. Every event on a Sequence therefore
    carries the sequence's metadata.

    Args:
        action: A short name for what happened.
        metadata: Application context. Merged over the enclosing sequence's
            metadata, so the call's values win on key collision.
        correlation_id: An identifier linking this event to a Sequence.
            Inherited from the enclosing sequence if omitted.
        decision_id: The guard decision that authorized the action, if any.

    Example:
        ::

            from arcjet.guard import capture_action

            capture_action(
                action="item.created",
                metadata={"item_type": "invoice"},
            )
    """
    capture(
        action=action,
        correlation_id=correlation_id,
        decision_id=decision_id,
        metadata=metadata,
    )
