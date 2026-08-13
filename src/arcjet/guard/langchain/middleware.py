"""Arcjet policy checkpoints as LangChain agent middleware.

Install ``arcjet[langchain-agents]``.  This module imports ``langchain``,
which pulls in LangGraph; :mod:`arcjet.guard.langchain` deliberately does not
import it, so ``guard_tool`` keeps working with only ``langchain-core``.

``wrap_tool_call`` sees a tool call's parsed, validated arguments immediately
before execution and may decline to call ``handler`` at all, which is what
makes it an enforcement point rather than an observation point.  Nothing here
rewrites a request: ``request.override(...)`` exists and is deliberately
unused, per the no-mutation rule in the checkpoint ADR.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Optional, Union, cast

from langchain.agents.middleware.types import AgentMiddleware
from langchain_core.messages import ToolMessage
from langgraph.prebuilt.tool_node import ToolCallRequest
from langgraph.types import Command

from arcjet._metadata import Metadata
from arcjet.guard._checkpoint import ResolvedInputs, run_checkpoint, run_checkpoint_sync
from arcjet.guard._client import ArcjetGuard, ArcjetGuardSync
from arcjet.guard._errors import OnGuardError
from arcjet.guard._policy_input import PolicyInputMap
from arcjet.guard._rules import RuleWithInput

# Type aliases for policy resolvers. Middleware resolvers take parsed arguments,
# unlike _tool.py resolvers which take RunnableConfig.
ActorResolver = str | Callable[[Mapping[str, Any]], str | None]
InputResolver = PolicyInputMap | Callable[[Mapping[str, Any]], PolicyInputMap]
AsyncActorResolver = (
    str | Callable[[Mapping[str, Any]], str | None | Awaitable[str | None]]
)
AsyncInputResolver = (
    PolicyInputMap
    | Callable[[Mapping[str, Any]], PolicyInputMap | Awaitable[PolicyInputMap]]
)


@dataclass(frozen=True, slots=True)
class ToolPolicy:
    """How one tool's calls are checked.

    Args:
        action: The label for this checkpoint, e.g. ``"email.sent"``.
            Convention is ``resource.verb`` in the past tense.
        rules: Bound rule inputs. Empty is normal and still contacts Guard,
            because the server selects remote policy by ``action``.
        actor: Who is acting — a string, or a callable taking the tool call's
            parsed arguments.
        inputs: Values offered for policy evaluation — a mapping, or a
            callable taking the parsed arguments.
        metadata: Metadata attached to this checkpoint's capture.
    """

    action: str
    rules: Sequence[RuleWithInput] = ()
    actor: Optional[ActorResolver | AsyncActorResolver] = None
    inputs: Optional[InputResolver | AsyncInputResolver] = None
    metadata: Optional[Metadata] = None


class ArcjetMiddleware(AgentMiddleware):
    """LangChain agent middleware enforcing Arcjet policies on tool calls.

    Tool calls matching an entry in ``policies`` are evaluated against Arcjet
    Guard; others pass through unguarded. A denied tool call raises
    ``ArcjetDeniedError`` and does not invoke the tool.
    """

    def __init__(
        self,
        *,
        guard: Union[ArcjetGuard, ArcjetGuardSync],
        policies: Mapping[str, ToolPolicy],
        on_guard_error: OnGuardError = "deny",
    ) -> None:
        """Initialize the middleware.

        Args:
            guard: The Arcjet Guard client (sync or async).
            policies: Mapping of tool names to their checkpoint policies.
                Tools not in this mapping pass through unguarded.
            on_guard_error: How to handle policy evaluation errors.
                ``"deny"`` is the default; ``"allow"`` permits degraded calls.
        """
        self._guard = guard
        self._policies = dict(policies)
        self._on_guard_error = on_guard_error

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command[Any]],
    ) -> ToolMessage | Command[Any]:
        """Synchronous tool call enforcement.

        Args:
            request: The tool call with parsed, validated arguments.
            handler: The tool execution function.

        Returns:
            The tool result (from ``handler``) or a denial message.

        Raises:
            ArcjetDeniedError: If the checkpoint denies the tool call.
            TypeError: If the guard is not synchronous.
        """
        tool_name = request.tool_call["name"]
        policy = self._policies.get(tool_name)

        if policy is None:
            return handler(request)

        if not isinstance(self._guard, ArcjetGuardSync):
            raise TypeError(
                "A synchronous middleware invocation requires ArcjetGuardSync"
            )

        args = request.tool_call["args"]

        def prepare() -> ResolvedInputs:
            actor: Optional[str] = None
            if policy.actor is not None:
                if isinstance(policy.actor, str):
                    actor = policy.actor
                else:
                    resolved_actor = policy.actor
                    actor_value = resolved_actor(args)
                    if inspect.isawaitable(actor_value):
                        raise TypeError(
                            "A synchronous actor resolver must not return an awaitable"
                        )
                    actor = actor_value

            inputs: Optional[PolicyInputMap] = None
            if policy.inputs is not None:
                if callable(policy.inputs):
                    resolved_inputs = cast(
                        Callable[
                            [Mapping[str, Any]],
                            PolicyInputMap | Awaitable[PolicyInputMap],
                        ],
                        policy.inputs,
                    )
                    inputs_value = resolved_inputs(args)
                    if inspect.isawaitable(inputs_value):
                        raise TypeError(
                            "A synchronous input resolver must not return an awaitable"
                        )
                    inputs = inputs_value
                else:
                    inputs = cast(PolicyInputMap, policy.inputs)

            return ResolvedInputs(actor=actor, inputs=inputs)

        return run_checkpoint_sync(
            lambda: handler(request),
            action=policy.action,
            guard=self._guard,
            prepare=prepare,
            rules=policy.rules,
            metadata=policy.metadata,
            on_guard_error=cast(OnGuardError, self._on_guard_error),
        )

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[Any]]],
    ) -> ToolMessage | Command[Any]:
        """Asynchronous tool call enforcement.

        Args:
            request: The tool call with parsed, validated arguments.
            handler: The tool execution function.

        Returns:
            The tool result (from ``handler``) or a denial message.

        Raises:
            ArcjetDeniedError: If the checkpoint denies the tool call.
            TypeError: If the guard is not asynchronous.
        """
        tool_name = request.tool_call["name"]
        policy = self._policies.get(tool_name)

        if policy is None:
            return await handler(request)

        if not isinstance(self._guard, ArcjetGuard):
            raise TypeError(
                "An asynchronous middleware invocation requires ArcjetGuard"
            )

        args = request.tool_call["args"]

        async def prepare() -> ResolvedInputs:
            actor: Optional[str] = None
            if policy.actor is not None:
                if isinstance(policy.actor, str):
                    actor = policy.actor
                else:
                    resolved_actor = cast(
                        Callable[[Mapping[str, Any]], Union[str, Awaitable[str]]],
                        policy.actor,
                    )
                    resolved = resolved_actor(args)
                    if isinstance(resolved, Awaitable):
                        actor = await cast(Awaitable[str], resolved)
                    else:
                        actor = cast(str, resolved)

            inputs: Optional[PolicyInputMap] = None
            if policy.inputs is not None:
                if callable(policy.inputs):
                    resolved_inputs = cast(
                        Callable[
                            [Mapping[str, Any]],
                            Union[PolicyInputMap, Awaitable[PolicyInputMap]],
                        ],
                        policy.inputs,
                    )
                    resolved = resolved_inputs(args)
                    if isinstance(resolved, Awaitable):
                        inputs = await cast(Awaitable[PolicyInputMap], resolved)
                    else:
                        inputs = cast(PolicyInputMap, resolved)
                else:
                    inputs = cast(PolicyInputMap, policy.inputs)

            return ResolvedInputs(actor=actor, inputs=inputs)

        return await run_checkpoint(
            lambda: handler(request),
            action=policy.action,
            guard=self._guard,
            prepare=prepare,
            rules=policy.rules,
            metadata=policy.metadata,
            on_guard_error=cast(OnGuardError, self._on_guard_error),
        )
