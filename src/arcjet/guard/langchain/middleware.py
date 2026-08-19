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

from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Optional, cast

from langchain.agents.middleware.types import AgentMiddleware
from langchain_core.messages import ToolMessage
from langchain_core.runnables.config import ensure_config
from langgraph.prebuilt.tool_node import ToolCallRequest
from langgraph.types import Command

from arcjet._errors import ArcjetMisconfiguration
from arcjet._metadata import Metadata
from arcjet.guard._checkpoint import ResolvedInputs, run_checkpoint, run_checkpoint_sync
from arcjet.guard._client import _GuardClient
from arcjet.guard._errors import OnGuardError
from arcjet.guard._policy_input import PolicyInputMap
from arcjet.guard._registry import _awaitable, _blocking
from arcjet.guard._rules import RuleWithInput

from ._tool import (
    _awaited,
    _correlation_from_config,
    _not_awaited,
    _resolved,
    _resolved_async,
)

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


def _policy_actor(policy: "ToolPolicy", args: Mapping[str, Any]) -> Any:
    """The actor this policy names, or the value its resolver returns."""
    if policy.actor is None or isinstance(policy.actor, str):
        return policy.actor
    return cast(Callable[[Mapping[str, Any]], Any], policy.actor)(args)


def _policy_inputs(policy: "ToolPolicy", args: Mapping[str, Any]) -> Any:
    """The inputs this policy names, or the value its resolver returns."""
    if policy.inputs is None or not callable(policy.inputs):
        return policy.inputs
    return cast(Callable[[Mapping[str, Any]], Any], policy.inputs)(args)


class ArcjetMiddleware(AgentMiddleware):
    """LangChain agent middleware enforcing Arcjet policies on tool calls.

    Tool calls matching an entry in ``policies`` are evaluated against Arcjet
    Guard; others pass through unguarded. A denied tool call raises
    ``ArcjetDeniedError`` and does not invoke the tool.
    """

    def __init__(
        self,
        *,
        policies: Mapping[str, ToolPolicy],
        guard: Optional[_GuardClient] = None,
        on_guard_error: OnGuardError = "deny",
        tools: Optional[Sequence[Any]] = None,
    ) -> None:
        """Initialize the middleware.

        Args:
            policies: Mapping of tool names to their checkpoint policies.
                Tools not in this mapping pass through unguarded.
            tools: The tools the agent was built with. Optional, but pass the
                same sequence given to ``create_agent``: a policy is matched by
                tool name, so a typo or a renamed ``@tool`` function otherwise
                leaves that tool unguarded and looks exactly like a healthy
                allow. Given them, a key naming no tool is refused here.
            guard: The Arcjet Guard client. Optional, as it is on every other
                guard surface: without one the checkpoint uses the client
                registered with :func:`~arcjet.guard.register_arcjet`.
            on_guard_error: How to handle policy evaluation errors.
                ``"deny"`` is the default; ``"allow"`` permits degraded calls.
        """
        if on_guard_error not in ("allow", "deny"):
            raise ArcjetMisconfiguration(
                f"on_guard_error must be 'allow' or 'deny', got {on_guard_error!r}. "
                f"It decides whether a tool call runs when policy could not be "
                f"evaluated, so there is no safe value to guess."
            )
        self._guard = guard
        self._policies = dict(policies)
        self._on_guard_error = on_guard_error
        if tools is not None:
            named = {getattr(tool, "name", None) for tool in tools}
            unmatched = sorted(key for key in self._policies if key not in named)
            if unmatched:
                raise ArcjetMisconfiguration(
                    f"No tool is named {unmatched!r}. A policy is matched by "
                    f"tool name, so this one would never be applied and the "
                    f"tool it was meant for would run unguarded. Known tools: "
                    f"{sorted(n for n in named if n)!r}."
                )

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

        if (
            self._guard is not None
            and _blocking(self._guard, "guard_sync", "guard") is None
        ):
            raise TypeError(
                "A synchronous middleware invocation requires a guard client with "
                "a blocking guard(), such as ArcjetGuardSync"
            )

        args = request.tool_call["args"]

        def prepare() -> ResolvedInputs:
            # Reported, not raised: raising skips the guard call, so the tool
            # would run with Guard holding no record that it happened and a
            # rate limit on the action would stop counting exactly the calls
            # whose actor could not be resolved.
            actor, degraded = _resolved(
                lambda: _not_awaited(_policy_actor(policy, args), "actor")
            )
            inputs, degraded = _resolved(
                lambda: _not_awaited(_policy_inputs(policy, args), "input"),
                so_far=degraded,
            )
            return ResolvedInputs(actor=actor, inputs=inputs, degraded=degraded)

        return run_checkpoint_sync(
            lambda: handler(request),
            action=policy.action,
            guard=self._guard,
            prepare=prepare,
            rules=policy.rules,
            metadata=policy.metadata,
            # The same ID a guarded tool reads, so an agent that mixes the two
            # produces one Sequence rather than splitting the run between them.
            # `ensure_config()` with no argument is the ambient config LangChain
            # propagates to this node; `ToolCallRequest` does not carry one.
            correlation_id=_correlation_from_config(ensure_config()),
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

        if self._guard is not None and _awaitable(self._guard, "guard") is None:
            raise TypeError(
                "An asynchronous middleware invocation requires a guard client "
                "with an awaitable guard(), such as ArcjetGuard"
            )

        args = request.tool_call["args"]

        async def prepare() -> ResolvedInputs:
            """The awaitable counterpart of the sync ``prepare``."""
            actor, degraded = await _resolved_async(
                lambda: _awaited(_policy_actor(policy, args))
            )
            inputs, degraded = await _resolved_async(
                lambda: _awaited(_policy_inputs(policy, args)),
                so_far=degraded,
            )
            return ResolvedInputs(actor=actor, inputs=inputs, degraded=degraded)

        return await run_checkpoint(
            lambda: handler(request),
            action=policy.action,
            guard=self._guard,
            prepare=prepare,
            rules=policy.rules,
            metadata=policy.metadata,
            # The same ID a guarded tool reads, so an agent that mixes the two
            # produces one Sequence rather than splitting the run between them.
            # `ensure_config()` with no argument is the ambient config LangChain
            # propagates to this node; `ToolCallRequest` does not carry one.
            correlation_id=_correlation_from_config(ensure_config()),
            on_guard_error=cast(OnGuardError, self._on_guard_error),
        )
