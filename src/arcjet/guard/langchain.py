"""Optional LangChain tool checkpoint integration.

Install ``arcjet[langchain]`` to use this module. Core Guard clients do not
import LangChain.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any, Literal, cast

from langchain_core.runnables import RunnableConfig
from langchain_core.tools import BaseTool, ToolException

from ._client import ArcjetGuard, ArcjetGuardSync
from ._policy_input import PolicyInputMap
from ._rules import RuleWithInput
from ._types import Decision

OnGuardError = Literal["allow", "deny"]
ActorResolver = str | Callable[[RunnableConfig], str]
InputResolver = (
    PolicyInputMap | Callable[[Mapping[str, Any], RunnableConfig], PolicyInputMap]
)
AsyncActorResolver = str | Callable[[RunnableConfig], str | Awaitable[str]]
AsyncInputResolver = (
    PolicyInputMap
    | Callable[
        [Mapping[str, Any], RunnableConfig], PolicyInputMap | Awaitable[PolicyInputMap]
    ]
)


class ArcjetToolDeniedError(ToolException):
    """Raised when Arcjet policy denies a LangChain tool call."""

    def __init__(self, action: str, decision: Decision) -> None:
        super().__init__(f'Arcjet denied action "{action}" ({decision.reason})')
        self.action = action
        self.decision = decision


class ArcjetToolUnavailableError(ToolException):
    """Raised when a required Arcjet policy cannot be evaluated."""

    def __init__(self, action: str, *, cause: BaseException | None = None) -> None:
        super().__init__(f'Arcjet policy for "{action}" could not be evaluated')
        self.action = action
        self.__cause__ = cause


def _arguments(tool: BaseTool, value: Any) -> Mapping[str, Any]:
    tool_call_id: str | None = None
    raw = value
    if isinstance(value, dict) and value.get("type") == "tool_call":
        tool_call_id = cast(str | None, value.get("id"))
        raw = value.get("args", {})
    parsed = tool._parse_input(raw, tool_call_id)  # noqa: SLF001
    if isinstance(parsed, dict):
        return parsed
    return {"input": parsed}


def _check_decision(
    decision: Decision, action: str, on_guard_error: OnGuardError
) -> None:
    if decision.conclusion == "DENY":
        raise ArcjetToolDeniedError(action, decision)
    if decision.has_failed_open() and on_guard_error == "deny":
        raise ArcjetToolUnavailableError(action)


class _GuardedTool(BaseTool):
    _tool: BaseTool
    _guard: ArcjetGuard | ArcjetGuardSync
    _action: str
    _actor: ActorResolver | AsyncActorResolver | None
    _inputs: InputResolver | AsyncInputResolver | None
    _rules: Sequence[RuleWithInput]
    _on_guard_error: OnGuardError

    def __init__(
        self,
        *,
        guard: ArcjetGuard | ArcjetGuardSync,
        tool: BaseTool,
        action: str,
        actor: ActorResolver | AsyncActorResolver | None,
        inputs: InputResolver | AsyncInputResolver | None,
        rules: Sequence[RuleWithInput],
        on_guard_error: OnGuardError,
    ) -> None:
        super().__init__(
            name=tool.name,
            description=tool.description,
            args_schema=tool.args_schema,
            return_direct=tool.return_direct,
            verbose=tool.verbose,
            callbacks=tool.callbacks,
            tags=tool.tags,
            metadata=tool.metadata,
            handle_tool_error=tool.handle_tool_error,
            handle_validation_error=tool.handle_validation_error,
            response_format=tool.response_format,
        )
        self._tool = tool
        self._guard = guard
        self._action = action
        self._actor = actor
        self._inputs = inputs
        self._rules = tuple(rules)
        self._on_guard_error = on_guard_error

    def invoke(
        self, input: Any, config: RunnableConfig | None = None, **kwargs: Any
    ) -> Any:
        if not isinstance(self._guard, ArcjetGuardSync):
            raise TypeError(
                "A synchronous LangChain invocation requires ArcjetGuardSync"
            )
        resolved_config = config if config is not None else cast(RunnableConfig, {})
        try:
            arguments = _arguments(self._tool, input)
            actor = self._resolve_actor(resolved_config)
            inputs = self._resolve_inputs(arguments, resolved_config)
            decision = self._guard.guard(
                self._rules,
                label=self._action,
                actor=actor,
                inputs=inputs,
            )
            _check_decision(decision, self._action, self._on_guard_error)
        except ArcjetToolDeniedError:
            raise
        except Exception as exc:
            if self._on_guard_error == "deny":
                raise ArcjetToolUnavailableError(self._action, cause=exc) from exc
        return self._tool.invoke(input, config=config, **kwargs)

    async def ainvoke(
        self, input: Any, config: RunnableConfig | None = None, **kwargs: Any
    ) -> Any:
        if not isinstance(self._guard, ArcjetGuard):
            raise TypeError("An asynchronous LangChain invocation requires ArcjetGuard")
        resolved_config = config if config is not None else cast(RunnableConfig, {})
        try:
            arguments = _arguments(self._tool, input)
            actor = await self._resolve_actor_async(resolved_config)
            inputs = await self._resolve_inputs_async(arguments, resolved_config)
            decision = await self._guard.guard(
                self._rules,
                label=self._action,
                actor=actor,
                inputs=inputs,
            )
            _check_decision(decision, self._action, self._on_guard_error)
        except ArcjetToolDeniedError:
            raise
        except Exception as exc:
            if self._on_guard_error == "deny":
                raise ArcjetToolUnavailableError(self._action, cause=exc) from exc
        return await self._tool.ainvoke(input, config=config, **kwargs)

    def _resolve_actor(self, config: RunnableConfig) -> str | None:
        if self._actor is None or isinstance(self._actor, str):
            return self._actor
        value = self._actor(config)
        if inspect.isawaitable(value):
            raise TypeError("A synchronous actor resolver must not return an awaitable")
        return value

    def _resolve_inputs(
        self, arguments: Mapping[str, Any], config: RunnableConfig
    ) -> PolicyInputMap | None:
        if self._inputs is None or not callable(self._inputs):
            return self._inputs
        resolver = cast(
            Callable[
                [Mapping[str, Any], RunnableConfig],
                PolicyInputMap | Awaitable[PolicyInputMap],
            ],
            self._inputs,
        )
        value = resolver(arguments, config)
        if inspect.isawaitable(value):
            raise TypeError("A synchronous input resolver must not return an awaitable")
        return value

    async def _resolve_actor_async(self, config: RunnableConfig) -> str | None:
        if self._actor is None or isinstance(self._actor, str):
            return self._actor
        resolver = cast(Callable[[RunnableConfig], str | Awaitable[str]], self._actor)
        value = resolver(config)
        if inspect.isawaitable(value):
            return cast(str, await value)
        return cast(str, value)

    async def _resolve_inputs_async(
        self, arguments: Mapping[str, Any], config: RunnableConfig
    ) -> PolicyInputMap | None:
        if self._inputs is None or not callable(self._inputs):
            return self._inputs
        resolver = cast(
            Callable[
                [Mapping[str, Any], RunnableConfig],
                PolicyInputMap | Awaitable[PolicyInputMap],
            ],
            self._inputs,
        )
        value = resolver(arguments, config)
        if inspect.isawaitable(value):
            return cast(PolicyInputMap, await value)
        return cast(PolicyInputMap, value)

    def _run(self, *_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("Guarded tools delegate through invoke()")

    async def _arun(self, *_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("Guarded tools delegate through ainvoke()")


def guard_tool(
    *,
    guard: ArcjetGuard | ArcjetGuardSync,
    tool: BaseTool,
    action: str,
    actor: ActorResolver | AsyncActorResolver | None = None,
    inputs: InputResolver | AsyncInputResolver | None = None,
    rules: Sequence[RuleWithInput] = (),
    on_guard_error: OnGuardError = "deny",
) -> BaseTool:
    """Wrap a LangChain tool with an Arcjet pre-execution checkpoint."""
    return _GuardedTool(
        guard=guard,
        tool=tool,
        action=action,
        actor=actor,
        inputs=inputs,
        rules=rules,
        on_guard_error=on_guard_error,
    )


__all__ = [
    "ArcjetToolDeniedError",
    "ArcjetToolUnavailableError",
    "guard_tool",
]
