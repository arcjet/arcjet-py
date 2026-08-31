"""Claude Agent SDK ``PreToolUse`` / ``UserPromptSubmit`` hooks.

Unwrapped built-ins and MCP tools have no authored handler to wrap.
``PreToolUse`` with ``permissionDecision: "deny"`` is the only deny that
still runs under ``allowed_tools`` / ``bypassPermissions``.
``permissionDecision: "ask"`` is HITL, not deny, and is never returned.

Inbound text is screened on ``UserPromptSubmit`` via ``inbound=``. There
is no ``guard_inbound`` helper. A deny is ``{"decision": "block"}``.

``can_use_tool`` is not a policy gate and is not wrapped.

``PreToolUse`` fires for every tool and the input carries only a name,
never the brand :func:`guard_tool` applies. List wrapped tools in
``exclude`` as ``{"server": ..., "name": ...}`` so they match
``mcp__{server}__{name}`` exactly.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import partial
from typing import Any, Optional, Union, cast

from arcjet._errors import ArcjetMisconfiguration
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
from .._context import _validated
from .._errors import ArcjetDeniedError, ArcjetUnavailableError, OnGuardError
from .._policy_input import PolicyInputMap
from .._registry import _awaitable
from .._rules import RuleWithInput
from ._context import claude_agent_context
from ._denial import payload_from_block, unavailable_message
from ._import import load_hook_matcher
from ._names import ExcludeEntry, as_exclude_entry, excluded_names, is_excluded

ActionResolver = Union[str, Callable[[Mapping[str, Any]], str], None]
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


@dataclass(frozen=True, slots=True)
class _HookConfig:
    guard: Any
    action: ActionResolver
    actor: ActorResolver
    inputs: InputResolver
    rules: RulesResolver
    metadata: MetadataResolver
    session_id: Optional[str]
    on_guard_error: OnGuardError
    exclude: frozenset[str]


@dataclass(frozen=True, slots=True)
class _InboundConfig:
    guard: Any
    action: str
    actor: ActorResolver
    inputs: InputResolver
    rules: RulesResolver
    metadata: MetadataResolver
    session_id: Optional[str]
    on_guard_error: OnGuardError


@dataclass(frozen=True, slots=True)
class PreToolUseVerdict:
    """What PreToolUse should tell the SDK. Unit tests call this without
    constructing a real ``HookMatcher``.
    """

    deny: bool
    reason: Optional[str] = None


@dataclass(frozen=True, slots=True)
class UserPromptSubmitVerdict:
    """What UserPromptSubmit should tell the SDK."""

    block: bool
    reason: Optional[str] = None


def _hook_mapping(source: Any) -> Mapping[str, Any]:
    if isinstance(source, Mapping):
        return source
    return {}


def _tool_name(source: Mapping[str, Any]) -> str:
    name = source.get("tool_name")
    return name if isinstance(name, str) else ""


def _tool_arguments(source: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = source.get("tool_input")
    return dict(raw) if isinstance(raw, Mapping) else {}


def _prompt(source: Mapping[str, Any]) -> str:
    raw = source.get("prompt")
    return raw if isinstance(raw, str) else ""


def _resolve(source: Any, arguments: Mapping[str, Any]) -> Any:
    if source is None or not callable(source):
        return source
    return source(arguments)


def _prepared(
    actor: ActorResolver,
    inputs: InputResolver,
    arguments: Mapping[str, Any],
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


def _resolved_rules(
    rules: RulesResolver, arguments: Mapping[str, Any]
) -> Sequence[RuleWithInput]:
    if not callable(rules):
        return rules
    return cast(
        Callable[[Mapping[str, Any]], Sequence[RuleWithInput]],
        rules,
    )(arguments)


def _resolved_metadata(
    metadata: MetadataResolver, arguments: Mapping[str, Any]
) -> Optional[Metadata]:
    if callable(metadata):
        return cast(
            Callable[[Mapping[str, Any]], Optional[Metadata]],
            metadata,
        )(arguments)
    return metadata


def _correlation(session_id: Optional[str], source: Mapping[str, Any]) -> Optional[str]:
    derived = claude_agent_context(source, session_id=session_id)
    return _resolve_correlation_id(derived.correlation_id)


def _merged_metadata(
    session_id: Optional[str],
    source: Mapping[str, Any],
    extra: Optional[Metadata],
) -> Optional[Metadata]:
    derived = claude_agent_context(source, session_id=session_id)
    merged: dict[str, Any] = {}
    if derived.metadata:
        merged.update(derived.metadata)
    if extra:
        merged.update(extra)
    return merged or None


def _unavailable(action: str, cause: Optional[BaseException]) -> BaseException:
    return ArcjetUnavailableError(action, cause=cause)


async def _decide(
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


def _resolve_tool_action(config: _HookConfig, source: Mapping[str, Any]) -> str:
    action = config.action
    if action is None:
        name = _tool_name(source) or "tool"
        return f"{name}.invoked"
    if callable(action):
        return cast(Callable[[Mapping[str, Any]], str], action)(source)
    return action


async def evaluate_pre_tool_use(source: Any, config: _HookConfig) -> PreToolUseVerdict:
    """Evaluate PreToolUse policy. Never raises an Arcjet error.

    A raise would leave the hook; depending on the SDK version that can
    fail-open or stringify. ``permissionDecision: "deny"`` is the only
    deny. ``"ask"`` is never returned.
    """
    hook = _hook_mapping(source)
    name = _tool_name(hook)
    if is_excluded(name, config.exclude):
        return PreToolUseVerdict(deny=False)

    action = f"{name or 'tool'}.invoked"
    correlation_id = _resolve_correlation_id(None)
    metadata: Optional[Metadata] = None

    try:
        action = _resolve_tool_action(config, hook)
        arguments = _tool_arguments(hook)
        correlation_id = _correlation(config.session_id, hook)
        extra = _resolved_metadata(config.metadata, arguments)
        metadata = _merged_metadata(config.session_id, hook, extra)
        prepared = _prepared(config.actor, config.inputs, arguments)
        rules = _resolved_rules(config.rules, arguments)
        decision = await _decide(
            config.guard,
            action=action,
            correlation_id=correlation_id,
            metadata=metadata,
            prepared=prepared,
            rules=rules,
        )
        failure = _classify_decision(
            decision,
            action=action,
            on_guard_error=config.on_guard_error,
            denied_error=ArcjetDeniedError,
            unavailable_error=_unavailable,
            degraded=prepared.degraded,
        )
    except Exception:
        if config.on_guard_error == "allow":
            logger.warning(
                "arcjet: policy for action %r could not be evaluated; proceeding "
                "because on_guard_error is 'allow'",
                action,
            )
            return PreToolUseVerdict(deny=False)
        _emit_capture(
            client=config.guard,
            action=action,
            outcome="unavailable",
            correlation_id=correlation_id,
            decision=None,
            metadata=metadata,
        )
        return PreToolUseVerdict(deny=True, reason=unavailable_message())

    if failure is not None:
        denied = getattr(decision, "conclusion", None) == "DENY"
        _emit_capture(
            client=config.guard,
            action=action,
            outcome="denied" if denied else "unavailable",
            correlation_id=correlation_id,
            decision=decision,
            metadata=metadata,
        )
        payload = payload_from_block(action, decision)
        return PreToolUseVerdict(deny=True, reason=payload["message"])

    _emit_capture(
        client=config.guard,
        action=action,
        outcome=_outcome_for_completed_action(decision, degraded=prepared.degraded),
        correlation_id=correlation_id,
        decision=decision,
        metadata=metadata,
    )
    return PreToolUseVerdict(deny=False)


async def evaluate_user_prompt_submit(
    source: Any, config: _InboundConfig
) -> UserPromptSubmitVerdict:
    """Evaluate UserPromptSubmit policy. Never raises an Arcjet error.

    A deny is ``{"decision": "block"}``. There is no ``guard_inbound``
    helper — this is the inbound path.
    """
    hook = _hook_mapping(source)
    action = config.action
    correlation_id = _resolve_correlation_id(None)
    metadata: Optional[Metadata] = None
    arguments: Mapping[str, Any] = {"prompt": _prompt(hook)}

    try:
        correlation_id = _correlation(config.session_id, hook)
        extra = _resolved_metadata(config.metadata, arguments)
        metadata = _merged_metadata(config.session_id, hook, extra)
        prepared = _prepared(config.actor, config.inputs, arguments)
        rules = _resolved_rules(config.rules, arguments)
        decision = await _decide(
            config.guard,
            action=action,
            correlation_id=correlation_id,
            metadata=metadata,
            prepared=prepared,
            rules=rules,
        )
        failure = _classify_decision(
            decision,
            action=action,
            on_guard_error=config.on_guard_error,
            denied_error=ArcjetDeniedError,
            unavailable_error=_unavailable,
            degraded=prepared.degraded,
        )
    except Exception:
        if config.on_guard_error == "allow":
            logger.warning(
                "arcjet: policy for action %r could not be evaluated; proceeding "
                "because on_guard_error is 'allow'",
                action,
            )
            return UserPromptSubmitVerdict(block=False)
        _emit_capture(
            client=config.guard,
            action=action,
            outcome="unavailable",
            correlation_id=correlation_id,
            decision=None,
            metadata=metadata,
        )
        return UserPromptSubmitVerdict(block=True, reason=unavailable_message())

    if failure is not None:
        denied = getattr(decision, "conclusion", None) == "DENY"
        _emit_capture(
            client=config.guard,
            action=action,
            outcome="denied" if denied else "unavailable",
            correlation_id=correlation_id,
            decision=decision,
            metadata=metadata,
        )
        payload = payload_from_block(action, decision)
        return UserPromptSubmitVerdict(block=True, reason=payload["message"])

    _emit_capture(
        client=config.guard,
        action=action,
        outcome=_outcome_for_completed_action(decision, degraded=prepared.degraded),
        correlation_id=correlation_id,
        decision=decision,
        metadata=metadata,
    )
    return UserPromptSubmitVerdict(block=False)


def pre_tool_use_output(verdict: PreToolUseVerdict) -> dict[str, Any]:
    """SDK ``HookJSONOutput`` for a PreToolUse deny or allow."""
    if not verdict.deny:
        return {}
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": verdict.reason or unavailable_message(),
        }
    }


def user_prompt_submit_output(verdict: UserPromptSubmitVerdict) -> dict[str, Any]:
    """SDK ``HookJSONOutput`` for a UserPromptSubmit block or allow."""
    if not verdict.block:
        return {}
    return {
        "decision": "block",
        "reason": verdict.reason or unavailable_message(),
    }


def _inbound_config(
    *,
    guard: Any,
    session_id: Optional[str],
    on_guard_error: OnGuardError,
    inbound: Mapping[str, Any],
) -> _InboundConfig:
    action = inbound.get("action")
    if not isinstance(action, str) or not action:
        raise ArcjetMisconfiguration(
            "guard_hooks(inbound=...) needs a non-empty action string "
            "(there is no guard_inbound helper; UserPromptSubmit is this path)"
        )
    inbound_error = inbound.get("on_guard_error", on_guard_error)
    if inbound_error not in ("allow", "deny"):
        raise ArcjetMisconfiguration(
            f"on_guard_error must be 'allow' or 'deny', got {inbound_error!r}. "
            f"It decides whether a call runs when policy could not be "
            f"evaluated, so there is no safe value to guess."
        )
    return _InboundConfig(
        guard=inbound.get("guard", guard),
        action=action,
        actor=inbound.get("actor"),
        inputs=inbound.get("inputs"),
        rules=inbound.get("rules", ()),
        metadata=inbound.get("metadata"),
        session_id=inbound.get("session_id", session_id),
        on_guard_error=inbound_error,
    )


def _tool_hooks_requested(
    *,
    action: ActionResolver,
    rules: RulesResolver,
    actor: ActorResolver,
    inputs: InputResolver,
    exclude: Sequence[ExcludeEntry] | None,
) -> bool:
    if action is not None:
        return True
    if callable(rules) or (isinstance(rules, Sequence) and len(rules) > 0):
        return True
    if actor is not None or inputs is not None:
        return True
    return bool(exclude)


def guard_hooks(
    *,
    guard: Any,
    action: ActionResolver = None,
    actor: ActorResolver = None,
    inputs: InputResolver = None,
    rules: RulesResolver = (),
    metadata: MetadataResolver = None,
    session_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    on_guard_error: OnGuardError = "deny",
    exclude: Sequence[ExcludeEntry] | None = None,
    inbound: Optional[Mapping[str, Any]] = None,
) -> dict[str, list[Any]]:
    """Build Claude Agent SDK hooks that fail closed.

    Returns a ``dict[HookEvent, list[HookMatcher]]`` for
    ``ClaudeAgentOptions.hooks``.

    * ``PreToolUse`` — deny unwrapped built-ins / MCP with
      ``permissionDecision: "deny"``. Tools already wrapped by
      :func:`~arcjet.guard.claude_agent_sdk.guard_tool` must be listed in
      *exclude* as ``{"server": ..., "name": ...}`` (qualified to
      ``mcp__{server}__{name}``) or as the exact reported name. A bare
      authored name does not match every server.
    * ``UserPromptSubmit`` — when *inbound* is set, ``{"decision":
      "block"}`` is the inbound path. There is no ``guard_inbound``.

    ``can_use_tool`` is not wrapped. ``permissionDecision: "ask"`` is
    never returned.

    Args:
        guard: The Arcjet client. An async client is preferred; a blocking
            client is accepted.
        action: Checkpoint label, or a callable of the hook input. Defaults
            to ``"{tool_name}.invoked"`` when a tool hook is registered.
        actor: Who is acting, or a callable of the tool arguments (or
            ``{"prompt": ...}`` on inbound).
        inputs: Policy inputs, or a callable of those arguments.
        rules: Local rules, or a callable of those arguments. Empty still
            contacts Guard.
        metadata: Capture metadata, or a callable of those arguments.
        session_id: Caller-owned UUID fallback. Hook ``session_id`` is
            preferred. Never minted.
        correlation_id: Alias of *session_id*. Ignored when *session_id*
            is set.
        on_guard_error: ``"deny"`` (default) or ``"allow"``.
        exclude: Tools already wrapped by ``guard_tool``.
        inbound: UserPromptSubmit policy. Requires ``action``. Optional
            ``rules``, ``actor``, ``inputs``, ``metadata``,
            ``on_guard_error``, ``session_id``.

    Raises:
        ArcjetMisconfiguration: *on_guard_error* is not ``"allow"`` or
            ``"deny"``, *inbound* is missing ``action``, or neither a
            tool hook nor inbound was requested.
        ValueError: *session_id* / *correlation_id* is not printable
            ASCII, or an exclude entry cannot be qualified.
        ImportError: the ``claude-agent-sdk`` extra is not installed.
    """
    if on_guard_error not in ("allow", "deny"):
        raise ArcjetMisconfiguration(
            f"on_guard_error must be 'allow' or 'deny', got {on_guard_error!r}. "
            f"It decides whether a call runs when policy could not be "
            f"evaluated, so there is no safe value to guess."
        )
    owned = session_id if session_id is not None else correlation_id
    if owned is not None:
        _validated(owned)
    if inbound is not None and not isinstance(inbound, Mapping):
        raise TypeError(
            "guard_hooks(inbound=...) is a mapping with at least action=; "
            "there is no guard_inbound helper"
        )

    want_tools = _tool_hooks_requested(
        action=action,
        rules=rules,
        actor=actor,
        inputs=inputs,
        exclude=exclude,
    )
    if not want_tools and inbound is None:
        raise ArcjetMisconfiguration(
            "guard_hooks() needs a tool policy (action= / rules=) and/or "
            "inbound= for UserPromptSubmit. There is no guard_inbound "
            "helper and no guard_can_use_tool."
        )

    inbound_config = (
        _inbound_config(
            guard=guard,
            session_id=owned,
            on_guard_error=on_guard_error,
            inbound=inbound,
        )
        if inbound is not None
        else None
    )

    hook_matcher = load_hook_matcher()
    hooks: dict[str, list[Any]] = {}

    if want_tools:
        config = _HookConfig(
            guard=guard,
            action=action,
            actor=actor,
            inputs=inputs,
            rules=rules,
            metadata=metadata,
            session_id=owned,
            on_guard_error=on_guard_error,
            exclude=excluded_names(
                [as_exclude_entry(entry) for entry in (exclude or ())]
            ),
        )

        async def pre_tool_use(
            input_data: Any, _tool_use_id: Optional[str], _context: Any
        ) -> dict[str, Any]:
            try:
                verdict = await evaluate_pre_tool_use(input_data, config)
            except Exception:
                if config.on_guard_error == "allow":
                    logger.warning(
                        "arcjet: the Claude Agent SDK PreToolUse hook failed; "
                        "the tool proceeds because on_guard_error is 'allow'"
                    )
                    return {}
                return pre_tool_use_output(
                    PreToolUseVerdict(deny=True, reason=unavailable_message())
                )
            return pre_tool_use_output(verdict)

        hooks["PreToolUse"] = [hook_matcher(matcher=None, hooks=[pre_tool_use])]

    if inbound_config is not None:

        async def user_prompt_submit(
            input_data: Any, _tool_use_id: Optional[str], _context: Any
        ) -> dict[str, Any]:
            try:
                verdict = await evaluate_user_prompt_submit(input_data, inbound_config)
            except Exception:
                if inbound_config.on_guard_error == "allow":
                    logger.warning(
                        "arcjet: the Claude Agent SDK UserPromptSubmit hook "
                        "failed; the prompt proceeds because on_guard_error "
                        "is 'allow'"
                    )
                    return {}
                return user_prompt_submit_output(
                    UserPromptSubmitVerdict(block=True, reason=unavailable_message())
                )
            return user_prompt_submit_output(verdict)

        hooks["UserPromptSubmit"] = [
            hook_matcher(matcher=None, hooks=[user_prompt_submit])
        ]

    return hooks
