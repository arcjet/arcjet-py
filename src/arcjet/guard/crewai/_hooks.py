"""CrewAI PRE_TOOL_CALL registrar.

CrewAI's first-class gate is the global hook dispatcher: every tool the
executor, LiteAgent, or a crew-injected / MCP adapter runs goes through
``InterceptionPoint.PRE_TOOL_CALL`` before the tool body. Raising
``HookAborted(reason, source="arcjet")`` is the only deny that actually
stops the tool — every other exception is swallowed (fail-open).

Only PRE is registered. POST_TOOL_CALL is deliberately left alone: it fires
on blocked calls too, it receives a *different* context object than PRE, and
a tool that runs a nested crew (CrewAI's delegation tools do) produces
interleaved PRE/POST pairs that cannot be matched up through the public
contract. Carrying state from PRE to POST therefore misattributes or drops
events. The decision is recorded in PRE instead, which is also the only
thing a hook can honestly observe: CrewAI turns a failing tool into a result
string, so POST could not tell success from failure either.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Optional, Union, cast

from arcjet._errors import ArcjetMisconfiguration
from arcjet._logging import logger
from arcjet._metadata import Metadata

from .._checkpoint import (
    ResolvedInputs,
    _classify_decision,
    _emit_capture,
    _guard_sync,
    _resolve_correlation_id,
)
from .._context import _validated
from .._errors import ArcjetDeniedError, ArcjetUnavailableError, OnGuardError
from .._policy_input import PolicyInputMap
from .._registry import _blocking
from .._rules import RuleWithInput
from ._import import load_crewai_hooks
from ._names import sanitize_tool_name

ActionResolver = Union[str, Callable[[Any], str]]
ActorResolver = Union[str, Callable[[Mapping[str, Any], Any], Optional[str]], None]
InputResolver = Union[
    PolicyInputMap,
    Callable[[Mapping[str, Any], Any], Optional[PolicyInputMap]],
    None,
]
RulesResolver = Union[
    Sequence[RuleWithInput],
    Callable[[Mapping[str, Any], Any], Sequence[RuleWithInput]],
]
MetadataResolver = Union[
    Metadata, Callable[[Mapping[str, Any], Any], Optional[Metadata]]
]

_HOOK_SOURCE = "arcjet"

#: The attribute :func:`~arcjet.guard.crewai.guard_tool` puts on the tool it
#: returns, so this hook does not evaluate the same call a second time. An
#: attribute rather than a registry of ``id()`` values: CPython reuses the id
#: of a collected object, so an id-keyed registry starts skipping unrelated
#: tools — a silent fail-open — once the wrapped tool is garbage collected.
_GUARD_BRAND = "_arcjet_guarded"


@dataclass(frozen=True, slots=True)
class ToolPolicy:
    """How one tool's crew-executed calls are checked.

    Matched by sanitized tool name, the same way CrewAI matches ``tools=``
    filters: ``Send Email`` and ``send_email`` name the same tool.

    Args:
        action: The label for this checkpoint, e.g. ``"email.sent"``.
            Convention is ``resource.verb`` in the past tense.
        rules: Bound rule inputs. Empty is normal and still contacts Guard,
            because the server selects remote policy by ``action``.
        actor: Who is acting — a string, or a callable taking the tool's
            arguments and the hook context.
        inputs: Values offered for policy evaluation — a mapping, or a
            callable taking the tool's arguments and the hook context.
        metadata: Metadata attached to this checkpoint's capture. Crew,
            task, and agent *names* are added as metadata; they are never
            used as a correlation id.
    """

    action: str
    rules: Sequence[RuleWithInput] = ()
    actor: ActorResolver = None
    inputs: InputResolver = None
    metadata: Optional[Metadata] = None


@dataclass(frozen=True, slots=True)
class _HookConfig:
    """Resolved registrar arguments, closed over by the hook.

    ``policies`` keys and ``tools`` entries are already sanitized, so matching
    a call is a dict lookup rather than a scan. Build one through
    :func:`_hook_config` so that stays true.
    """

    guard: Any
    action: Optional[ActionResolver]
    actor: ActorResolver
    inputs: InputResolver
    rules: RulesResolver
    metadata: Optional[MetadataResolver]
    correlation_id: Optional[str]
    on_guard_error: OnGuardError
    policies: Mapping[str, ToolPolicy]
    tools: Optional[frozenset[str]]


def _hook_config(
    *,
    guard: Any = None,
    action: Optional[ActionResolver] = None,
    actor: ActorResolver = None,
    inputs: InputResolver = None,
    rules: RulesResolver = (),
    metadata: Optional[MetadataResolver] = None,
    correlation_id: Optional[str] = None,
    on_guard_error: OnGuardError = "deny",
    policies: Optional[Mapping[str, ToolPolicy]] = None,
    tools: Optional[Sequence[str]] = None,
) -> _HookConfig:
    """A config whose tool names are sanitized the way CrewAI sanitizes them."""
    return _HookConfig(
        guard=guard,
        action=action,
        actor=actor,
        inputs=inputs,
        rules=rules,
        metadata=metadata,
        correlation_id=correlation_id,
        on_guard_error=on_guard_error,
        policies={
            sanitize_tool_name(name): policy
            for name, policy in (policies or {}).items()
        },
        tools=(
            frozenset(sanitize_tool_name(name) for name in tools)
            if tools is not None
            else None
        ),
    )


@dataclass(frozen=True, slots=True)
class _PreAbort:
    """PRE decided the tool must not run. Translated to ``HookAborted``."""

    reason: str


def _is_already_guarded(ctx: Any) -> bool:
    """Whether ``guard_tool`` already evaluates this tool's calls.

    Reads the brand off the tool the hook was handed and off the
    ``_original_tool`` a ``CrewStructuredTool`` carries, which is where the
    wrapped ``BaseTool`` ends up once an agent converts it. An unwrapped tool
    is never branded, so handing the crew the original rather than the
    wrapped copy leaves it guarded by this hook.
    """
    tool = getattr(ctx, "tool", None)
    if tool is None:
        return False
    if getattr(tool, _GUARD_BRAND, False):
        return True
    original = getattr(tool, "_original_tool", None)
    return original is not None and bool(getattr(original, _GUARD_BRAND, False))


def _context_arguments(ctx: Any) -> Mapping[str, Any]:
    """The arguments the tool is about to receive, as the model sent them.

    Handed to a resolver whole. Nothing is filtered out: a resolver reading
    ``arguments["user_id"]`` is reading the tool's own argument, and hiding it
    would fail closed on a correctly written policy. Use
    :func:`~arcjet.guard.crewai.free_text_arguments` when you want to offer
    only free text to a scanning rule.
    """
    raw = getattr(ctx, "tool_input", None)
    return raw if isinstance(raw, Mapping) else {}


def _context_tool_name(ctx: Any) -> str:
    name = getattr(ctx, "tool_name", None)
    if not isinstance(name, str) or not name:
        return ""
    return sanitize_tool_name(name)


def _context_metadata(ctx: Any, extra: Optional[Metadata]) -> Metadata:
    """Caller metadata plus crew / task / agent *names* — never their ids."""
    merged: dict[str, Any] = {}
    if extra:
        merged.update(extra)
    agent = getattr(ctx, "agent", None)
    role = getattr(agent, "role", None) if agent is not None else None
    agent_name = getattr(agent, "name", None) if agent is not None else None
    task = getattr(ctx, "task", None)
    crew = getattr(ctx, "crew", None)
    names = {
        "tool": _context_tool_name(ctx) or None,
        "agent": role or agent_name,
        "task": getattr(task, "name", None) if task is not None else None,
        "crew": getattr(crew, "name", None) if crew is not None else None,
    }
    for key, value in names.items():
        if value is not None and key not in merged:
            merged[key] = value
    return merged


def _resolve_action(config: _HookConfig, ctx: Any, policy: Optional[ToolPolicy]) -> str:
    if policy is not None:
        return policy.action
    action = config.action
    if action is None:
        name = _context_tool_name(ctx) or "tool"
        return f"{name}.invoked"
    if callable(action):
        return cast(Callable[[Any], str], action)(ctx)
    return action


def _prepared(
    config: _HookConfig, ctx: Any, policy: Optional[ToolPolicy]
) -> ResolvedInputs:
    """What the decision is made from, with a failed resolver reported not raised.

    A resolver that fails degrades what the decision is made *from*; it is not
    a failure to reach a decision. Guard is still called, so the call stays on
    the record and a rate limit on the label keeps counting, and
    ``on_guard_error`` decides whether a partly-judged call may run — the same
    contract as every other Arcjet checkpoint.
    """
    arguments = _context_arguments(ctx)
    actor_src: ActorResolver = policy.actor if policy is not None else config.actor
    inputs_src: InputResolver = policy.inputs if policy is not None else config.inputs
    actor, degraded = _resolve_one(actor_src, arguments, ctx)
    inputs, degraded = _resolve_one(inputs_src, arguments, ctx, so_far=degraded)
    return ResolvedInputs(actor=actor, inputs=inputs, degraded=degraded)


def _resolve_one(
    source: Any,
    arguments: Mapping[str, Any],
    ctx: Any,
    so_far: Optional[BaseException] = None,
) -> tuple[Any, Optional[BaseException]]:
    if source is None or not callable(source):
        return source, so_far
    try:
        return source(arguments, ctx), so_far
    except Exception as exc:
        return None, so_far or exc


def _resolved_rules(
    config: _HookConfig, ctx: Any, policy: Optional[ToolPolicy]
) -> Sequence[RuleWithInput]:
    if policy is not None:
        return policy.rules
    rules = config.rules
    if not callable(rules):
        return rules
    return cast(
        Callable[[Mapping[str, Any], Any], Sequence[RuleWithInput]],
        rules,
    )(_context_arguments(ctx), ctx)


def _resolved_metadata(
    config: _HookConfig, ctx: Any, policy: Optional[ToolPolicy]
) -> Optional[Metadata]:
    if policy is not None:
        return _context_metadata(ctx, policy.metadata)
    metadata = config.metadata
    if callable(metadata):
        resolved = cast(
            Callable[[Mapping[str, Any], Any], Optional[Metadata]], metadata
        )(_context_arguments(ctx), ctx)
        return _context_metadata(ctx, resolved)
    return _context_metadata(ctx, metadata)


def _correlation(config: _HookConfig) -> Optional[str]:
    """The caller's id, or the enclosing sequence's. Never minted from the crew."""
    if config.correlation_id is None:
        return _resolve_correlation_id(None)
    return _resolve_correlation_id(_validated(config.correlation_id))


def _unavailable(action: str, cause: Optional[BaseException]) -> BaseException:
    return ArcjetUnavailableError(action, cause=cause)


def evaluate_pre_tool_call(ctx: Any, config: _HookConfig) -> Optional[_PreAbort]:
    """Evaluate PRE policy. Return an abort, or ``None`` to let the tool run.

    Deliberately returns rather than raises, and does not import CrewAI: the
    registrar is the only thing that turns this into
    ``HookAborted(reason, source="arcjet")``. Raising
    :class:`~arcjet.guard.ArcjetDeniedError` or
    :class:`~arcjet.guard.ArcjetUnavailableError` from a hook would be
    swallowed by CrewAI's dispatcher and the tool would run.
    """
    if _is_already_guarded(ctx):
        return None

    name = _context_tool_name(ctx)
    if config.tools is not None and name not in config.tools:
        return None
    policy = config.policies.get(name)

    # Bound before the attempt so the failure path can still name the action
    # and reach the same Sequence when a factory throws.
    action = f"{name or 'tool'}.invoked"
    correlation_id = _resolve_correlation_id(None)
    metadata: Optional[Metadata] = None

    try:
        action = _resolve_action(config, ctx, policy)
        correlation_id = _correlation(config)
        metadata = _resolved_metadata(config, ctx, policy)
        prepared = _prepared(config, ctx, policy)
        rules = _resolved_rules(config, ctx, policy)
        decision = _guard_sync(
            config.guard,
            rules=rules,
            label=action,
            metadata=metadata,
            correlation_id=correlation_id,
            actor=prepared.actor,
            inputs=prepared.inputs,
        )
        failure = _classify_decision(
            decision,
            action=action,
            on_guard_error=config.on_guard_error,
            denied_error=ArcjetDeniedError,
            unavailable_error=_unavailable,
            degraded=prepared.degraded,
        )
    except Exception as exc:
        # Policy was not evaluated: the guard call failed, or the client
        # answered with something that is not a decision.
        if config.on_guard_error == "allow":
            logger.warning(
                "arcjet: policy for action %r could not be evaluated; proceeding "
                "because on_guard_error is 'allow'",
                action,
            )
            return None
        _emit_capture(
            client=config.guard,
            action=action,
            outcome="unavailable",
            correlation_id=correlation_id,
            decision=None,
            metadata=metadata,
        )
        return _PreAbort(str(ArcjetUnavailableError(action, cause=exc)))

    if failure is not None:
        _emit_capture(
            client=config.guard,
            action=action,
            outcome="denied" if decision.conclusion == "DENY" else "unavailable",
            correlation_id=correlation_id,
            decision=decision,
            metadata=metadata,
        )
        return _PreAbort(str(failure))

    # "success" is the decision's outcome — the call was allowed to proceed —
    # not the tool's. A hook cannot observe the body: CrewAI turns a failing
    # tool into a result string, and a later hook may still abort the call.
    _emit_capture(
        client=config.guard,
        action=action,
        outcome="success",
        correlation_id=correlation_id,
        decision=decision,
        metadata=metadata,
    )
    return None


@dataclass(frozen=True, slots=True)
class ArcjetCrewAIHooks:
    """Handle for the hook registered by :func:`register_arcjet_hooks`.

    Not a policy API. ``unregister()`` takes the hook down again, which is
    what lets a test — or a process that wants to re-register with different
    policies — start over. Unregistering twice is a no-op.
    """

    _hook: Any
    _hooks: Any

    def unregister(self) -> None:
        """Remove the hook this handle registered."""
        global _registered
        self._hooks.unregister_hook(
            self._hooks.InterceptionPoint.PRE_TOOL_CALL, self._hook
        )
        with _registration_lock:
            if _registered is self:
                _registered = None


#: The live registration, if any. CrewAI's registry is process-wide and
#: appends, so registering twice would evaluate every tool call twice —
#: double-charging a rate limit — while the second set of policies silently
#: replaced nothing.
_registered: Optional[ArcjetCrewAIHooks] = None

# Guards the check-then-set below, for the same reason `register_arcjet` holds
# one: assignment is atomic under the GIL, so the lock is not protecting the
# variable but the decision — two threads registering at startup must not both
# observe an empty slot and both believe they won.
_registration_lock = threading.Lock()


def register_arcjet_hooks(
    *,
    guard: Any = None,
    action: Optional[ActionResolver] = None,
    actor: ActorResolver = None,
    inputs: InputResolver = None,
    rules: RulesResolver = (),
    metadata: Optional[MetadataResolver] = None,
    correlation_id: Optional[str] = None,
    on_guard_error: OnGuardError = "deny",
    policies: Optional[Mapping[str, ToolPolicy]] = None,
    tools: Optional[Sequence[str]] = None,
) -> ArcjetCrewAIHooks:
    """Register a fail-closed PRE_TOOL_CALL hook on CrewAI's dispatcher.

    Every tool a crew, LiteAgent, MCP adapter, or crew-injected tool list
    executes hits ``PRE_TOOL_CALL`` before the body. A ``DENY`` or, under the
    default ``on_guard_error="deny"``, an unevaluated policy raises
    ``HookAborted(reason, source="arcjet")`` so the tool does not run.
    CrewAI swallows every other exception — raising
    :class:`~arcjet.guard.ArcjetDeniedError` or
    :class:`~arcjet.guard.ArcjetUnavailableError` from this hook would
    *run* the tool.

    The agent always sees ``Tool execution blocked by hook. Tool: {name}``.
    ``HookAborted.reason`` is telemetry only.

    Registered once per process. CrewAI's hook registry is global and
    appends, so a second registration would evaluate every tool call twice;
    this refuses one instead. Call ``unregister()`` on the handle first to
    replace a registration.

    The hook path is synchronous, so *guard* must have a blocking ``guard()``
    (``launch_arcjet_sync`` / :class:`~arcjet.guard.ArcjetGuardSync`). An
    async client is refused here rather than per call, because a hook cannot
    report a wiring mistake: under ``on_guard_error="allow"`` it would
    silently allow every tool call.

    Correlation is caller-owned: pass *correlation_id* or open
    :func:`~arcjet.guard.arcjet_sequence`. Crew, task, and agent names are
    metadata. Their ids are never read and never minted into a Sequence.

    Screen inbound user text with the core :func:`~arcjet.guard.guard` /
    :func:`~arcjet.guard.guard_sync` call **before** ``crew.kickoff``. There
    is no inbound helper. ``human_input`` and
    ``ToolCallHookContext.request_human_input`` are HITL, not a policy gate.

    Args:
        guard: A blocking Arcjet client. ``None`` uses the registered client.
        action: Checkpoint label, or a callable of the hook context. Defaults
            to ``"{sanitized_tool_name}.invoked"``.
        actor: Who is acting, or a callable of ``(arguments, ctx)``.
        inputs: Policy inputs, or a callable of ``(arguments, ctx)``.
            *arguments* is the tool's own argument mapping, unfiltered.
        rules: Local rules, or a callable of ``(arguments, ctx)``.
        metadata: Capture metadata, or a callable of ``(arguments, ctx)``.
        correlation_id: Caller-owned Sequence id. Validated like
            :func:`~arcjet.guard.arcjet_sequence`. Falls back to the ambient
            sequence. Never derived from ``crew.id`` / ``task.id``.
        on_guard_error: ``"deny"`` (default) or ``"allow"``.
        policies: Optional per-tool overrides, keyed by tool name. Keys are
            sanitized the way CrewAI sanitizes ``tools=`` filters.
        tools: If set, only these tool names are guarded (sanitized). Other
            tools pass through.

    Returns:
        A handle whose :meth:`ArcjetCrewAIHooks.unregister` removes the hook.

    Raises:
        ArcjetMisconfiguration: *on_guard_error* is not ``"allow"`` or
            ``"deny"``, *guard* has no blocking ``guard()``, or a
            registration is already live.
        ValueError: *correlation_id* is not printable ASCII within 256 bytes.
    """
    global _registered

    if on_guard_error not in ("allow", "deny"):
        raise ArcjetMisconfiguration(
            f"on_guard_error must be 'allow' or 'deny', got {on_guard_error!r}. "
            f"It decides whether a call runs when policy could not be "
            f"evaluated, so there is no safe value to guess."
        )
    if guard is not None and _blocking(guard, "guard_sync", "guard") is None:
        raise ArcjetMisconfiguration(
            "CrewAI tool hooks are synchronous, so they need a client with a "
            "blocking guard() — launch_arcjet_sync() or ArcjetGuardSync. The "
            "client given has only an awaitable guard(), which no hook can "
            "wait on."
        )
    if correlation_id is not None:
        _validated(correlation_id)

    hooks = load_crewai_hooks()
    config = _hook_config(
        guard=guard,
        action=action,
        actor=actor,
        inputs=inputs,
        rules=rules,
        metadata=metadata,
        correlation_id=correlation_id,
        on_guard_error=on_guard_error,
        policies=policies,
        tools=tools,
    )

    def pre_tool_call(ctx: Any) -> None:
        abort = evaluate_pre_tool_call(ctx, config)
        if abort is not None:
            raise hooks.HookAborted(reason=abort.reason, source=_HOOK_SOURCE)

    # The claim and the registration are made together, so two threads racing
    # at startup cannot both put a hook on CrewAI's registry.
    with _registration_lock:
        if _registered is not None:
            raise ArcjetMisconfiguration(
                "Arcjet CrewAI hooks are already registered in this process. "
                "CrewAI's hook registry is global and appends, so registering "
                "again would evaluate every tool call twice. Call unregister() "
                "on the handle from the first call to replace it."
            )
        hooks.register_hook(hooks.InterceptionPoint.PRE_TOOL_CALL, pre_tool_call)
        _registered = ArcjetCrewAIHooks(_hook=pre_tool_call, _hooks=hooks)
        return _registered


def unregister_arcjet_hooks(handle: ArcjetCrewAIHooks) -> None:
    """Remove the hook *handle* registered."""
    handle.unregister()
