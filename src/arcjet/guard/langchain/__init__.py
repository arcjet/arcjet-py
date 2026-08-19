"""Optional LangChain tool checkpoint integration.

Install ``arcjet[langchain]`` to use this module. Core Guard clients do not
import LangChain.

A guarded tool is an instance of the wrapped tool's own class — a generated
subclass — that evaluates policy and then hands the call to the tool it wraps.
Everything the framework derives from a tool — its schema, its arguments — is
asked of the wrapped tool rather than recomputed here, so a guarded tool
advertises and executes exactly what the unguarded one did.

A guarded tool reads its correlation ID from ``arcjet_correlation_id`` in a
``RunnableConfig``, preferring ``configurable`` over ``metadata``, and falls
back to the enclosing :func:`arcjet.guard.arcjet_sequence`.  LangChain's own
``run_id`` is deliberately **not** used, and should not be adopted later: a
Sequence is meant to be joinable from the user-facing session a human would
go looking for, and an id the framework mints per run produces a Sequence
nobody would think to query.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

# Needs only `langchain-core`, the same dependency `guard_tool` already has,
# so it costs a user of this package nothing to import eagerly.
from ._callbacks import ArcjetAsyncCaptureHandler, ArcjetCaptureHandler
from ._tool import (
    ActorResolver,
    ArcjetToolDeniedError,
    ArcjetToolUnavailableError,
    AsyncActorResolver,
    AsyncInputResolver,
    InputResolver,
    OnGuardError,
    guard_tool,
)

if TYPE_CHECKING:  # pragma: no cover - for type checkers only
    from ._middleware import ArcjetMiddleware, ToolPolicy

#: Names served from :mod:`arcjet.guard.langchain._middleware`, which needs
#: LangGraph. Importing them eagerly would push LangGraph onto every
#: ``guard_tool`` user, so they are resolved on first access instead — a
#: reader still finds them on the package, and the cost is paid only by
#: someone who asks for them.
_MIDDLEWARE_EXPORTS = frozenset({"ArcjetMiddleware", "ToolPolicy"})


def __getattr__(name: str) -> Any:
    if name in _MIDDLEWARE_EXPORTS:
        try:
            from . import _middleware
        except ImportError as exc:  # pragma: no cover - depends on the install
            raise ImportError(
                f"{name} needs the agent middleware dependencies. "
                f'Install them with: pip install "arcjet[langchain-agents]"'
            ) from exc
        return getattr(_middleware, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(__all__)


__all__ = [
    "ActorResolver",
    "ArcjetToolDeniedError",
    "ArcjetToolUnavailableError",
    "AsyncActorResolver",
    "ArcjetAsyncCaptureHandler",
    "ArcjetCaptureHandler",
    "ArcjetMiddleware",
    "AsyncInputResolver",
    "InputResolver",
    "OnGuardError",
    "ToolPolicy",
    "guard_tool",
]
